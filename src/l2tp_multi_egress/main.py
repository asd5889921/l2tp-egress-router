from __future__ import annotations

import asyncio
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from importlib.resources import files

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .auth import AuthManager
from .diagnostics import PPPMonitor, SourceDiagnostics
from .models import AppState, Binding, Credentials, Egress
from .settings import Settings
from .ss_uri import parse_ss_uri
from .status import SystemStatus, test_egress
from .storage import StateStore
from .transaction import TransactionManager


class SSParseRequest(BaseModel):
    uri: str
    egress_id: str


class InitialAdmin(BaseModel):
    username: str
    password: str


class BulkDeleteRequest(BaseModel):
    ids: list[str]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.ensure_dirs()
    store = StateStore(settings)
    auth = AuthManager(settings)
    transactions = TransactionManager(settings)
    diagnostics = SourceDiagnostics(settings)
    ppp = PPPMonitor(settings, diagnostics)
    services = SystemStatus(settings)
    login_attempts: dict[str, deque[float]] = defaultdict(deque)

    async def capture_loop() -> None:
        while True:
            await ppp.refresh_capture()
            await asyncio.sleep(5)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if not settings.dry_run:
            transactions.xray.require_version()
        task = asyncio.create_task(capture_loop())
        yield
        task.cancel()

    app = FastAPI(title="l2tp-egress-router", version="0.1.0", lifespan=lifespan)
    static_path = files("l2tp_multi_egress").joinpath("static")
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

    def session(request: Request) -> dict:
        token = request.cookies.get("l2er_session", "")
        payload = auth.parse_session(token)
        if not payload:
            raise HTTPException(401, "请先登录")
        return payload

    def mutation_session(request: Request, x_csrf_token: str | None = Header(default=None)) -> dict:
        payload = session(request)
        if not x_csrf_token or not secrets.compare_digest(x_csrf_token, payload["csrf"]):
            raise HTTPException(403, "CSRF 校验失败")
        return payload

    def apply(candidate: AppState) -> dict:
        try:
            transaction = transactions.apply(candidate)
            return {"transaction": transaction.model_dump(), "state": store.load().model_dump()}
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(str(static_path.joinpath("index.html")))

    @app.get("/api/bootstrap")
    async def bootstrap() -> dict:
        return {"initialized": auth.initialized(), "listen_host": settings.listen_host}

    @app.post("/api/initialize")
    async def initialize(data: InitialAdmin, request: Request) -> dict:
        if request.client and request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            raise HTTPException(403, "首次初始化只能从本机访问")
        try:
            auth.initialize(data.username, data.password)
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"ok": True}

    @app.post("/api/login")
    async def login(data: Credentials, request: Request, response: Response) -> dict:
        address = request.client.host if request.client else "unknown"
        attempts = login_attempts[address]
        cutoff = time.time() - 300
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        if len(attempts) >= 10:
            raise HTTPException(429, "登录失败次数过多，请稍后重试")
        if not auth.verify(data.username, data.password):
            attempts.append(time.time())
            raise HTTPException(401, "用户名或密码错误")
        attempts.clear()
        token, csrf = auth.create_session(data.username)
        response.set_cookie("l2er_session", token, httponly=True, secure=False, samesite="strict", max_age=43200)
        return {"ok": True, "csrf": csrf}

    @app.post("/api/logout")
    async def logout(response: Response, _: dict = Depends(mutation_session)) -> dict:
        response.delete_cookie("l2er_session")
        return {"ok": True}

    @app.get("/api/state")
    async def get_state(_: dict = Depends(session)) -> dict:
        pending = transactions.pending()
        return {"state": store.load().model_dump(), "pending": pending.model_dump() if pending else None}

    @app.put("/api/egresses/{egress_id}")
    async def put_egress(egress_id: str, egress: Egress, _: dict = Depends(mutation_session)) -> dict:
        if egress.id != egress_id:
            raise HTTPException(422, "URL 与出口 ID 不一致")
        state = store.load()
        items = [egress if item.id == egress_id else item for item in state.egresses]
        if not any(item.id == egress_id for item in state.egresses):
            items.append(egress)
        return apply(state.model_copy(update={"egresses": items}))

    @app.post("/api/egresses")
    async def create_egress(data: dict, _: dict = Depends(mutation_session)) -> dict:
        state = store.load()
        used = {item.id for item in state.egresses}
        while True:
            egress_id = f"egress-{secrets.token_hex(4)}"
            if egress_id not in used:
                break
        payload = {key: value for key, value in data.items() if key != "id"}
        try:
            egress = Egress.model_validate({**payload, "id": egress_id})
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return apply(state.model_copy(update={"egresses": [*state.egresses, egress]}))

    @app.delete("/api/egresses/{egress_id}")
    async def delete_egress(egress_id: str, _: dict = Depends(mutation_session)) -> dict:
        state = store.load()
        if any(item.egress_id == egress_id for item in state.bindings):
            raise HTTPException(409, "该出口仍被 IP 段绑定引用")
        items = [item for item in state.egresses if item.id != egress_id]
        if len(items) == len(state.egresses):
            raise HTTPException(404, "出口不存在")
        return apply(state.model_copy(update={"egresses": items}))

    @app.post("/api/egresses/bulk-delete")
    async def bulk_delete_egresses(data: BulkDeleteRequest, _: dict = Depends(mutation_session)) -> dict:
        state = store.load()
        ids = set(data.ids)
        if not ids:
            raise HTTPException(422, "请至少选择一个出口")
        referenced = {item.egress_id for item in state.bindings if item.egress_id in ids}
        if referenced:
            raise HTTPException(409, "所选出口仍被 IP 段绑定，请先删除或改绑")
        items = [item for item in state.egresses if item.id not in ids]
        if len(items) == len(state.egresses):
            raise HTTPException(404, "出口不存在")
        return apply(state.model_copy(update={"egresses": items}))

    @app.put("/api/bindings/{binding_id}")
    async def put_binding(binding_id: str, binding: Binding, _: dict = Depends(mutation_session)) -> dict:
        if binding.id != binding_id:
            raise HTTPException(422, "URL 与绑定 ID 不一致")
        state = store.load()
        items = [binding if item.id == binding_id else item for item in state.bindings]
        if not any(item.id == binding_id for item in state.bindings):
            items.append(binding)
        return apply(state.model_copy(update={"bindings": items}))

    @app.delete("/api/bindings/{binding_id}")
    async def delete_binding(binding_id: str, _: dict = Depends(mutation_session)) -> dict:
        state = store.load()
        items = [item for item in state.bindings if item.id != binding_id]
        if len(items) == len(state.bindings):
            raise HTTPException(404, "绑定不存在")
        return apply(state.model_copy(update={"bindings": items}))

    @app.post("/api/bindings/bulk-delete")
    async def bulk_delete_bindings(data: BulkDeleteRequest, _: dict = Depends(mutation_session)) -> dict:
        state = store.load()
        ids = set(data.ids)
        if not ids:
            raise HTTPException(422, "请至少选择一个绑定")
        items = [item for item in state.bindings if item.id not in ids]
        if len(items) == len(state.bindings):
            raise HTTPException(404, "绑定不存在")
        return apply(state.model_copy(update={"bindings": items}))

    @app.put("/api/fakedns")
    async def set_fakedns(enabled: bool, _: dict = Depends(mutation_session)) -> dict:
        return apply(store.load().model_copy(update={"fake_dns": enabled}))

    @app.post("/api/parse-ss")
    async def parse_ss(data: SSParseRequest, _: dict = Depends(mutation_session)) -> dict:
        try:
            return parse_ss_uri(data.uri, egress_id=data.egress_id).model_dump()
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/history")
    async def history(_: dict = Depends(session)) -> list[dict]:
        return store.histories()

    @app.post("/api/history/{name}/restore")
    async def restore(name: str, _: dict = Depends(mutation_session)) -> dict:
        try:
            transaction = transactions.apply_history(name)
            return {"transaction": transaction.model_dump(), "state": store.load().model_dump()}
        except (ValueError, RuntimeError, FileNotFoundError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/transactions/{transaction_id}/confirm")
    async def confirm(transaction_id: str, _: dict = Depends(mutation_session)) -> dict:
        try:
            transactions.confirm(transaction_id)
            return {"ok": True}
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/transactions/{transaction_id}/rollback")
    async def rollback(transaction_id: str, _: dict = Depends(mutation_session)) -> dict:
        try:
            return {"state": transactions.rollback(transaction_id).model_dump()}
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/connections")
    async def connections(_: dict = Depends(session)) -> list[dict]:
        return ppp.connections()

    @app.get("/api/system")
    async def system_status(_: dict = Depends(session)) -> dict:
        return services.all()

    @app.post("/api/system/{name}/restart")
    async def restart(name: str, _: dict = Depends(mutation_session)) -> dict:
        try:
            services.restart(name)
            return {"ok": True, "status": services.service(name)}
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/egresses/{egress_id}/test")
    async def connectivity(egress_id: str, _: dict = Depends(mutation_session)) -> dict:
        egress = next((item for item in store.load().egresses if item.id == egress_id), None)
        if not egress:
            raise HTTPException(404, "出口不存在")
        return await test_egress(settings, egress)

    return app


def run() -> None:
    import uvicorn
    settings = Settings.from_env()
    uvicorn.run(create_app, factory=True, host=settings.listen_host, port=settings.listen_port, proxy_headers=False)
