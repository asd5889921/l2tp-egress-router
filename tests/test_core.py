from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from l2tp_multi_egress.diagnostics import SourceDiagnostics
from l2tp_multi_egress.main import create_app
from l2tp_multi_egress.models import AppState, Binding, Egress, ProxyType
from l2tp_multi_egress.network import iptables_restore_script
from l2tp_multi_egress.l2tp import L2TPManager
from l2tp_multi_egress.settings import Settings
from l2tp_multi_egress.ss_uri import parse_ss_uri
from l2tp_multi_egress.transaction import TransactionManager
from l2tp_multi_egress.xray import build_config


def settings(tmp_path: Path, rollback: int = 60) -> Settings:
    return Settings(tmp_path / "etc", tmp_path / "run", Path("xray"), "127.0.0.1:10085", True, "127.0.0.1", 17890, rollback)


def sample_state() -> AppState:
    return AppState(
        egresses=[Egress(id="hk", name="Hong Kong", type=ProxyType.SHADOWSOCKS, address="proxy.example", port=8388, password="secret", method="aes-256-gcm")],
        bindings=[Binding(id="group1", source_cidr="192.168.1.0/24", egress_id="hk", tproxy_port=12001, mark=32769)],
    )


def test_ss_uri_sip002_and_legacy():
    userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    modern = parse_ss_uri(f"ss://{userinfo}@example.com:8388#HK", egress_id="hk")
    legacy = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:p@ss@[2001:db8::1]:443").decode().rstrip("=")
    old = parse_ss_uri(f"ss://{legacy}", egress_id="old")
    assert (modern.method, modern.password, modern.name) == ("aes-256-gcm", "secret", "HK")
    assert (old.address, old.port, old.password) == ("2001:db8::1", 443, "p@ss")


def test_state_rejects_overlaps():
    base = sample_state()
    with pytest.raises(ValidationError, match="来源网段重叠"):
        AppState(egresses=base.egresses, bindings=base.bindings + [Binding(id="group2", source_cidr="192.168.1.128/25", egress_id="hk", tproxy_port=12002, mark=32770)])


def test_generated_xray_and_iptables_are_udp_tproxy_only():
    state = sample_state()
    config = build_config(state, "127.0.0.1:10085")
    inbound = config["inbounds"][0]
    assert inbound["settings"]["network"] == "tcp,udp"
    assert inbound["streamSettings"]["sockopt"]["tproxy"] == "tproxy"
    assert config["outbounds"][0]["mux"]["enabled"] is False
    rules = iptables_restore_script(state)
    assert "-p udp -j TPROXY" in rules
    assert "-i ppp+" in rules
    assert "--dport 1701 -j RETURN" in rules
    assert "MASQUERADE" not in rules and "SNAT" not in rules and "REDIRECT" not in rules


def test_l2tp_model_and_isolated_client_config(tmp_path):
    egress = Egress(id="jp-l2tp", name="Japan L2TP", type=ProxyType.L2TP, address="203.0.113.10", port=1701, username="panabit", password="secret")
    manager = L2TPManager(settings(tmp_path))
    config = manager.write_configs(AppState(egresses=[egress]))
    text = config.read_text()
    assert "[lac jp-l2tp]" in text
    assert "lns = 203.0.113.10" in text
    assert "noauth" in (tmp_path / "etc" / "l2tp" / "jp-l2tp" / "ppp.options").read_text()
    with pytest.raises(ValidationError):
        Egress(id="bad", name="bad", type=ProxyType.L2TP, address="x", port=1700, username="u", password="p")


def test_l2tp_binding_bypasses_xray_tproxy():
    egress = Egress(id="l2", name="L2TP", type=ProxyType.L2TP, address="203.0.113.10", port=1701, username="u", password="p")
    state = AppState(egresses=[egress], bindings=[Binding(id="b", source_cidr="192.168.50.0/24", egress_id="l2", tproxy_port=12010, mark=32780)])
    rules = iptables_restore_script(state)
    assert "-A L2ER_TPROXY -i ppp+ -s 192.168.50.0/24 -j RETURN" in rules


def test_nat_diagnostic_requires_peer_concentration(tmp_path):
    diag = SourceDiagnostics(settings(tmp_path), min_samples=10, concentration=0.9)
    for _ in range(9):
        diag.record("ppp0", "10.200.0.10")
    diag.record("ppp0", "192.168.1.2")
    report = diag.report("ppp0", "10.200.0.10")
    assert report["nat_suspected"] is True
    assert "NAT模式" in report["warning"]


def test_transaction_apply_confirm_and_rollback(tmp_path):
    cfg = settings(tmp_path)
    manager = TransactionManager(cfg)
    candidate = sample_state()
    tx = manager.apply(candidate)
    assert manager.store.load().revision == 1
    manager.rollback(tx.id)
    assert manager.store.load().revision == 0
    tx2 = manager.apply(candidate)
    manager.confirm(tx2.id)
    assert manager.pending() is None


def test_web_login_crud_and_confirmation(tmp_path):
    cfg = settings(tmp_path)
    app = create_app(cfg)
    with TestClient(app) as client:
        assert client.post("/api/initialize", json={"username": "admin", "password": "long-test-password"}).status_code == 200
        login = client.post("/api/login", json={"username": "admin", "password": "long-test-password"})
        csrf = login.json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        egress = sample_state().egresses[0].model_dump(mode="json")
        response = client.put("/api/egresses/hk", json=egress, headers=headers)
        assert response.status_code == 200
        txid = response.json()["transaction"]["id"]
        assert client.post(f"/api/transactions/{txid}/confirm", headers=headers).status_code == 200
        binding = sample_state().bindings[0].model_dump(mode="json")
        response = client.put("/api/bindings/group1", json=binding, headers=headers)
        assert response.status_code == 200
        txid = response.json()["transaction"]["id"]
        assert client.post(f"/api/transactions/{txid}/confirm", headers=headers).status_code == 200
        state = client.get("/api/state").json()["state"]
        assert state["bindings"][0]["source_cidr"] == "192.168.1.0/24"
