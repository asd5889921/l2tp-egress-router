from __future__ import annotations

import base64
from urllib.parse import unquote, urlsplit

from .models import Egress, ProxyType


def _decode_base64(value: str) -> str:
    value = unquote(value).strip()
    value += "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("ss:// Base64 内容无效") from exc


def parse_ss_uri(uri: str, *, egress_id: str, default_name: str = "Shadowsocks") -> Egress:
    """Parse SIP002 and legacy whole-payload Shadowsocks URIs."""
    if not uri.startswith("ss://"):
        raise ValueError("链接必须以 ss:// 开头")
    parsed = urlsplit(uri)
    name = unquote(parsed.fragment) or default_name
    host = parsed.hostname
    port = parsed.port
    username = parsed.username
    password = parsed.password

    if host and port and username:
        if password is None:
            decoded = _decode_base64(username)
            if ":" not in decoded:
                raise ValueError("SIP002 用户信息必须为 method:password")
            method, secret = decoded.split(":", 1)
        else:
            method, secret = unquote(username), unquote(password)
    else:
        payload = uri[5:].split("#", 1)[0].split("?", 1)[0]
        decoded = _decode_base64(payload)
        if "@" not in decoded:
            raise ValueError("旧格式 ss:// 链接缺少服务器地址")
        credentials, endpoint = decoded.rsplit("@", 1)
        if ":" not in credentials:
            raise ValueError("旧格式 ss:// 链接缺少加密方式或密码")
        method, secret = credentials.split(":", 1)
        endpoint_parsed = urlsplit("//" + endpoint)
        host, port = endpoint_parsed.hostname, endpoint_parsed.port

    if not host or not port or not method or not secret:
        raise ValueError("ss:// 链接缺少地址、端口、加密方式或密码")
    return Egress(
        id=egress_id,
        name=name,
        type=ProxyType.SHADOWSOCKS,
        address=host,
        port=port,
        password=secret,
        method=method,
    )
