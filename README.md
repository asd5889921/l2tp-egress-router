# l2tp-egress-router

L2TP egress routing overlay for Debian 12. It keeps the existing pure-L2TP
`xl2tpd` installation intact and adds Xray-core v26.6.27 TPROXY routing,
Shadowsocks/HTTP/SOCKS5 egress management, source-IP diagnostics, and a
FastAPI web console.

## Current status

- Existing `xl2tpd` configuration is treated as upstream-owned and is not overwritten.
- Xray version is pinned to `26.6.27`.
- PPP reconnect hooks restore source-CIDR routes automatically.
- Web console supports egress editing, SS URI parsing, bindings, snapshots,
  rollback, service status, and connectivity tests.

## Continue development

```bash
git clone https://github.com/asd5889921/l2tp-egress-router.git
cd l2tp-egress-router
```

The currently deployed VPS is separate from this source repository. Review
the existing project files and deployment notes before changing firewall or
PPP behavior.

