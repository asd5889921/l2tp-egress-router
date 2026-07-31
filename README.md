# l2tp-egress-router

L2TP egress routing overlay for Debian 12. It keeps the existing pure-L2TP
`xl2tpd` installation intact and adds Xray-core v26.6.27 TPROXY routing,
Shadowsocks/HTTP/SOCKS5 egress management, source-IP diagnostics, and a
FastAPI web console.

## Current status

- Existing `xl2tpd` configuration is treated as upstream-owned and is not overwritten.
- Each outbound pure-L2TP egress runs in its own network namespace with a
  dedicated veth, xl2tpd process, control socket, route table, and state file;
  the existing LNS process is never reused or restarted.
- Xray version is pinned to `26.6.27`.
- PPP reconnect hooks restore source-CIDR routes automatically.
- The web panel can export/import a validated `l2er-config.json` backup. It contains routing state and egress credentials, but never admin credentials or sessions.
- For shell-based migration, use `scripts/l2er-config-backup.sh backup <file.tar.gz>` and `restore <file.tar.gz>`; restore creates a timestamped copy of the current state first.
- Web console supports egress editing, SS URI parsing, bindings, snapshots,
  rollback, service status, and connectivity tests.
- Connection diagnostics retain only private IPv4 source samples in memory for
  five minutes (at most 1000 samples per interface). Xray runs at error log
  level by default, and watchdog errors rotate daily with seven days retained.

## Continue development

```bash
git clone https://github.com/asd5889921/l2tp-egress-router.git
cd l2tp-egress-router
```

The currently deployed VPS is separate from this source repository. Review
the existing project files and deployment notes before changing firewall or
PPP behavior.

