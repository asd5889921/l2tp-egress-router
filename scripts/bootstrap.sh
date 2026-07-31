#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${L2ER_REPO_URL:-https://github.com/asd5889921/l2tp-egress-router.git}"
BRANCH="${L2ER_BRANCH:-main}"
APP_DIR="${L2ER_APP_DIR:-/opt/l2tp-egress-router}"
CONFIG_DIR="${L2ER_CONFIG_DIR:-/etc/l2tp-egress-router}"
RUN_DIR="${L2ER_RUN_DIR:-/run/l2tp-egress-router}"
L2TP_INSTALLER_URL="${L2ER_L2TP_INSTALLER_URL:-https://raw.githubusercontent.com/asd5889921/l2tp-vpn-installer/main/bootstrap.sh}"

[[ "$(id -u)" == 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "仅支持 Debian/Ubuntu。" >&2; exit 1; }
[[ -r /dev/tty && -w /dev/tty ]] || { echo "需要交互式终端。" >&2; exit 1; }

read -r -p "Web 管理员用户名 [admin]: " ADMIN_USER </dev/tty
ADMIN_USER="${ADMIN_USER:-admin}"
while true; do
  read -r -s -p "Web 管理员密码（至少 12 位）: " ADMIN_PASS </dev/tty
  echo >/dev/tty
  read -r -s -p "再次输入管理密码: " ADMIN_PASS_CONFIRM </dev/tty
  echo >/dev/tty
  if [[ ${#ADMIN_PASS} -lt 12 ]]; then echo "密码至少需要 12 位。" >&2; continue; fi
  if [[ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]]; then echo "两次密码不一致。" >&2; continue; fi
  break
done

if [[ -e /etc/xl2tpd/xl2tpd.conf || -e /etc/ppp/options.xl2tpd || -e /etc/ppp/chap-secrets ]]; then
  echo "检测到已有 L2TP/LNS 配置。为避免覆盖现有服务，本脚本停止。" >&2
  echo "请在全新 VPS 执行，或先手动备份并处理已有配置。" >&2
  exit 1
fi

echo "第一步：配置新 VPS 的纯 L2TP 服务端。"
echo "下面会让你填写 Panabit 将要使用的账号、密码、LNS 地址、地址池、MTU 和 DNS。"
curl -fsSL "$L2TP_INSTALLER_URL" | bash

echo "第二步：安装 l2tp-egress-router。"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git python3 python3-venv python3-pip iproute2 iptables curl
if [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" fetch origin "$BRANCH"
  git -C "$APP_DIR" reset --hard "origin/$BRANCH"
else
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$APP_DIR"
fi
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --no-cache-dir "$APP_DIR"
"$APP_DIR/.venv/bin/python" -c 'from l2tp_multi_egress.xray_release import download_and_install; print(download_and_install())'

install -d -m 700 "$CONFIG_DIR" "$RUN_DIR"
install -d -m 755 /etc/ppp/ip-up.d /etc/ppp/ip-down.d
install -m 755 "$APP_DIR/config/ppp-hooks/90-l2tp-egress-router-up" /etc/ppp/ip-up.d/90-l2tp-egress-router
install -m 755 "$APP_DIR/config/ppp-hooks/90-l2tp-egress-router-down" /etc/ppp/ip-down.d/90-l2tp-egress-router

export L2ER_CONFIG_DIR="$CONFIG_DIR" L2ER_RUN_DIR="$RUN_DIR" L2ER_XRAY_BINARY=/usr/local/bin/xray L2ER_DRY_RUN=1
"$APP_DIR/.venv/bin/python" - <<'PY'
from l2tp_multi_egress.models import AppState
from l2tp_multi_egress.settings import Settings
from l2tp_multi_egress.storage import atomic_write
from l2tp_multi_egress.xray import XrayManager
s = Settings.from_env()
s.ensure_dirs()
state = AppState()
atomic_write(s.state_file, state.model_dump_json(indent=2) + "\n")
XrayManager(s).write_config(state)
PY
ADMIN_USER="$ADMIN_USER" ADMIN_PASS="$ADMIN_PASS" "$APP_DIR/.venv/bin/python" - <<'PY'
import os
from l2tp_multi_egress.auth import AuthManager
from l2tp_multi_egress.settings import Settings
auth = AuthManager(Settings.from_env())
if not auth.initialized():
    auth.initialize(os.environ["ADMIN_USER"], os.environ["ADMIN_PASS"])
PY
unset ADMIN_PASS ADMIN_PASS_CONFIRM

cat > /etc/systemd/system/l2er-xray.service <<EOF
[Unit]
Description=l2tp-egress-router Xray core
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/xray run -config $CONFIG_DIR/xray_config/config.json
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/l2er-web.service <<EOF
[Unit]
Description=l2tp-egress-router Web
After=l2er-xray.service xl2tpd.service
Requires=l2er-xray.service
[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=L2ER_CONFIG_DIR=$CONFIG_DIR
Environment=L2ER_RUN_DIR=$RUN_DIR
Environment=L2ER_XRAY_BINARY=/usr/local/bin/xray
Environment=L2ER_LISTEN_HOST=0.0.0.0
Environment=L2ER_LISTEN_PORT=17890
ExecStart=$APP_DIR/.venv/bin/l2er-web
Restart=on-failure
RestartSec=3
User=root
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/l2er-watchdog.service <<EOF
[Unit]
Description=l2tp-egress-router rollback watchdog
After=network-online.target
[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=L2ER_CONFIG_DIR=$CONFIG_DIR
Environment=L2ER_RUN_DIR=$RUN_DIR
Environment=L2ER_XRAY_BINARY=/usr/local/bin/xray
ExecStart=$APP_DIR/.venv/bin/l2er-watchdog
Restart=always
RestartSec=2
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now l2er-xray l2er-watchdog l2er-web
echo
echo "安装完成。"
echo "请在 Panabit 中填写新 VPS 公网 IP、UDP 1701、刚才设置的 L2TP 用户名和密码。"
echo "Web 管理员：$ADMIN_USER"
echo "然后打开 http://$(hostname -I | awk '{print $1}'):17890/，使用刚才设置的管理密码登录。"
