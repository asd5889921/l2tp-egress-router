#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${L2ER_APP_DIR:-/opt/l2tp-egress-router}"
CONFIG_DIR="${L2ER_CONFIG_DIR:-/etc/l2tp-egress-router}"
RUN_DIR="${L2ER_RUN_DIR:-/run/l2tp-egress-router}"
PURGE_L2TP=0
[[ "${1:-}" == "--purge-l2tp" ]] && PURGE_L2TP=1
[[ "$(id -u)" == 0 ]] || { echo "请使用 root 用户运行。" >&2; exit 1; }
[[ -r /dev/tty && -w /dev/tty ]] || { echo "需要交互式终端。" >&2; exit 1; }

echo "将删除 l2tp-egress-router："
printf '  应用：%s\n  配置：%s\n  运行目录：%s\n' "$APP_DIR" "$CONFIG_DIR" "$RUN_DIR"
if (( PURGE_L2TP )); then
  echo "同时删除纯 L2TP 服务端配置并卸载 xl2tpd/ppp。"
else
  echo "保留 xl2tpd/ppp 及其配置；如需删除请使用 --purge-l2tp。"
fi
echo "这会断开当前 L2TP 连接，且不可通过本脚本恢复。"
read -r -p "确认请输入 REMOVE： " confirmation < /dev/tty
[[ "$confirmation" == "REMOVE" ]] || { echo "已取消。"; exit 1; }

for unit in l2er-web l2er-watchdog l2er-xray; do
  systemctl disable --now "$unit" 2>/dev/null || true
  rm -f "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload

rm -f /etc/ppp/ip-up.d/90-l2tp-egress-router /etc/ppp/ip-down.d/90-l2tp-egress-router
rm -rf "$APP_DIR" "$CONFIG_DIR" "$RUN_DIR"
rm -f /usr/local/bin/xray

if (( PURGE_L2TP )); then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup="/root/l2er-uninstall-backup-$stamp"
  install -d -m 700 "$backup"
  for path in /etc/xl2tpd/xl2tpd.conf /etc/ppp/options.xl2tpd /etc/ppp/chap-secrets; do
    [[ -f "$path" ]] && cp -a "$path" "$backup/"
  done
  rm -rf /etc/xl2tpd
  rm -f /etc/ppp/options.xl2tpd /etc/ppp/chap-secrets /etc/sysctl.d/99-l2tp-ip-forward.conf
  sysctl --system >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get purge -y xl2tpd ppp || true
  apt-get autoremove -y || true
  echo "L2TP 配置删除前备份保存在：$backup"
fi

echo "卸载完成。未清空系统防火墙规则；如需清理由管理员按实际规则检查。"
