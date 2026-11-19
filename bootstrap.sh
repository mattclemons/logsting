#!/usr/bin/env bash
# LogSting one-command bootstrap.
# Clone the repo, run ./bootstrap.sh, and the full stack (app + CRS WAF + logging)
# comes up on this box. Local only. No branches, no per-module checkout.
set -euo pipefail
cd "$(dirname "$0")"

say() { printf '[*] %s\n' "$*"; }
ok()  { printf '[+] %s\n' "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

# 0. curl + CA certificates. A minimal Debian box may have neither, and the
# Docker installer downloads over HTTPS, which needs the CA bundle.
if ! command -v curl >/dev/null 2>&1 || [ ! -f /etc/ssl/certs/ca-certificates.crt ]; then
  say "installing curl and ca-certificates"
  command -v apt-get >/dev/null 2>&1 || die "no apt-get; install curl and ca-certificates manually, then re-run"
  sudo apt-get update -y && sudo apt-get install -y curl ca-certificates
  sudo update-ca-certificates || true
fi

# 1. Docker Engine + compose plugin.
# Debian's repos do not carry docker-compose-plugin; it lives in Docker's own
# apt repo. The official installer sets that up and installs both.
if ! command -v docker >/dev/null 2>&1; then
  say "docker not found, installing via get.docker.com"
  curl -fsSL https://get.docker.com | sudo sh
  sudo systemctl enable --now docker || true
  # let this user run docker without sudo next time (needs re-login to take effect)
  sudo usermod -aG docker "$USER" 2>/dev/null || true
fi

# Pick a docker invocation that works right now. A fresh group add does not apply
# until re-login, so fall back to sudo for this run.
DOCKER="docker"
docker info >/dev/null 2>&1 || DOCKER="sudo docker"
$DOCKER compose version >/dev/null 2>&1 || die "docker compose plugin missing after install"

# 2. Build and start
# The WAF writes its audit log as a low-privilege user, so the bind-mounted log
# dirs must be writable by the container, not just the host user.
mkdir -p logs/app logs/waf
chmod 0777 logs/app logs/waf 2>/dev/null || true
say "building and starting LogSting"
$DOCKER compose up -d --build

# 3. Wait for the WAF-fronted app to answer
say "waiting for health on :8080"
up=""
for _ in $(seq 1 45); do
  if curl -fsS --noproxy '*' http://localhost:8080/healthz >/dev/null 2>&1; then up=1; break; fi
  sleep 2
done
[ -n "$up" ] || die "app did not become healthy; check: $DOCKER compose logs"

ip=$(hostname -I 2>/dev/null | awk '{print $1}')
ok "LogSting is up"
echo "    local:  http://localhost:8080/"
[ -n "${ip:-}" ] && echo "    on LAN: http://${ip}:8080/"
echo "    logs:   ./logs/app/security.ndjson   ./logs/waf/audit.json"
echo "    tests:  make test"
if [ "$DOCKER" = "sudo docker" ]; then
  echo "    note:   log out and back in (or run 'newgrp docker') so make targets work without sudo"
fi
