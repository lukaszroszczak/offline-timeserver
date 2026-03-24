#!/usr/bin/env bash
set -euo pipefail

# Deploy offline_timeserver to a remote host over SSH.
# Usage:
#   SSHPASS=... SUDO_PASS=... deploy/armbian/scripts/deploy-remote.sh user@host
# If SSHPASS is set, requires sshpass locally. Otherwise uses ssh keys/agent.
# If SUDO_PASS is set, will use sudo -S on the remote for privileged actions.

REMOTE=${1:-}
if [ -z "$REMOTE" ]; then
  echo "Usage: SSHPASS=... SUDO_PASS=... $0 user@host" >&2
  exit 2
fi

SSH=(ssh -o StrictHostKeyChecking=accept-new)
SCP=(scp -o StrictHostKeyChecking=accept-new)
if [ -n "${SSHPASS:-}" ]; then
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "sshpass required when SSHPASS is set" >&2
    exit 3
  fi
  SSH=(sshpass -e ssh -o StrictHostKeyChecking=accept-new)
  SCP=(sshpass -e scp -o StrictHostKeyChecking=accept-new)
  export SSHPASS
fi

SUDO="sudo"
if [ -n "${SUDO_PASS:-}" ]; then
  SUDO="sudo -S"
fi

run_remote() {
  local cmd=$1
  if [ -n "${SUDO_PASS:-}" ]; then
    printf '%s\n' "$SUDO_PASS" | "${SSH[@]}" "$REMOTE" "$cmd"
  else
    "${SSH[@]}" "$REMOTE" "$cmd"
  fi
}

echo "==> Prepping remote directories"
run_remote "$SUDO mkdir -p /opt/offline_timeserver /etc/default"

echo "==> Sending source tree (tar over SSH)"
tar czf - --exclude-vcs --transform 's,^,offline_timeserver/,' . | "${SSH[@]}" "$REMOTE" "$SUDO tar xzf - -C /opt --strip-components 1"

echo "==> Installing dependencies (apt)"
run_remote "$SUDO apt-get update -y"
run_remote "$SUDO apt-get install -y python3 python3-venv python3-pip chrony gpsd gpsd-clients nftables"

echo "==> Installing systemd unit"
run_remote "$SUDO install -m 0644 /opt/offline_timeserver/deploy/armbian/systemd/offline_timeserver.service /etc/systemd/system/"
run_remote "$SUDO systemctl daemon-reload"

echo "==> Writing env file (/etc/default/offline_timeserver)"
ADMIN_USER_ESC=${ADMIN_USER:-admin}
ADMIN_PASS_ESC=${ADMIN_PASS:-admin}
SECRET_KEY_ESC=${SECRET_KEY:-$(openssl rand -hex 16 2>/dev/null || echo dev-secret)}
TMP_ENV=$(mktemp)
cat > "$TMP_ENV" <<ENV
# offline_timeserver environment
ADMIN_USER=${ADMIN_USER_ESC}
ADMIN_PASS=${ADMIN_PASS_ESC}
SECRET_KEY=${SECRET_KEY_ESC}
# Optional: LOG_LEVEL=INFO, LOG_DIR=/var/log/offline_timeserver
ENV
"${SCP[@]}" "$TMP_ENV" "$REMOTE:/tmp/offline_timeserver.env"
rm -f "$TMP_ENV"
run_remote "$SUDO mv /tmp/offline_timeserver.env /etc/default/offline_timeserver && $SUDO chown root:root /etc/default/offline_timeserver && $SUDO chmod 0640 /etc/default/offline_timeserver || true"

echo "==> Enabling + starting service"
run_remote "$SUDO systemctl enable --now offline_timeserver"
run_remote "$SUDO systemctl status --no-pager --full offline_timeserver || true"

echo "==> Done. Check: http://<host>:8000 and /login"

