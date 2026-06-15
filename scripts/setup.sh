#!/usr/bin/env bash
# One-command bare-metal bootstrap for goblin-nip05d:
#   - builds the release binary
#   - installs it to /usr/local/bin
#   - creates the state directory
#   - installs an env file from .env.example (if absent)
#   - installs and enables the hardened systemd unit
#
# Re-runnable: it never overwrites an existing /etc/goblin-nip05d.env.
# Requires: a Rust toolchain (cargo) and root (sudo) for the install steps.
#
# After it finishes, edit /etc/goblin-nip05d.env (set GOBLIN_DOMAIN /
# GOBLIN_BASE_URL / GOBLIN_RELAYS), put a TLS-terminating reverse proxy in
# front (see deploy/Caddyfile or deploy/nginx.conf.example), then:
#   sudo systemctl restart goblin-nip05d

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN=/usr/local/bin/goblin-nip05d
ENV_FILE=/etc/goblin-nip05d.env
UNIT=/etc/systemd/system/goblin-nip05d.service
STATE_DIR=/var/lib/goblin-nip05d

say() { printf '\033[1;33m==>\033[0m %s\n' "$1"; }

if [[ $EUID -ne 0 ]]; then
	SUDO=sudo
else
	SUDO=""
fi

say "Building release binary"
( cd "$REPO_DIR" && cargo build --release --locked )

say "Installing binary to $BIN"
$SUDO install -m0755 "$REPO_DIR/target/release/goblin-nip05d" "$BIN"

say "Creating state directory $STATE_DIR"
$SUDO mkdir -p "$STATE_DIR"

if [[ -f "$ENV_FILE" ]]; then
	say "Env file $ENV_FILE already exists — leaving it untouched"
else
	say "Installing env file to $ENV_FILE (EDIT IT: set your domain)"
	$SUDO install -m0640 "$REPO_DIR/.env.example" "$ENV_FILE"
fi

say "Installing systemd unit to $UNIT"
$SUDO install -m0644 "$REPO_DIR/deploy/goblin-nip05d.service" "$UNIT"

say "Reloading systemd and enabling the service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable goblin-nip05d

cat <<EOF

Done. Next steps:
  1. Edit $ENV_FILE — set GOBLIN_DOMAIN, GOBLIN_BASE_URL, GOBLIN_RELAYS.
  2. Put a TLS-terminating reverse proxy in front that sets X-Real-IP
     (see $REPO_DIR/deploy/Caddyfile or nginx.conf.example).
  3. Start it:  $SUDO systemctl start goblin-nip05d
  4. Check it:  curl -s http://127.0.0.1:8191/api/v1/health
EOF
