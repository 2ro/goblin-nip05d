#!/usr/bin/env bash
# Guided bare-metal setup for the STANDALONE goblin-nip05d name authority:
#   - recommends the bundled Floonet relay package first (the preferred route)
#   - builds the release binary
#   - installs it to /usr/local/bin
#   - creates the state directory
#   - asks for your domain and writes a ready env file (no hand-editing needed)
#   - installs and enables the hardened systemd unit
#
# This standalone edition is essentially deprecated: the same name service is
# BUNDLED in the Floonet relay package, which has a fuller guided installer and
# lets you run the authority alongside a relay, standalone, or off. Prefer that
# unless you specifically want the name service with no relay of your own. See
# https://code.gri.mw/GRIN/floonet-strfry (run `sudo ./install.sh` there).
#
# This authority holds NO secrets (no wallet, no payment token), so there is
# nothing to hide-prompt or lock down beyond the state directory. If you later
# want paid names or name transfers, use the bundled Floonet edition, which
# adds those and collects any GoblinPay token over a hidden prompt into a
# root-only 0600 file.
#
# Re-runnable: it never overwrites an existing /etc/goblin-nip05d.env.
# Requires: a Rust toolchain (cargo) and root (sudo) for the install steps.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Paths are overridable for prefix installs and testing; defaults are the
# conventional system locations the systemd unit and README assume.
BIN="${GOBLIN_NIP05D_BIN:-/usr/local/bin/goblin-nip05d}"
ENV_FILE="${GOBLIN_NIP05D_ENV:-/etc/goblin-nip05d.env}"
UNIT="${GOBLIN_NIP05D_UNIT:-/etc/systemd/system/goblin-nip05d.service}"
STATE_DIR="${GOBLIN_NIP05D_STATE:-/var/lib/goblin-nip05d}"

say() { printf '\033[1;33m==>\033[0m %s\n' "$1"; }

if [[ $EUID -ne 0 ]]; then
	SUDO=sudo
else
	SUDO=""
fi

ask() {
	local q="$1" def="$2" reply=""
	if [[ -t 0 ]]; then
		read -r -p "$(printf '\033[1;33m==>\033[0m %s [%s] ' "$q" "$def")" reply || reply=""
	fi
	printf '%s' "${reply:-$def}"
}

cat <<'EOF'

goblin-nip05d — standalone name authority setup
===============================================
Note: the RECOMMENDED route is the Floonet relay package, which bundles this
same name service with a fuller guided installer (alongside a relay, standalone,
or off) plus paid names and name transfers:

    git clone https://code.gri.mw/GRIN/floonet-strfry && cd floonet-strfry
    sudo ./install.sh

Continue below only if you specifically want the name service on its own.

EOF

if [[ -t 0 ]]; then
	read -r -p "$(printf '\033[1;33m==>\033[0m Continue with the standalone install? [Y/n] ')" go || go=""
	case "${go:-y}" in
		[Nn]*) echo "Aborted. See floonet-strfry for the bundled edition."; exit 0 ;;
	esac
fi

if [[ "${SKIP_BUILD:-0}" == 1 ]]; then
	say "SKIP_BUILD set — assuming the binary is already at $BIN"
else
	say "Building release binary"
	( cd "$REPO_DIR" && cargo build --release --locked )

	say "Installing binary to $BIN"
	$SUDO install -m0755 "$REPO_DIR/target/release/goblin-nip05d" "$BIN"
fi

say "Creating state directory $STATE_DIR"
$SUDO mkdir -p "$STATE_DIR"

if [[ -f "$ENV_FILE" ]]; then
	say "Env file $ENV_FILE already exists — leaving it untouched"
else
	# Guided: ask for the domain and write a ready-to-run env file rather than
	# leaving the operator to hand-edit placeholders. base_url is derived so the
	# authority's config validation (host must equal the domain) always holds.
	DOMAIN="$(ask 'Domain for names (the @domain in name@domain)' 'names.example')"
	RELAY="$(ask 'Relay to advertise in NIP-05 responses' "wss://$DOMAIN")"
	say "Writing $ENV_FILE for $DOMAIN"
	$SUDO install -m0640 "$REPO_DIR/.env.example" "$ENV_FILE"
	$SUDO sed -i \
		-e "s#^GOBLIN_DOMAIN=.*#GOBLIN_DOMAIN=$DOMAIN#" \
		-e "s#^GOBLIN_BASE_URL=.*#GOBLIN_BASE_URL=https://$DOMAIN#" \
		-e "s#^GOBLIN_RELAYS=.*#GOBLIN_RELAYS=$RELAY#" \
		"$ENV_FILE"
fi

say "Installing systemd unit to $UNIT"
$SUDO install -m0644 "$REPO_DIR/deploy/goblin-nip05d.service" "$UNIT"

if command -v systemctl >/dev/null 2>&1; then
	say "Reloading systemd and enabling the service"
	$SUDO systemctl daemon-reload
	$SUDO systemctl enable goblin-nip05d
else
	say "systemctl not found — skipping enable (start it however you run services)"
fi

cat <<EOF

Done. Next steps:
  1. Review $ENV_FILE (domain, base URL, and advertised relay are set).
  2. Put a TLS-terminating reverse proxy in front that sets X-Real-IP
     (see $REPO_DIR/deploy/Caddyfile or nginx.conf.example).
  3. Start it:  $SUDO systemctl start goblin-nip05d
  4. Check it:  curl -s http://127.0.0.1:8191/api/v1/health
EOF
