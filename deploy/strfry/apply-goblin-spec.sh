#!/usr/bin/env sh
# Build "the Goblin relay" = STOCK upstream strfry + the Goblin spec in this dir.
#
# No fork, no patches, no vendored source: this clones hoytech/strfry fresh at a
# pinned commit, compiles it UNTOUCHED, then drops in strfry.conf and the
# write-policy plugin — both of which use strfry's own native config + plugin
# mechanisms (see README.md). The result is a ready-to-run Goblin relay.
#
# The Docker path (`docker compose up -d relay`) does the same thing and bundles
# the build deps; this script is the no-Docker equivalent. Needs a C++ toolchain
# plus strfry's libs (liblmdb, flatbuffers, libsecp256k1, libb2, zstd, openssl,
# perl) — see https://github.com/hoytech/strfry#compile-strfry
#
# Usage: ./apply-goblin-spec.sh [target-dir]      (default: ./strfry-build)
set -eu

STRFRY_REPO="https://github.com/hoytech/strfry"
# Pinned for reproducibility. Keep in sync with the Dockerfile's STRFRY_REF.
STRFRY_REF="7984f80822189bf8124699f3d49580334b32385e"

SPEC_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-$SPEC_DIR/strfry-build}"

echo ">> Cloning stock strfry into $TARGET"
if [ ! -d "$TARGET/.git" ]; then
    git clone "$STRFRY_REPO" "$TARGET"
fi
cd "$TARGET"
git fetch origin
git checkout "$STRFRY_REF"
git submodule update --init

echo ">> Building strfry (unmodified upstream source @ $STRFRY_REF)"
make setup-golpe
make -j"$(nproc 2>/dev/null || echo 2)"

echo ">> Applying the Goblin spec (config + write-policy plugin)"
cp "$SPEC_DIR/strfry.conf"            "$TARGET/strfry.conf"
cp "$SPEC_DIR/strfry-writepolicy.py" "$TARGET/strfry-writepolicy.py"
chmod +x "$TARGET/strfry-writepolicy.py"
# The shipped conf uses container paths; repoint db + plugin at this local build
# (edits only the COPY in the build dir — the canonical spec files are untouched).
mkdir -p "$TARGET/strfry-db"
sed -i 's#^db = .*#db = "'"$TARGET"'/strfry-db/"#' "$TARGET/strfry.conf"
sed -i 's#/usr/local/bin/strfry-writepolicy.py#'"$TARGET"'/strfry-writepolicy.py#' "$TARGET/strfry.conf"

cat <<EOF

Done — stock strfry + the Goblin spec is built at:
  $TARGET/strfry

Run the Goblin relay (binds :7777 by default; see strfry.conf):
  cd "$TARGET" && ./strfry relay
EOF
