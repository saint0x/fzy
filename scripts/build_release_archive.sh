#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET=""
VERSION=""

usage() {
  cat <<'EOF'
scripts/build_release_archive.sh [options]

Builds a release archive containing the `fz` CLI, the compatibility `fozzy` alias, and top-level docs.

Options:
  --target <triple>   Cargo target triple to build
  --version <tag>     Release tag to embed in archive name
  --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  TARGET="$(rustc -vV | sed -n 's/^host: //p')"
fi

if [[ -z "$VERSION" ]]; then
  VERSION="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; data=json.load(sys.stdin); pkg=next(p for p in data["packages"] if p["name"]=="fz"); print("v"+pkg["version"])')"
fi

DIST_DIR="$ROOT/dist"
STAGE_DIR="$DIST_DIR/fz-${VERSION}-${TARGET}"
ARCHIVE="$DIST_DIR/fz-${VERSION}-${TARGET}.tar.gz"
CHECKSUM="$ARCHIVE.sha256"

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR" "$DIST_DIR"

cargo build --locked -p fz --release --target "$TARGET"

cp "target/$TARGET/release/fz" "$STAGE_DIR/fz"
cp "target/$TARGET/release/fozzy" "$STAGE_DIR/fozzy"
cp "$ROOT/README.md" "$STAGE_DIR/README.md"
cp "$ROOT/USAGE.md" "$STAGE_DIR/USAGE.md"
cp "$ROOT/INSTALL.md" "$STAGE_DIR/INSTALL.md"

tar -czf "$ARCHIVE" -C "$DIST_DIR" "$(basename "$STAGE_DIR")"
shasum -a 256 "$ARCHIVE" | awk '{print $1}' >"$CHECKSUM"

printf 'archive=%s\nchecksum=%s\n' "$ARCHIVE" "$CHECKSUM"
