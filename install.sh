#!/usr/bin/env bash
set -euo pipefail

REPO="${FZ_INSTALL_REPO:-saint0x/fzy}"
BIN_NAME="fz"
INSTALL_DIR="${FZ_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_VERSION="${FZ_VERSION:-latest}"
FROM_SOURCE=0
MODIFY_PATH=1
ARCHIVE_PATH=""
LOCAL_CHECKOUT=""

usage() {
  cat <<'EOF'
install.sh [options]

Installs the `fz` CLI for the current user.

Options:
  --version <tag>    Install a specific release tag (for example `v0.1.0`)
  --to <dir>         Install into a custom bin directory
  --repo <owner/repo>
                     Override the GitHub repository used for release downloads
  --from-source      Install from source with `cargo install --git`
  --from-archive <path>
                     Install from a local release archive
  --from-local-checkout <path>
                     Install from a local repository checkout with `cargo install --path`
  --no-modify-path   Do not update shell profile files
  --help             Show this help
EOF
}

log() {
  printf '[install] %s\n' "$*"
}

fail() {
  printf '[install] error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

resolve_os() {
  case "$(uname -s)" in
    Darwin) echo "apple-darwin" ;;
    Linux) echo "unknown-linux-gnu" ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
  esac
}

resolve_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

resolve_target() {
  printf '%s-%s' "$(resolve_arch)" "$(resolve_os)"
}

resolve_latest_tag() {
  need_cmd curl
  local api="https://api.github.com/repos/${REPO}/releases/latest"
  local tag
  tag="$(curl -fsSL "$api" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$tag" ]] || fail "unable to resolve latest release tag from $api"
  printf '%s' "$tag"
}

ensure_install_dir() {
  mkdir -p "$INSTALL_DIR"
}

path_contains() {
  local dir="$1"
  case ":${PATH:-}:" in
    *":$dir:"*) return 0 ;;
    *) return 1 ;;
  esac
}

detect_profile() {
  if [[ -n "${ZDOTDIR:-}" && -f "${ZDOTDIR}/.zshrc" ]]; then
    printf '%s' "${ZDOTDIR}/.zshrc"
    return 0
  fi
  if [[ -f "$HOME/.zshrc" ]]; then
    printf '%s' "$HOME/.zshrc"
    return 0
  fi
  if [[ -f "$HOME/.bashrc" ]]; then
    printf '%s' "$HOME/.bashrc"
    return 0
  fi
  printf '%s' "$HOME/.profile"
}

maybe_update_path() {
  local dir="$1"
  if [[ "$MODIFY_PATH" -ne 1 ]]; then
    return 0
  fi
  if path_contains "$dir"; then
    return 0
  fi

  local profile
  profile="$(detect_profile)"
  mkdir -p "$(dirname "$profile")"
  touch "$profile"

  local marker="# fz installer PATH"
  if grep -Fq "$marker" "$profile"; then
    return 0
  fi

  {
    printf '\n%s\n' "$marker"
    printf 'export PATH="%s:$PATH"\n' "$dir"
  } >>"$profile"

  log "added $dir to PATH in $profile"
}

verify_install() {
  local binary="$INSTALL_DIR/$BIN_NAME"
  [[ -x "$binary" ]] || fail "expected installed binary at $binary"
  "$binary" version >/dev/null
  "$binary" env --json >/dev/null
  log "verified $binary"
}

install_from_release() {
  need_cmd curl
  need_cmd tar

  local tag="$REQUESTED_VERSION"
  if [[ "$tag" == "latest" ]]; then
    tag="$(resolve_latest_tag)"
  fi

  local target archive url tmpdir
  target="$(resolve_target)"
  archive="${BIN_NAME}-${tag}-${target}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${tag}/${archive}"
  tmpdir="$(mktemp -d)"
  trap "rm -rf '$tmpdir'" EXIT

  log "downloading $url"
  curl -fsSL "$url" -o "$tmpdir/$archive"
  install_from_archive "$tmpdir/$archive"
}

install_from_archive() {
  need_cmd tar
  local archive="$1"
  [[ -f "$archive" ]] || fail "archive not found: $archive"

  local tmpdir staging
  tmpdir="$(mktemp -d)"
  trap "rm -rf '$tmpdir'" EXIT
  staging="$tmpdir/unpack"
  mkdir -p "$staging"
  tar -xzf "$archive" -C "$staging"

  local binary
  binary="$(find "$staging" -type f -name "$BIN_NAME" | head -n1)"
  [[ -n "$binary" ]] || fail "release archive did not contain $BIN_NAME"

  ensure_install_dir
  install -m 0755 "$binary" "$INSTALL_DIR/$BIN_NAME"
  maybe_update_path "$INSTALL_DIR"
  verify_install
}

install_from_local_checkout() {
  need_cmd cargo
  [[ -n "$LOCAL_CHECKOUT" ]] || fail "local checkout path must not be empty"
  [[ -d "$LOCAL_CHECKOUT" ]] || fail "local checkout not found: $LOCAL_CHECKOUT"

  ensure_install_dir

  local cargo_root
  cargo_root="$(mktemp -d)"
  trap "rm -rf '$cargo_root'" EXIT

  log "building $BIN_NAME from local checkout"
  cargo install --locked --root "$cargo_root" --path "$LOCAL_CHECKOUT/apps/fozzyc"

  install -m 0755 "$cargo_root/bin/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
  maybe_update_path "$INSTALL_DIR"
  verify_install
}

install_from_source() {
  need_cmd cargo
  ensure_install_dir

  local cargo_root
  cargo_root="$(mktemp -d)"
  trap 'rm -rf "$cargo_root"' EXIT

  local args=(
    install
    --locked
    --root "$cargo_root"
    --git "https://github.com/${REPO}.git"
    --bin "$BIN_NAME"
  )
  if [[ "$REQUESTED_VERSION" != "latest" ]]; then
    args+=(--tag "$REQUESTED_VERSION")
  fi

  log "building $BIN_NAME from source"
  cargo "${args[@]}"

  install -m 0755 "$cargo_root/bin/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
  maybe_update_path "$INSTALL_DIR"
  verify_install
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || fail "--version requires a value"
      REQUESTED_VERSION="$2"
      shift 2
      ;;
    --to)
      [[ $# -ge 2 ]] || fail "--to requires a value"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a value"
      REPO="$2"
      shift 2
      ;;
    --from-source)
      FROM_SOURCE=1
      shift
      ;;
    --from-archive)
      [[ $# -ge 2 ]] || fail "--from-archive requires a value"
      ARCHIVE_PATH="$2"
      shift 2
      ;;
    --from-local-checkout)
      [[ $# -ge 2 ]] || fail "--from-local-checkout requires a value"
      LOCAL_CHECKOUT="$2"
      shift 2
      ;;
    --no-modify-path)
      MODIFY_PATH=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

if [[ -n "$ARCHIVE_PATH" ]]; then
  install_from_archive "$ARCHIVE_PATH"
elif [[ -n "$LOCAL_CHECKOUT" ]]; then
  install_from_local_checkout
elif [[ "$FROM_SOURCE" -eq 1 ]]; then
  install_from_source
else
  install_from_release
fi

log "done"
