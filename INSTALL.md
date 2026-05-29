# Install fz

`fz` is the only supported end-user CLI for this repository.

## Recommended

Install the latest release binary:

```bash
curl -fsSL https://raw.githubusercontent.com/saint0x/fzy/main/install.sh | sh
```

By default the installer:

- downloads the latest release for your platform
- installs `fz` to `~/.local/bin`
- updates your shell profile if `~/.local/bin` is not already on `PATH`
- verifies the install with `fz version` and `fz env`

## Pin a version

```bash
curl -fsSL https://raw.githubusercontent.com/saint0x/fzy/main/install.sh | sh -s -- --version v0.1.0
```

## Custom install directory

```bash
curl -fsSL https://raw.githubusercontent.com/saint0x/fzy/main/install.sh | sh -s -- --to "$HOME/bin"
```

## Build from source

Use this when you intentionally want a local build instead of a release artifact:

```bash
curl -fsSL https://raw.githubusercontent.com/saint0x/fzy/main/install.sh | sh -s -- --from-source
```

This path requires:

- Rust toolchain with `cargo`
- network access to clone the repository if it is not already cached by Cargo

## Verify

```bash
fz version
fz env --json
fz usage
```

## Package and release

For maintainers:

- build a release archive locally with `scripts/build_release_archive.sh`
- publish tagged release artifacts through `.github/workflows/release.yml`
- Homebrew formula template lives at `packaging/homebrew/fz.rb`
