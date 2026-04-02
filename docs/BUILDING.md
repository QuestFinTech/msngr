# Building MSNGR

## Prerequisites

- **Go 1.24+** — [Download](https://go.dev/dl/)
- **GNU Make** — Pre-installed on Linux/macOS; on Windows use [MSYS2](https://www.msys2.org/) or WSL
- **Git** — For version/commit embedding

No other dependencies are required. MSNGR uses only the Go standard library and CGo-free SQLite, so cross-compilation works without a C toolchain.

## Build for your platform

```bash
make build
```

This compiles the `msngr` binary into the `run/` directory and copies `config.yaml.example` as `run/config.yaml` if no config exists yet.

## Build manually (without Make)

```bash
go build -ldflags "-X main.Version=0.2.0 -X main.Commit=$(git rev-parse --short HEAD) -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o msngr ./cmd/msngr
```

## Cross-compile release binaries

```bash
make release
```

This builds archives for all supported platforms into `dist/`:

| OS | Architecture | Archive |
|----|-------------|---------|
| Linux | amd64 | `msngr-0.2.0-linux-amd64.tar.gz` |
| Linux | arm64 | `msngr-0.2.0-linux-arm64.tar.gz` |
| macOS | amd64 (Intel) | `msngr-0.2.0-darwin-amd64.tar.gz` |
| macOS | arm64 (Apple Silicon) | `msngr-0.2.0-darwin-arm64.tar.gz` |
| Windows | amd64 | `msngr-0.2.0-windows-amd64.tar.gz` |
| Windows | arm64 | `msngr-0.2.0-windows-arm64.tar.gz` |

Each archive contains:
- `msngr` (or `msngr.exe` on Windows) — the compiled binary
- `config.yaml.example` — example configuration
- `LICENSE` — license file
- `README.md` — project readme

A `checksums.txt` file with SHA-256 hashes is generated alongside the archives.

## Overriding the version

The version defaults to the value in the Makefile. Override it for custom builds:

```bash
make build VERSION=0.3.0-beta
make release VERSION=0.3.0-rc1
```

## Running after build

```bash
cd run/

# Edit config.yaml as needed, then:
./msngr init    # Create database
./msngr run     # Start gateway
```

See [Configuration](../README.md#configuration) in the README for config details.

## Publishing a GitHub release

Tag the release and use `gh` to publish with the built archives:

```bash
git tag v0.2.0
git push origin v0.2.0

make release
gh release create v0.2.0 dist/*.tar.gz dist/checksums.txt \
  --title "MSNGR v0.2.0" \
  --notes "Release notes here"
```
