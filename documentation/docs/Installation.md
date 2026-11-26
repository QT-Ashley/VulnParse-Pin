# Installation

VulnParse-Pin (`vpp`) is a cross-platform Python CLI package (`Linux`, `macOS`, and `Windows`) distributed on PyPI under the **Apache License, Version 2.0** (`v2.0.0+`).

See the [Usage Guide](Usage.md) for all subcommands and flags, [Workflow Examples](Workflow%20Examples.md) for runnable end-to-end workflows, and [Deployment Options](Deployment%20Options.md) for container, Kubernetes, and systemd deployments. For known constraints, refer to [Known Limitations](Known%20Limitations.md).

## Requirements

- **Python 3.11 or later** (CI tests Python `3.11`, `3.12`, `3.13`, and `3.14`):

  ```bash
  python --version
  ```

## Recommended: Isolated CLI Install with `pipx` or `uv`

Using [`pipx`](https://pipx.pypa.io/) or [`uv`](https://docs.astral.sh/uv/) installs `vpp` and `vulnparse-pin` in an isolated environment while placing the CLI directly on your `PATH`.

### With `pipx`

- **With interactive Textual TUI support (`[ui]` extra):**

  ```bash
  pipx install "vulnparse-pin[ui]"
  ```

- **Core headless CLI only (minimal dependencies for CI/automation):**

  ```bash
  pipx install vulnparse-pin
  ```

### With `uv`

- **With interactive Textual TUI support (`[ui]` extra):**

  ```bash
  uv tool install "vulnparse-pin[ui]"
  ```

- **Core headless CLI only:**

  ```bash
  uv tool install vulnparse-pin
  ```

## Alternative: Install with `pip` in a Virtual Environment

1. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   # Linux / macOS:
   source .venv/bin/activate
   # Windows PowerShell:
   # .venv\Scripts\Activate.ps1
   # Windows cmd.exe:
   # .venv\Scripts\activate.bat
   ```

2. Install VulnParse-Pin:

   ```bash
   pip install "vulnparse-pin[ui]"
   ```

   Or for headless CLI-only usage:

   ```bash
   pip install vulnparse-pin
   ```

3. For local development, testing, and CycloneDX SBOM generation:

   ```bash
   pip install -e ".[dev,ui,sbom]"
   ```

## Verify Installation

Both `vpp` and `vulnparse-pin` console scripts (as well as `python -m vulnparse_pin`) are installed:

```bash
vpp --help
vpp --version
```

Or using the full command name:

```bash
vulnparse-pin --help
vulnparse-pin --version
```

Run the 100% offline bundled demo to verify DuckDB, reporting, and TUI wiring end-to-end:

```bash
vpp demo --no-ui
```

## Environment Variables

VulnParse-Pin supports the following environment variables across runtime storage, threat-intel cache integrity, API lookups, and webhook delivery:

| Environment Variable | Purpose | Default / Notes |
| --- | --- | --- |
| `VULNPARSE_PIN_PORTABLE` | Set to `1`, `true`, `yes`, `y`, or `on` to enable portable `./data` storage instead of OS user data directories | Unset (`false`); equivalent to passing `--portable` / `-P` (`src/vulnparse_pin/core/apppaths.py`) |
| `VP_SQLITE_HMAC_KEY` | HMAC-SHA256 signing key for local SQLite threat-intel index files (`nvd_cache.sqlite3`, `epss_cache.sqlite3`, `kev_cache.sqlite3`, `ghsa_cache.sqlite3`, `osv_cache.sqlite3`) | Unset (falls back to unsigned SHA-256 digest verification in `.sig.json`); set a shared secret for tamper-evident cache enforcement (`vpp intel status`) |
| `VP_FEED_CACHE_HMAC_KEY` | HMAC-SHA256 signing key for cached raw feed files managed by `FeedCacheManager` | Unset (falls back to SHA-256 checksum sidecar); required when verifying HMAC-signed raw feed bundles across staging and air-gapped enclaves |
| `VP_GHSA_TK` | GitHub personal access token used by online `--ghsa` enrichment lookups (configured via `enrichment.ghsa_token_env` in `config.yaml`) | Unset; falls back to `GITHUB_TOKEN` if unset or invalid (`src/vulnparse_pin/utils/ghsa_enrichment.py`) |
| `GITHUB_TOKEN` | Standard GitHub Actions / CLI token fallback for online `--ghsa` lookups when `VP_GHSA_TK` is unset | Unset; increases GitHub API rate limits when querying GHSA online |
| `VP_WEBHOOK_HMAC_KEY` | HMAC-SHA256 signing secret for outbound scan-complete webhook payloads (configured via `webhook.signing_key_env` in `config.yaml`) | Unset; required when delivering signed webhooks (`--webhook-endpoint` or `webhook.enabled: true` in `config.yaml`) |

> [!NOTE]
> If you enable `VP_SQLITE_HMAC_KEY` or `VP_FEED_CACHE_HMAC_KEY` on a workspace that previously generated unsigned SHA-256 caches, refresh or re-sync your local caches with `vpp intel sync --refresh` (or `--allow-regen` for local sidecar regeneration) so `vpp intel status` validates cleanly under the HMAC key.

## Additional Notes

- **Distribution format (`v2.0.0+`)**: Starting with `v2.0.0`, VulnParse-Pin ships as standard attested Python wheels and source distributions via PyPI and [GitHub Releases](https://github.com/QT-Ashley/VulnParse-Pin/releases), plus multi-arch OCI container images at `ghcr.io/qt-ashley/vulnparse-pin` and a root source [Dockerfile](../../Dockerfile) (PyInstaller `--onefile` binaries were retired after `v1.2.2`). For containerized or read-only deployments, see [Deployment Options](Deployment%20Options.md).
- **Support**: For questions or issues, visit [GitHub Issues](https://github.com/QT-Ashley/VulnParse-Pin/issues) or email [support@vulnparse-pin.com](mailto:support@vulnparse-pin.com).
- **Upgrades**: Review [Upgrade and Migration](Upgrade%20and%20Migration.md) before upgrading from `v1.x` to `v2.0.0`.
