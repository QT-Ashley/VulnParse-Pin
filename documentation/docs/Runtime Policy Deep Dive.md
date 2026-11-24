# Runtime Policy Deep Dive

This page explains runtime control-plane policy in VulnParse-Pin v2.0.0 (`Apache-2.0`): `PermFileHandler` (PFH), `_UMASK_LOCK` & non-PFH atomic writes, DuckDB workspace permissions, read-only `vpp verify` enforcement, logging policy, and `RunContext` / `Services` wiring.

## Scope

Primary implementation files:

- `src/vulnparse_pin/app/bootstrap.py`
- `src/vulnparse_pin/cli/commands.py` (`_build_verify_pfh`, `run_verify_command`, `run_intel_command`)
- `src/vulnparse_pin/core/classes/dataclass.py` (`RunContext`, `Services`)
- `src/vulnparse_pin/io/pfhandler.py` (`PermFileHandler`, `_UMASK_LOCK`)
- `src/vulnparse_pin/storage/db.py` (`VppDatabase`, `_validate_duckdb_paths`, `ensure_safe_dir_non_pfh`, `open_for_write_non_pfh`)
- `src/vulnparse_pin/utils/logger.py`
- `src/vulnparse_pin/cli/args.py`

## Runtime bootstrap sequence (`initialize_runtime`)

1. Resolve `AppPaths.resolve(portable=...)` (XDG/platform app-data vs `--portable` `./data/`).
2. Create required directories (`paths.ensure_dirs()`).
3. Initialize bootstrap `LoggerWrapper` (`bootstrap.log`).
4. Construct `PermFileHandler` via `build_pfh(paths, logger, args)`.
5. Load, validate, and project configs via `ConfigSource -> ConfigValidator -> ConfigProjector`.
6. Initialize `FeedCacheManager`, optional `NVDFeedCache`, `LedgerService`, and `WebhookRuntimeConfig`.
7. Assemble frozen `Services` and `RunContext`.
8. Rebind `LoggerWrapper` to the run-specific log file (`build_run_log()`).
9. Construct `SchemaDetector(PARSER_SPECS)`.

## `RunContext` and `Services`

`RunContext` (`paths`, `pfh`, `logger`, `services`) and `Services` (`feed_cache`, `nvd_cache`, `scoring_config`, `topn_config`, `ledger`, `runmanifest_mode`, `nmap_ctx_config`, `webhook_config`, `global_config`, plus v2 fields `db`, `run_id`, `asset_matcher`, `decisions_registry`) are frozen dataclasses so runtime policy cannot be mutated mid-run.

## PFH Policy (`PermFileHandler`) and CLI Defaults

`build_pfh()` constructs `PermFileHandler` with secure-by-default flags from `cli/args.py`:

| Flag / Attribute | Default | Override Flag | Effect |
| --- | --- | --- | --- |
| `forbid_symlinks_read` | `True` | `--allow-symlinks-read` | Rejects symlinks and symlink ancestors on read |
| `forbid_symlinks_write` | `True` | (fail-closed) | Rejects symlinks and symlink ancestors on write |
| `enforce_roots_on_read` | `False` | `--enforce-root-read` (`-err`) | Confines reads to `allowed_roots` + explicit workspace roots |
| `enforce_roots_on_write` | `True` | (enforced) | Confines writes to authorized output paths & `allowed_roots` |
| `file_mode` (POSIX) | `0o600` | `--file-mode` (`-fm`) | Owner-only read/write permissions on created files |
| `dir_mode` (POSIX) | `0o700` | `--dir-mode` (`-dm`) | Owner-only permissions on created directories |

Diagnostic mode:

```bash
vpp scan --debug-path-policy
```

prints `pfh.describe_policy()` and exits without running a scan.

## `_UMASK_LOCK`, Non-PFH Atomic Writes, and DuckDB Path Hardening

Because `os.umask()` is process-global, `src/vulnparse_pin/io/pfhandler.py` defines `_UMASK_LOCK = threading.Lock()`. Both PFH and `src/vulnparse_pin/storage/db.py` serialize `umask` transitions under `_UMASK_LOCK`:

- **`ensure_safe_dir_non_pfh(dir_path, dir_mode=0o700)`:** Checks every path ancestor against symlinks and `ELOOP` loops (`_check_no_symlinks_or_loops`), creates missing directories with `0o777 & ~dir_mode` under `_UMASK_LOCK`, and re-verifies post-create.
- **`open_for_write_non_pfh(target_path, file_mode=0o600, dir_mode=0o700)`:** Validates ancestors and existing targets against symlinks/non-regular files, creates a sibling staging temp file under restricted `umask` (`_UMASK_LOCK`), applies `0o600` POSIX permissions, and atomically replaces the target via `os.replace()`.
- **`VppDatabase` & `_validate_duckdb_paths()`:** Before opening `.vpp.db`, validates the DB path, all ancestors, and `.wal` / `.tmp` sidecars against symlinks and `ELOOP`. In read-write mode on POSIX, `duckdb.connect()` and `BEGIN TRANSACTION` execute with `umask(0o177)` under `_UMASK_LOCK` so `.vpp.db` and `.wal` are born `0o600` without a race window, followed by `_chmod_0600_if_exists()`.

## Read-Only Default Policy on `vpp verify` (`_build_verify_pfh`)

`run_verify_command()` (`src/vulnparse_pin/cli/commands.py`) uses `_build_verify_pfh(args)` rather than `initialize_runtime(args)`:

- Attaches a silent `logging.NullHandler()` logger and calls `build_pfh(paths, silent_logger, args)` **without** calling `paths.ensure_dirs()`, so `vpp verify` performs **zero writes** to `$HOME`, `$XDG_DATA_HOME`, `$XDG_CONFIG_HOME`, or `$XDG_CACHE_HOME` (allowing execution in read-only containers and `0o500` home environments).
- Directories and log files are created only if the operator explicitly passes a non-default `--log-file` (`!= "vulnparse_pin.log"`).
- All security flags (`forbid_symlinks_read=True`, `--allow-symlinks-read`, `--enforce-root-read`, `--portable`) remain strictly enforced across both the RunManifest file and every non-null artifact listed in `manifest["outputs"]`.

## Logging Policy (`LoggerWrapper`)

`LoggerWrapper` (`src/vulnparse_pin/utils/logger.py`) configures a `DEBUG` file handler (ANSI-stripped) and a CLI-level console handler (`INFO` default, custom `SUCCESS` level `25`).

## Related pages

- [Security Features](Security%20Features.md)
- [Threat Model](Threat%20Model.md)
- [Caching Deep Dive](Caching%20Deep%20Dive.md)
- [Usage](Usage.md)
