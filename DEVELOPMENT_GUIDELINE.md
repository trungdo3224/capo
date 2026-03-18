# CAPO Development Guidelines & Conventions

Consistency is key to keeping C.A.P.O. maintainable as it scales. Adhere to the following conventions when contributing.

## 1. Python Code Style

- **Linting & Formatting**: Use `ruff` (configured in `pyproject.toml`). Run it before committing:
  ```bash
  ruff check .
  ruff format .
  ```
- **Line length**: 100 characters (configured in `[tool.ruff]`).
- **Target version**: Python 3.10+. Use `match`, `|` union types, and `str | None` syntax freely.
- **Typing**: Use standard Python type hints. Prefer `list[dict]` over `List[Dict]`. Annotate all public function signatures.
- **Variables**: `snake_case` for variables and functions. `PascalCase` for classes.
- **Imports**: Sorted by `ruff` (rule `I`). Stdlib → third-party → local.

## 2. Error Handling

- **Custom exceptions only**: Raise from `capo/errors.py`. Never let raw `subprocess.CalledProcessError`, `KeyError`, or `FileNotFoundError` propagate to the CLI.

  ```python
  from capo.errors import ToolNotFoundError, TargetError, CapoError

  if not shutil.which("nmap"):
      raise ToolNotFoundError("nmap is not installed or not in PATH")
  ```

- **Missing binary**: Always check for the external tool binary before running. Catch `FileNotFoundError` and raise `ToolNotFoundError`.
- **No target set**: If a command requires a target and none is set, call `ensure_target()` from `capo/cli/helpers.py`. It prints a clean error and exits.

## 3. CLI UI Conventions

CAPO uses `typer` and `rich` for terminal output.

- **NEVER use standard `print()`**.
- **Always use `capo.utils.display` helpers**:
  - `print_success("[+] ...")` — successful actions
  - `print_error("[-] ...")` — critical failures or bad input
  - `print_warning("[!] ...")` — non-fatal edge cases (e.g., "No users found")
  - `console.print()` — general styled text, tables, panels
- **Fail gracefully**: On bad state or missing pre-conditions, print a clean error and `raise typer.Exit(1)`. Never let an unhandled Python exception reach the user.

## 4. Architecture Rules

### State & Campaign Management

- **Never write directly to `_state` dicts**. Always use the defined class methods on `StateManager` or `CampaignManager` (e.g., `add_user()`, `add_port()`, `add_domain()`). These handle FileLock concurrency, schema migration, and deduplication.
- **Domain data**: Use `StateManager.add_domain()` to add domains — never `set("domain", ...)`. State v3 uses a `domains` list; `get("domain")` returns the first entry for backward compatibility.
- **Access campaign data via public API**: Use `campaign_manager.get(key)` and `campaign_manager.campaign_dir`, not `campaign_manager._state` or `campaign_manager._dir`.
- **Know the scope**:
  - `StateManager` → host-specific data (ports, directories, vhosts, domains, scan history)
  - `CampaignManager` → engagement-wide data (AD domain, cross-host users, global credentials)
- **Variable injection**: Fetch injected values via `StateManager.get_var("USERFILE")`, never by manually accessing the list fields. `{PASSWORD}` is an alias for `{PASS}`.

### `capo/cli/` vs `capo/modules/`

- **`capo/cli/`**: Strictly for argument parsing and CLI command routing. No business logic, no parsing, no subprocess calls.
- **`capo/modules/`**: All logic lives here — tool execution, output parsing, state updates, rule evaluation. Instantiate modules from the CLI layer and call their methods.

### REST API (`capo/api.py`)

- All new endpoints must go through `capo/api.py` (the main API app).
- Use Pydantic v2 models for request/response bodies.
- Endpoints should read from `StateManager`/`CampaignManager` singletons — do not re-parse files at request time.
- The Studio API (`capo/studio/api.py`) is a separate app for CRUD over YAML files. Keep studio-specific logic there.

## 5. Writing Wrappers

When creating a new wrapper in `capo/modules/wrappers/`:

- **Inherit from `BaseWrapper`**. This provides `execute()`, dry-run mode, output file logging, scan history recording, and profile support.
- **Three-step contract**: 1) Build command, 2) `parse_output()`, 3) push to state. Keep these stages cleanly separated so `parse_output()` can be unit-tested in isolation with sample output strings.
- **No silent failures**: If a wrapper encounters bad output, log a warning and return empty results — do not crash.
- **Output directory**: Always write raw tool output to `~/.capo/workspaces/<ip>/scans/`. Use the `output_file` argument of `execute()`. `BaseWrapper._output_dir()` raises `TargetError` if no workspace is set — callers do not need to guard this themselves.

## 6. YAML Configuration Conventions

### Cheatsheets (`core_cheatsheets/`)

- Use standard variable tokens: `{IP}`, `{DOMAIN}`, `{USER}`, `{PASS}`, `{PASSWORD}`, `{USERFILE}`, `{PASSFILE}`, `{DC_IP}`, `{LHOST}`, `{LPORT}`, `{HOSTNAME}`, `{USERS_FILE}`, `{HASHES_FILE}`.
- Every command entry needs at minimum: `name`, `description`, `command`, `tool`, `tags`.
- `tags` are used by `fuzzy_search()`; include common synonyms.
- Custom cheatsheets in `~/.capo/custom_cheatsheets/` override core entries on `name` collision — document this behavior in your YAML.

### Methodologies (`core_methodologies/`)

- Each step needs an `id` (unique within the methodology), `name`, `commands` list.
- Optional auto-complete conditions: `users_min`, `ports_min`, `creds_min` — set these when step completion can be inferred from state minimums.
- `applicable_when.ports` controls which methodologies are suggested for a target.

### Daemon Rules (`core_rules/`)

- Use JMESPath expressions for `condition` fields. Test conditions with `jmespath.search()` locally before adding.
- `require_ports` is a convenience shorthand for "any of these ports open"; use it instead of a JMESPath port check where possible.
- `require_state` maps to semantic conditions: `has_domain` checks `state["domains"]` (v3) with fallback to `state["domain"]` (v2 compat); `has_valid_user` checks `state["users"]` or `state["credentials"]`; `has_valid_password` checks `state["credentials"]`.
- Keep `objective` strings short — they appear in the daemon's Rich table.

### Custom Triggers (`~/.capo/custom_triggers.yaml`)

- Keys are port numbers (integers or strings).
- Each entry needs `description`, `command`, and optionally `tags`.
- Regex patterns in trigger conditions must be sufficiently strict to avoid false positives.

## 7. Testing

- Write unit tests in `tests/`.
- **Always monkeypatch** `capo.config.CAPO_HOME` and `capo.config.WORKSPACES_DIR` to `tmp_path` to avoid touching live pentest state:
  ```python
  def test_something(tmp_path, monkeypatch):
      monkeypatch.setattr("capo.config.WORKSPACES_DIR", tmp_path / "workspaces")
  ```
- Use `typer.testing.CliRunner` for CLI integration tests.
- Parser tests must use sample output fixtures from `conftest.py` — do not require live tools.
- Wrapper tests should construct and validate command strings without executing (`dry_run=True`).
- Concurrent write tests must use `threading` with at least 3 threads to catch `filelock` edge cases.
