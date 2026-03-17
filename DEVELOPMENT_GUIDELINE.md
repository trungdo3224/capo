# CAPO Development Guidelines & Conventions

Consistency is key to keeping C.A.P.O. maintainable as it scales. When contributing to or expanding on CAPO, please adhere to the following conventions to ensure high quality and predictable behavior.

## 1. Python Code Style

- **Formatting**: We use `black` for formatting and `isort` for import sorting. Always run these tools before committing.
- **Typing**: Use standard Python type hinting (e.g., `def parse(self, output: str) -> list[dict]:`). This helps catch bugs early.
- **Variables**: Use `snake_case` for variables and functions. Use `PascalCase` for Classes. 

## 2. CLI UI Conventions

CAPO uses `typer` and the `rich` library for terminal output. Consistency in UI helps pentester workflows immensely.

- **NEVER use standard `print()`**.
- **Always use `capo.utils.display` helpers**:
  - `print_success("[+] ...")` for successful actions.
  - `print_error("[-] ...")` for critical failures or bad input.
  - `print_warning("[!] ...")` for edge cases or non-fatal issues (e.g. "No users found").
  - `console.print()` for general styled text tables.
- **Fail Gracefully**: If a user runs a command that needs an IP but no target is set in state, print a clean `print_error("No target set")` and exit, rather than throwing a Python unhandled exception.

## 3. Architecture Rules

### State & Campaign Management
- **Do not write directly to `_state` dictionaries**. Always use the defined class methods on `StateManager` or `CampaignManager` (e.g. `add_user()`, `add_port()`). These methods handle crucial business logic like FileLock concurrency and deduplication.
- **Know the Scope**:
  - `StateManager`: For *Host-Specific* data (ports, directories, vulnerabilities).
  - `CampaignManager`: For *Engagement-Wide* data (Active Directory domains, organization users, global cracked passwords).
- **Variable Injection**: If a tool wrapper requires authentication logic, fetch the variables using `StateManager.get_var("USERFILE")` rather than manually accessing the list.

### `capo/cli/` vs `capo/modules/`
- **`capo/cli/`**: This folder is **strictly for argument parsing and CLI command routing**. Business logic, data parsing, and execution should not live here.
- **`capo/modules/`**: This is where logic lives. Tool wrappers execution, output parsing, methodology tracking. Instantiate modules from the CLI layer.

## 4. Writing Wrappers

When creating a new wrapper in `capo/modules/wrappers/`:
- **Subprocess**: Always use the provided helper methods in `BaseWrapper` for executing shell commands, as this provides standard logging and `--dry-run` inspection natively.
- **Missing Dependencies**: Assume the user might not have the tool installed. Catch `FileNotFoundError` or check for the binary first, and raise a `capo.errors.ToolNotFoundError` gracefully.
- **State Updating**: A wrapper’s job is 1) Run Tool, 2) Parse Output, 3) Update State. Keep the parsing logic isolated so it can be Unit Tested with sample output files easily.

## 5. YAML Configuration Conventions

Methodologies and Cheatsheets are heavily YAML-driven. To maintain them:
- **Use Standard Variables**: Stick to predefined tokens like `{IP}`, `{DOMAIN}`, `{USER}`, `{PASS}`, `{USERFILE}`, `{PASSFILE}`, `{LHOST}`, `{LPORT}`.
- **Triggers**: When adding auto-suggest triggers in `core_triggers.yaml`, ensure the regex patterns are sufficiently strict to prevent false positives during module parsing.

## 6. Testing

- Write reproducible Unit Tests in `tests/`.
- Ensure CLI test functions use `typer.testing.CliRunner`.
- **Mocks**: When testing file I/O operations around state config, always monkeypatch `capo.config.CAPO_HOME` and `capo.config.WORKSPACES_DIR` using a `tmp_path` fixture to avoid nuking the developer's actual pentest state.
