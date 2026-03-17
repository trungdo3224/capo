# CAPO (Context-Aware Pentest Orchestrator) — Developer & Architecture Guide

Welcome to the CAPO Developer Guide. This document covers the internal architecture so you can maintain, extend, and adapt the tool for your own penetration testing workflows.

## 1. Architectural Overview

CAPO is built on four core pillars:

1. **Context-Awareness**: Every action operates within a "Workspace" linked to a specific Target (IP/Hostname).
2. **State Storage**: Scan and enumeration results are persisted as a shared `state.json` per target.
3. **Variable Tokenization**: Commands use tokens like `{IP}`, `{DOMAIN}` that are resolved at runtime from state.
4. **YAML-Driven Logic**: Methodologies, cheatsheets, triggers, and daemon rules are YAML, so expanding functionality requires no Python code.

### Core Components

- **CLI Layer (`capo/cli/`)**: Built with [Typer](https://typer.tiangolo.com/). `cli/__init__.py` assembles the Typer app and registers all subcommand groups. CLI modules pass arguments to module-layer classes — no business logic lives here.
- **State Manager (`capo/state.py`)**: Manages `~/.capo/workspaces/<target>/state.json` using `filelock` for safe concurrent writes. All target-specific data (ports, users, credentials, directories) flows through here.
- **Campaign Manager (`capo/campaign.py`)**: Manages `~/.capo/campaigns/<name>/campaign.json`. Tracks engagement-wide AD data (domain, cross-host users, hashes, credentials). State Manager merges campaign data into `get_var()` lookups when a campaign is active.
- **Wrappers (`capo/modules/wrappers/`)**: Python classes inheriting from `BaseWrapper`. Each wrapper executes an external binary, parses its output, and pushes findings into State Manager.
- **Cheatsheet Engine (`capo/modules/cheatsheet/engine.py`)**: Loads 13 core YAMLs + custom YAMLs. Performs fuzzy search using `thefuzz`. Injects state variables into commands at lookup time.
- **Methodology Engine (`capo/modules/methodology.py`)**: Loads attack workflows from `core_methodologies/`. Tracks per-step progress in `state.json["methodology_progress"]`. Steps can self-complete when state satisfies configured minimums.
- **Trigger System (`capo/modules/triggers.py`)**: `PORT_TRIGGERS` dict maps port numbers to contextual suggestions. `check_triggers()` evaluates open ports + AD/web/credential context and prints next-step commands.
- **Daemon (`capo/modules/daemon.py`)**: Background process that polls `state.json` every 2 seconds. Loads `core_rules/*.yaml` (JMESPath-based conditions) and fires suggestion tables when state changes.
- **Mode Manager (`capo/modules/mode.py`)**: Enforces OSCP/CPTS exam policies. Controls which tools are allowed (e.g., Metasploit restrictions), AI feature gating, and logs Metasploit usage.
- **REST API (`capo/api.py`)**: FastAPI app (`capo.api:app`) exposing engagement state, suggestions, cheatsheets, methodologies, and triggers over HTTP for external tool integration and the Studio UI.
- **Studio (`capo/studio/`)**: Separate FastAPI app (`capo.studio.api:app`) launched via `capo studio`. Serves the React frontend and provides CRUD over cheatsheets/methodologies.

---

## 2. Directory Structure

```text
capo/
├── main.py                  # Entry point — imports app from cli/__init__.py
├── api.py                   # FastAPI REST API (capo.api:app)
├── config.py                # Global paths, profiles, exam mode constants
├── state.py                 # StateManager — per-target JSON with FileLock
├── campaign.py              # CampaignManager — engagement-wide cross-host data
├── errors.py                # Custom exceptions (TargetError, ToolNotFoundError, CapoError)
├── cli/
│   ├── __init__.py          # Typer app assembly, subapp registration
│   ├── target.py            # capo target commands
│   ├── scan.py              # capo scan commands
│   ├── nxc.py               # capo nxc commands
│   ├── brute.py             # capo brute commands
│   ├── web.py               # capo web commands
│   ├── state_cmds.py        # capo state commands
│   ├── mode_cmds.py         # capo mode + capo suggest
│   ├── cheatsheet.py        # capo search, query, categories
│   ├── triggers_cmds.py     # capo triggers commands
│   ├── methodology_cmds.py  # capo methodology commands
│   ├── daemon_cmds.py       # capo daemon command
│   ├── studio_cmds.py       # capo studio (launches web UI)
│   ├── report.py            # capo report commands
│   └── helpers.py           # ensure_target(), display helpers
├── modules/
│   ├── mode.py              # ModeManager — OSCP/CPTS enforcement
│   ├── triggers.py          # PORT_TRIGGERS + check_triggers() + custom triggers
│   ├── daemon.py            # Daemon + SuggestionRule (JMESPath polling)
│   ├── methodology.py       # MethodologyEngine, Methodology, MethodologyStep
│   ├── reporting.py         # CSV/Markdown export helpers
│   ├── cheatsheet/
│   │   └── engine.py        # CheatsheetEngine + CheatsheetEntry
│   └── wrappers/
│       ├── base.py          # BaseWrapper — execute(), parse_output(), get_suggestions()
│       ├── nmap_wrapper.py  # NmapWrapper — scans + XML parser
│       ├── nxc_wrapper.py   # NetExecWrapper — SMB/LDAP/WinRM/spray
│       ├── web_wrapper.py   # WebFuzzWrapper — ffuf dir/vhost/subdns/recursive
│       └── brute_wrapper.py # BruteWrapper — Hydra SSH/HTTP-POST/GET/web-form
├── core_cheatsheets/        # 13 built-in YAML command databases
├── core_methodologies/      # 4 attack workflow YAMLs
├── core_rules/              # Daemon suggestion rules (JMESPath-based YAMLs)
├── studio/
│   ├── api.py               # Studio FastAPI app + serves frontend/index.html
│   ├── schemas.py           # Pydantic models for studio endpoints
│   └── yaml_manager.py      # YAML read/write helper
└── utils/
    └── display.py           # Rich console formatting (tables, panels, colors)
```

---

## 3. The State Engine (`state.json`)

Running `capo target set 10.129.231.194` creates `~/.capo/workspaces/10.129.231.194/state.json`.

### Full State Schema (v2):

```json
{
  "schema_version": 2,
  "target": "10.129.231.194",
  "ip": "10.129.231.194",
  "domain": "corp.local",
  "os": "Windows Server 2016",
  "hostname": "DC01",
  "ports": [
    {"port": 445, "protocol": "tcp", "service": "smb", "version": "...", "state": "open"}
  ],
  "services": {"445/tcp": {"service": "smb", "version": "..."}},
  "users": ["Administrator", "john"],
  "hashes": [{"hash": "$krb5...", "username": "john"}],
  "credentials": [{"username": "john", "password": "Pass123", "service": "smb"}],
  "directories": [{"path": "/admin", "status": 200}],
  "vhosts": ["app.corp.local"],
  "shares": [{"name": "SYSVOL", "permissions": "READ", "comment": ""}],
  "domain_info": {"domain_name": "corp.local", "dc_ip": "10.129.231.194", "dns_name": ""},
  "notes": [{"note": "...", "timestamp": "..."}],
  "flags": {"local_txt": "", "proof_txt": ""},
  "scan_history": [
    {"tool": "nmap", "command": "...", "output_file": "...", "timestamp": "...", "duration": 12.3}
  ],
  "methodology_progress": {
    "ad_kill_chain": {"started_at": "...", "completed_steps": ["recon"]}
  },
  "created_at": "...",
  "updated_at": "..."
}
```

All tokens (`{IP}`, `{DOMAIN}`, `{USER}`, `{PASS}`, `{USERFILE}`, `{PASSFILE}`, `{DC_IP}`, `{LHOST}`, `{LPORT}`, `{HOSTNAME}`, `{USERS_FILE}`, `{HASHES_FILE}`) are resolved by `StateManager.get_var()`.

When a campaign is active, `StateManager.get_var()` also merges campaign-level users/hashes/credentials.

**Concurrency**: All writes use `filelock` + atomic temp-file swap. List fields are deduplicated-union'd; dict fields are shallow-merged on concurrent writes.

---

## 4. REST API (`capo/api.py`)

The main API app (`capo.api:app`) is for external integration. Start it with uvicorn or mount it in your own runner.

| Method | Path | Description |
|---|---|---|
| GET | `/api/config` | Capo config paths |
| GET | `/api/state` | Current target, workspace, campaign context |
| GET | `/api/engagement/status` | Active target + campaign + full state |
| GET | `/api/suggestions` | Context-aware suggestions for current target |
| GET | `/api/cheatsheets` | List cheatsheet filenames |
| GET | `/api/cheatsheets/{filename}` | Load cheatsheet YAML as JSON |
| POST | `/api/cheatsheets/{filename}` | Save cheatsheet to custom dir |
| GET | `/api/methodologies` | List methodology filenames |
| GET | `/api/methodologies/{filename}` | Load methodology YAML as JSON |
| POST | `/api/methodologies/{filename}` | Save methodology to custom dir |
| GET | `/api/triggers/custom` | Return custom triggers as port→entries dict |
| POST | `/api/triggers/custom` | Save custom triggers to `~/.capo/custom_triggers.yaml` |

---

## 5. Upgrading / Extending CAPO

### A. Adding a New CLI Command

All command groups live in `capo/cli/`. To add a new group (e.g., `capo pwn`):

1. Create `capo/cli/pwn.py` with a Typer sub-app and commands.
2. Register it in `capo/cli/__init__.py`:

```python
from capo.cli.pwn import app as pwn_app
app.add_typer(pwn_app, name="pwn")
```

3. Keep business logic out of the CLI module — put it in `capo/modules/`.

### B. Creating a New Tool Wrapper

1. Create `capo/modules/wrappers/gobuster_wrapper.py`.
2. Inherit from `BaseWrapper`.
3. Implement `parse_output()` to push findings to state, and `get_suggestions()` to return follow-up commands.

```python
from capo.modules.wrappers.base import BaseWrapper

class GobusterWrapper(BaseWrapper):
    def run_dir(self, wordlist: str):
        command = f"gobuster dir -u http://{self.state.get('ip')} -w {wordlist} -o out.txt"
        self.execute(command)

    def parse_output(self, output: str):
        for line in output.splitlines():
            if line.startswith("/"):
                self.state.add_directory({"path": line.split()[0], "status": 200})

    def get_suggestions(self) -> list[str]:
        return []
```

Always save raw output to `~/.capo/workspaces/<ip>/scans/` and raise `capo.errors.ToolNotFoundError` if the binary is missing.

### C. Creating a New Methodology (No Code Needed)

Add a YAML file to `capo/core_methodologies/`:

```yaml
id: api-pentest
name: "API Penetration Testing"
description: "Workflow for attacking REST APIs."
applicable_when:
  ports: [80, 443, 8080]
steps:
  - id: enumeration
    name: "Endpoint Enumeration"
    commands:
      - "ffuf -u http://{IP}/api/FUZZ -w /path/to/wordlist"
    users_min: 0
  - id: auth_bypass
    name: "Test JWT and Auth"
    commands:
      - "curl -H 'Authorization: Bearer <token>' http://{IP}/api/admin"
    users_min: 1
```

### D. Creating a New Cheatsheet (No Code Needed)

Add a YAML file to `capo/core_cheatsheets/` (e.g., `mysql.yaml`):

```yaml
category: "mysql"
description: "MySQL enumeration and exploitation"
commands:
  - name: "mysql-login"
    description: "Attempt root login without password"
    command: "mysql -h {IP} -u root"
    tool: "mysql"
    tags: ["database", "mysql", "auth"]
  - name: "mysql-creds"
    description: "Extract credentials from db"
    command: "mysql -h {IP} -u {USER} -p{PASS} -e 'SELECT * FROM users;'"
    tool: "mysql"
    tags: ["database", "mysql", "creds"]
```

Custom cheatsheets in `~/.capo/custom_cheatsheets/` override core entries with the same name.

### E. Adding a Daemon Rule (No Code Needed)

Add a YAML file to `capo/core_rules/` with JMESPath conditions:

```yaml
rules:
  - id: krb-detected
    name: "Kerberos Detected"
    description: "Port 88 open — likely DC"
    require_ports: [88]
    objective: "Enumerate AD with Kerbrute"
    commands:
      - "kerbrute userenum -d {DOMAIN} --dc {DC_IP} /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"
```

### F. Adding Custom Triggers

Create `~/.capo/custom_triggers.yaml`:

```yaml
8080:
  - description: "Tomcat manager panel"
    command: "curl -s http://{IP}:8080/manager/html"
    tags: ["web", "tomcat"]
```

---

## 6. Testing

All tests are in `tests/` and use `pytest`. Run from the project root:

```bash
pytest -v
```

Key conventions:
- Always monkeypatch `capo.config.CAPO_HOME` and `capo.config.WORKSPACES_DIR` to `tmp_path` to avoid touching the developer's live state.
- Use `typer.testing.CliRunner` for CLI integration tests.
- Keep parser tests independent of live tools by using sample output fixtures from `conftest.py`.
- Test wrappers by constructing commands without executing (`dry_run=True`).

### Test Coverage

| File | What it tests |
|---|---|
| `test_state.py` | StateManager: set_target, add_port, add_user, add_credential, add_hash, get_var, export, schema migration |
| `test_campaign.py` | CampaignManager: set/clear campaign, add_host/user/hash/credential, state merge |
| `test_cheatsheet.py` | CheatsheetEngine: load_all, search, fuzzy_search, variable injection, multi-credential expansion |
| `test_triggers.py` | PORT_TRIGGERS, check_triggers, custom trigger loading, AD/web/credential context |
| `test_methodology.py` | MethodologyEngine: load, get_applicable, get_progress, auto_check, auto-complete conditions |
| `test_mode.py` | ModeManager: set_mode, tool allowlist (OSCP/CPTS), Metasploit tracking, can_use_ai |
| `test_parsers.py` | Nmap XML parser, NXC LDAP/shares/RID/null parser, ffuf JSON parser |
| `test_brute.py` | BruteWrapper: SSH/HTTP-POST command construction and validation |
| `test_web_subdns.py` | WebFuzzWrapper subdns command construction |
| `test_git_exposure.py` | Git exposure detection → git-specific suggestion triggers |
| `test_cli.py` | CLI integration via CliRunner |
| `test_state_locking.py` | FileLock concurrent write safety |
| `test_daemon.py` | SuggestionRule evaluation, Daemon.evaluate_and_suggest |

---

## 7. System Chart

```
flowchart TD
    style CLI fill:#2b1d3d,stroke:#ff007f,stroke-width:2px,color:#fff
    style StateMgr fill:#003366,stroke:#00aaff,stroke-width:2px,color:#fff
    style Workspace fill:#1a1a1a,stroke:#aaaaaa,stroke-dasharray: 5 5,color:#fff

    classDef logic fill:#003300,stroke:#00ffaa,stroke-width:1px,color:#fff
    classDef wrapper fill:#400000,stroke:#ff5555,stroke-width:1px,color:#fff
    classDef database fill:#333300,stroke:#ffff00,stroke-width:1px,color:#fff

    CLI["💻 CLI (capo/cli/__init__.py)"]

    StateMgr["🧠 State Manager (state.py)"]
    CampMgr["🛡️ Campaign Manager (campaign.py)"]
    Workspace[/"📂 ~/.capo/workspaces/{target}/state.json"\]
    CampaignDB[/"📂 ~/.capo/campaigns/{name}/campaign.json"\]

    StateMgr <--> Workspace
    CampMgr <--> CampaignDB
    StateMgr -->|Query AD info| CampMgr

    subgraph Intelligence ["📚 Intelligence Databases"]
        direction LR
        Cheatsheets[/"core_cheatsheets/*.yaml"/]:::database
        Rules[/"core_rules/*.yaml"/]:::database
        Methodologies[/"core_methodologies/*.yaml"/]:::database
    end

    subgraph Wrappers ["🛠️ Tool Wrappers"]
        direction LR
        BaseWrap("base.py"):::wrapper
        BaseWrap -.-> Nmap("nmap"):::wrapper
        BaseWrap -.-> NxC("nxc"):::wrapper
        BaseWrap -.-> Brute("brute"):::wrapper
        BaseWrap -.-> Web("web"):::wrapper
    end

    subgraph Modules ["⚙️ Core Modules"]
        direction LR
        Daemon("daemon.py"):::logic
        Method("methodology.py"):::logic
        Trigger("triggers.py"):::logic
        Report("reporting.py"):::logic
        Mode("mode.py"):::logic
    end

    API["🌐 REST API (api.py)"]
    Studio["🖥️ Studio (studio/api.py)"]

    CLI -->|Command Routing| Wrappers
    CLI -->|Invokes| Modules
    CLI -->|Manages| StateMgr
    CLI --> API
    API --> Studio

    Nmap & NxC & Brute & Web -- "Push Parsed Data" --> StateMgr
    StateMgr <--> |Atomic Sync| Workspace

    Daemon -- "Polls State" --> Workspace
    Daemon -.-> |Loads conditions| Rules

    Method -- "Updates Progress" --> StateMgr
    Method -.-> |Parses Steps| Methodologies

    Report -- "Reads" --> StateMgr
    Trigger -- "Evaluates & Injects" --> StateMgr

    CLI -.-> |Fuzzy Match / Query| Cheatsheets

    API --> StateMgr
    API -.-> |Reads| Cheatsheets
    API -.-> |Reads| Methodologies
```
