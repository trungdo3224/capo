# CAPO (Context-Aware Pentest Orchestrator) - Developer & Architecture Guide

Welcome to the CAPO Developer Guide. This document is designed to help you understand the internal architecture of CAPO so you can independently maintain, extend, and adapt the tool for your own penetration testing workflows.

## 1. Architectural Overview

CAPO is built on a few core philosophical pillars:
1. **Context-Awareness**: Every action takes place within a "Workspace" linked to a specific Target (IP/Hostname).
2. **State Storage**: The results of scans and enumerations are saved as a shared state (JSON).
3. **Variable Tokenization**: Complex commands use tokens (e.g., `{IP}`, `{DOMAIN}`) that are dynamically resolved using the State Storage.
4. **YAML-Driven Logic**: Methodologies and Cheatsheets are heavily abstracted into YAML to allow for rapid expansion without writing Python code.

### Core Components

- **CLI Layer (`capo/cli/main.py`)**: Built using [Typer](https://typer.tiangolo.com/). Handles routing user commands to the appropriate subcommand modules (`scan.py`, `brute.py`, etc.).
- **State Manager (`capo/state.py`)**: Manages `~/.capo/workspaces/<target>/state.json` via FileLock concurrency. Handles reading, appending, and variable substitution.
- **Campaign Manager (`capo/campaign.py`)**: Manages `~/.capo/campaigns/<campaign>/campaign.json` via FileLock. Syncs engagement-wide AD data across all hosts in a campaign.
- **Wrappers (`capo/modules/wrappers/`)**: Python classes that wrap external binaries (like `nmap`, `ffuf`). They execute the tool, parse the output, and push findings back to the State Manager.
- **Brute Wrapper (`capo/modules/wrappers/brute_wrapper.py`)**: Hydra-powered SSH and web-form bruteforce wrapper (`http-post`, `http-get`, custom modules).
- **Methodology Engine (`capo/modules/methodology.py`)**: Parses workflows defined in `core_methodologies/` (YAML) and prompts the user to execute step-by-step commands.
- **Cheatsheet Engine (`capo/modules/cheatsheet/engine.py`)**: Parses reference queries in `core_cheatsheets/` (YAML), substituting variables with current state context so the user can copy-paste them directly.

---

## 2. Directory Structure

```text
capo/
├── cli/                     # CLI commands (Typer subcommands)
│   ├── main.py              # Entry point for the CLI application
│   └── target.py, scan.py   # Isolated CLI groups
├── state.py                 # Core logic for managing state.json and resolving tokens
├── campaign.py              # Core logic for cross-host AD data tracking
├── config.py                # Global configurations & path definitions
├── core_cheatsheets/        # YAML files containing copy-paste command references
├── core_methodologies/      # YAML files dictating step-by-step workflows
├── modules/
│   ├── methodology.py       # Logic to step through Methodologies
│   ├── triggers.py          # Trigger system (e.g., if Port 80 is open -> run web methodology)
│   ├── cheatsheet/          # Cheatsheet engine logic
│   └── wrappers/            # Tool wrappers (nmap, ffuf, etc.)
│       ├── base.py          # Base wrapper class providing shell execution
│       ├── nmap_wrapper.py  # Nmap execution and XML parsing
│       ├── nxc_wrapper.py   # NetExec/CME execution and parsing
│       ├── web_wrapper.py   # ffuf directory/vhost/subdns execution and parsing
│       └── brute_wrapper.py # Hydra SSH/web form bruteforce execution and parsing
└── utils/
    └── display.py           # Rich console formatting (tables, panels, colors)
```

---

## 3. The State Engine (`state.json`)

When you run `capo target set 10.129.231.194`, CAPO generates a folder at `~/.capo/workspaces/10.129.231.194/` with a `state.json` file.

### Example State Object:
```json
{
  "target": "10.129.231.194",
  "ip": "10.129.231.194",
  "domain": "linkvortex.htb",
  "vhosts": ["dev.linkvortex.htb"],
  "ports": [
    {"port": 22, "protocol": "tcp", "service": "ssh", "version": "", "state": "open"},
    {"port": 80, "protocol": "tcp", "service": "http", "version": "", "state": "open"}
  ],
  "services": {
    "80/tcp": {"service": "http", "version": "Apache"}
  },
  "credentials": [
    {"username": "admin", "password": "Summer2024!", "service": "http-post-form"}
  ]
}
```

Whenever a Cheatsheet or Methodology uses a token like `{IP}` or `{DOMAIN}`, `state.py` reads this JSON and injects the live values.

---

## 4. Upgrading / Extending CAPO

### A. Adding a New Typer CLI Command (Python)
If you want to add a new top-level command like `capo pwn`, open `capo/main.py`:

```python
@app.command("pwn")
def pwn_target(target: str = typer.Argument(..., help="Target IP")):
    """
    Launch the ultimate pwn module.
    """
    from capo.state import state_manager
    state_manager.set_target(target)
    # Do your logic here...
    console.print(f"[+] Pwning {state_manager.get('ip')}...")
```

### B. Creating a New Tool Wrapper
If you want CAPO to natively run a new tool (e.g., `gobuster`) and save its results to state:

1. Create `capo/modules/wrappers/gobuster_wrapper.py`.
2. Inherit from `BaseWrapper` (or implement standard subprocess logic).
3. Execute the tool, ensuring you output to the `~/.capo/workspaces/<ip>/scans/` directory.
4. **Parse the output** and push it into the state.
```python
# Pseudo-code
def run_gobuster(self, target_url):
    command = f"gobuster dir -u {target_url} -w wordlist.txt -o out.txt"
    self.execute_shell(command)
    directories = self.parse_gobuster_output("out.txt")
  for d in directories:
    self.state.add_directory(d)
```

### E. New Brute Module (Hydra)
CAPO now includes a dedicated brute-force command group:

```bash
capo brute ssh -U users.txt -P passwords.txt
capo brute http-post --form '/login.php:username=^USER^&password=^PASS^:F=Invalid' -U users.txt -P passwords.txt
capo brute web-form -m https-post-form --form '/auth:user=^USER^&pass=^PASS^:F=invalid' -U users.txt -P passwords.txt
```

Implementation reference:
- `capo/modules/wrappers/brute_wrapper.py`
- `capo/main.py` (`brute` Typer group)

### C. Creating a New Methodology (No Code Needed)
Methodologies are just YAML files in `capo/core_methodologies/`. 
To add an API testing methodology, create `core_methodologies/api_pentest.yaml`:

```yaml
id: api-pentest
name: "API Penetration Testing"
description: "Workflow for attacking RESTly APIs."
steps:
  - id: enumeration
    name: "Endpoint Enumeration"
    commands:
      - "ffuf -u http://{IP}/api/FUZZ -w /path/to/wordlist"
  - id: auth_bypass
    name: "Test JWT and Auth"
    commands:
      - "Include JWT tokens in headers: -H 'Authorization: Bearer <token>'"
```

### D. Creating a New Cheatsheet (No Code Needed)
Simply add a YAML file to `capo/core_cheatsheets/` (e.g., `mysql.yaml`). 

```yaml
id: mysql
name: MySQL Enumeration
categories:
  - name: Login
    commands:
      - desc: "Attempt root login without password"
        cmd: "mysql -h {IP} -u root"
  - name: Exploitation
    commands:
      - desc: "Extract credentials from db"
        cmd: "mysql -h {IP} -u {USERNAME} -p{PASSWORD} -e 'SELECT * FROM users;'"
```
CAPO will automatically detect this and make it available via `capo query mysql`.

---

## 5. Testing and Debugging

- **Testing**: Tests are located in `tests/`. Run them using `pytest` from the root directory to ensure state parsing and wrapper logic work correctly.
  ```bash
  pytest -v
  ```
- **Debugging**: 
  - If state parsing fails, check `~/.capo/workspaces/<ip>/state.json`. Manually editing this file can fix broken states during development.
  - If an external tool inside a wrapper fails, ensure you print or log `stderr`. Wrappers should always gracefully handle missing binaries or failed executions without crashing the main Typer app.


# System Chart

flowchart TD
    style CLI fill:#2b1d3d,stroke:#ff007f,stroke-width:2px,color:#fff
    style StateMgr fill:#003366,stroke:#00aaff,stroke-width:2px,color:#fff
    style Workspace fill:#1a1a1a,stroke:#aaaaaa,stroke-dasharray: 5 5,color:#fff
    
    classDef logic fill:#003300,stroke:#00ffaa,stroke-width:1px,color:#fff
    classDef wrapper fill:#400000,stroke:#ff5555,stroke-width:1px,color:#fff
    classDef database fill:#333300,stroke:#ffff00,stroke-width:1px,color:#fff

    %% CLI Layer
    CLI["💻 CLI Entrypoint (cli/main.py)"]
    
    %% State
    StateMgr["🧠 State Manager (state.py)"]
    CampMgr["🛡️ Campaign Manager (campaign.py)"]
    Workspace[/"📂 ~/.capo/workspaces/{target}/state.json"\]
    CampaignDB[/"📂 ~/.capo/campaigns/{name}/campaign.json"\]
    
    StateMgr <--> Workspace
    CampMgr <--> CampaignDB
    StateMgr -->|Query AD info| CampMgr
    
    %% Intelligence
    subgraph Intelligence ["📚 Intelligence Databases"]
        direction LR
        Cheatsheets[/"core_cheatsheets/*.yaml"/]:::database
        Rules[/"core_rules/*.yaml"/]:::database
        Methodologies[/"core_methodologies/*.yaml"/]:::database
    end
    
    %% Tool Wrappers
    subgraph Wrappers ["🛠️ Tool Wrappers"]
        direction LR
        BaseWrap("base.py\n(Run & Parse)"):::wrapper
        BaseWrap -.-> Nmap("nmap"):::wrapper
        BaseWrap -.-> NxC("nxc"):::wrapper
        BaseWrap -.-> Brute("brute"):::wrapper
        BaseWrap -.-> Web("web"):::wrapper
    end
    
    %% Core Modules
    subgraph Modules ["⚙️ Core Modules"]
        direction LR
        Daemon("daemon.py\n(Suggestions)"):::logic
        Method("methodology.py\n(Step Tracking)"):::logic
        Trigger("triggers.py\n(Autopilot)"):::logic
        Report("reporting.py\n(Doc Gen)"):::logic
        Mode("mode.py\n(OSCP/Cpts restrictions)"):::logic
    end
    
    %% Relationships
    CLI -->|"Command Routing"| Wrappers
    CLI -->|"Invokes"| Modules
    CLI -->|"Manages"| StateMgr
    
    %% State Flow
    Nmap & NxC & Brute & Web -- "Push Parsed Data" --> StateMgr
    StateMgr <--> |"Atomic Sync"| Workspace
    
    %% Module Interactions
    Daemon -- "Polls State" --> Workspace
    Daemon -.-> |"Loads conditions"| Rules
    
    Method -- "Updates Step DB" --> StateMgr
    Method -.-> |"Parses Steps"| Methodologies
    
    Report -- "Reads" --> StateMgr
    Trigger -- "Evaluates & Injects" --> StateMgr
    
    CLI -.-> |"Fuzzy Match / Query"| Cheatsheets