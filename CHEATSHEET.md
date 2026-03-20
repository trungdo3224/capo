# C.A.P.O Cheatsheet (Context-Aware Pentest Orchestrator)

## Workflow Basics

**1. Start a New Engagement**
```bash
# Option A: Session-based (recommended — full command tracking)
capo session new Forest 10.10.10.161 --domain htb.local --campaign HTB

# Option B: Quick target-only (no session tracking)
capo target set 10.10.10.10
capo target set-domain example.com --dc-ip 10.10.10.10
capo target campaign my-ad-lab
```

**2. Initial Recon**
```bash
# Fast TCP scan (all ports)
capo scan quick

# Run default Nmap scripts on discovered ports
capo scan detailed

# Or run the full pipeline: quick -> detailed -> triggers
capo scan full
```

**3. Web Enumeration**
```bash
# Fuzz directories (auto-uses target IP)
capo web fuzz

# Fuzz directories against domain/subdomain host header context
capo web fuzz --host domain -d app.example.com

# Scan for vhosts
capo web vhost --domain example.com

# DNS subdomain enumeration
capo web subdns --domain example.com

# Recursive directory scan
capo web recursive --depth 2
```

**4. Password Brute Force (Hydra)**
```bash
# SSH single credential check
capo brute ssh -u root -p toor

# SSH bruteforce with user/pass lists
capo brute ssh -U users.txt -P passwords.txt

# HTTP POST form bruteforce
capo brute http-post --form '/login.php:username=^USER^&password=^PASS^:F=Invalid' -U users.txt -P passwords.txt
```

**5. Check Progress**
```bash
# See what ports/creds/users have been found
capo state show

# Get context-aware next steps
capo suggest

# Review session command history
capo session show
```

---

## Session Management (`capo session`)

Named engagement contexts with full command tracking in SQLite. Every `capo scan/nxc/web/brute/kerberos` command is auto-recorded.

| Command | Description | Example |
| :--- | :--- | :--- |
| `new` | Create + activate session | `capo session new Forest 10.10.10.161 -d htb.local -c HTB` |
| `use` | Switch to an existing session | `capo session use Sauna` |
| `list` | List all sessions with stats | `capo session list` |
| `show` | Session detail + commands + findings | `capo session show` / `capo session show Forest` |
| `delete` | Delete a session and all its data | `capo session delete Forest` / `--force` |
| `commands` | List commands in active session | `capo session commands --key --tool nmap` |
| `log` | Manually record a command run outside capo | `capo session log "ssh user@10.10.10.161"` |
| `mark` | Mark a command as key step and/or finding | `capo session mark 3 --key --finding "Got shell"` |
| `findings` | List all findings in active session | `capo session findings` |

```bash
# Full session workflow
capo session new Forest 10.10.10.161 --domain htb.local --campaign HTB
capo scan quick                                     # auto-recorded
capo scan detailed                                  # auto-recorded
capo session commands                               # see all recorded commands
capo session mark 3 --key                           # flag command #3 as key step
capo session mark 5 --key --finding "AS-REP hash" --category credential --severity high
capo session findings                               # review findings
capo session log "evil-winrm -i 10.10.10.161"       # log manual command
capo session use Sauna                              # switch to another session
capo session list                                   # overview all sessions
```

---

## Target Management (`capo target`)

| Command | Description | Example |
| :--- | :--- | :--- |
| `set` | Set target IP & init workspace | `capo target set 10.129.2.5` |
| `show` | Show current target info | `capo target show` |
| `campaign` | Set Active Campaign context | `capo target campaign my-lab` |
| `set-domain` | Set AD domain context | `capo target set-domain flight.htb` |
| `set-lhost` | Set your IP/Port for reverse shells | `capo target set-lhost 10.10.14.5 -p 443` |
| `add-domain` | Add an associated domain name | `capo target add-domain dc.flight.htb` |
| `add-vhost` | Manually add a sub/vhost to scope | `capo target add-vhost admin.flight.htb` |
| `note` | Add a text note to the target | `capo target note "Potential BOF on port 88"` |
| `flag` | Save a captured flag | `capo target flag local af7b...` |
| `add-user` | Manually add a user | `capo target add-user svc_sql` |
| `add-cred` | Manually add credentials | `capo target add-cred svc_sql P@ssword!` |
| `add-hash` | Manually add a hash | `capo target add-hash $krb5tgs$...` |

## Scanning (`capo scan`)

| Command | Description |
| :--- | :--- |
| `quick` | **Phase 1**: Quick SYN scan of all 65535 TCP ports. Updates state with open ports. |
| `detailed` | **Phase 2**: Runs `nmap -sC -sV` only on ports found in the `quick` scan. |
| `full` | Runs `quick` -> `detailed` -> triggers in one go. |
| `udp` | Scans top UDP ports. |
| `vuln` | Runs safe NSE vulnerability scripts (OSCP-safe). |
| `ports` | Scan specific ports with version/script detection. |
| `os` | OS detection scan (-O --osscan-guess). Best run as root. |
| `scripts` | Run specific NSE scripts against discovered ports. |
| `custom` | Custom nmap scan — pass any nmap flags. |

```bash
capo scan quick --profile aggressive   # Lab/CTF speed
capo scan quick --profile stealth      # Fragile targets
capo scan ports 80,443,8080            # Targeted port scan
capo scan os                           # OS fingerprinting
capo scan scripts smb-vuln-ms17-010    # Run specific NSE scripts
capo scan custom --args "-p 80 -sC --script http-enum"   # Any nmap flags
```

## Web Enumeration (`capo web`)

*All commands pull `{IP}` and `{DOMAIN}` from state automatically.*

| Command | Description | Parameters |
| :--- | :--- | :--- |
| `fuzz` | Directory fuzzing with `ffuf`. | `--host ip\|domain`, `-d` (domain), `--ext php,txt`, `-w` (wordlist) |
| `vhost` | Virtual host discovery. | `-d` (base domain), `-w` (wordlist) |
| `subdns` | DNS subdomain enumeration. | `-d` (base domain), `-w` (wordlist), `-r` (resolver) |
| `recursive` | Recursive directory scan. | `--depth 2` |

### If `.git` directory is found

```bash
# 1. Confirm exposure
curl -s http://{IP}/.git/HEAD           # Expect: ref: refs/heads/...
curl -s http://{IP}/.git/config         # Contains remote URL + branch

# 2. Dump the repository
git-dumper http://{IP}/.git/ ./git-dump
# Fallback:
wget --mirror -I .git http://{IP}/.git/ -P ./git-dump-wget

# 3. Review history
git -C ./git-dump log --oneline --all
git -C ./git-dump show {COMMIT_HASH}
git -C ./git-dump stash show -p

# 4. Hunt for secrets
grep -rEil 'password|secret|api.?key|token|private.?key' ./git-dump
trufflehog filesystem ./git-dump
gitleaks detect -s ./git-dump --no-git
```

> **Cheatsheet shortcut:** `capo query git-detect` / `capo query git-dump` / `capo query git-grep-secrets`

## NetExec / SMB (`capo nxc`)

Wrappers for NetExec (CrackMapExec). All results update shared state.

| Command | Description |
| :--- | :--- |
| `null` | Test for SMB Null Session. |
| `guest` | Test for SMB Guest Session. |
| `shares` | List SMB shares. (Uses creds from state if not provided) |
| `users` | Enumerate domain users via SMB/LDAP. |
| `pass-pol` | Get password policy. |
| `rid-brute` | RID Cycling to find users. |
| `ldap-enum` | LDAP enumeration (users, groups, trusts). |
| `spray` | Password spray a userlist. |
| `winrm` | Check for WinRM access. |

## Kerberos & Lateral Movement (`capo kerberos`)

Impacket wrappers for AD attacks and lateral movement. All support `--dry-run`.

| Command | Description | Example |
| :--- | :--- | :--- |
| `asrep-roast` | AS-REP roast accounts without pre-auth | `capo kerberos asrep-roast -f users.txt` |
| `kerberoast` | Request TGS tickets for SPN accounts | `capo kerberos kerberoast -u user -p pass` |
| `secretsdump` | Dump SAM/LSA/NTDS hashes remotely | `capo kerberos secretsdump -u admin -H <hash>` |
| `dcsync` | DCSync — replicate NTDS with replication rights | `capo kerberos dcsync -u admin -p pass --dump-user Administrator` |
| `psexec` | SYSTEM shell via psexec.py (SMB) | `capo kerberos psexec -u admin -H <hash>` |
| `wmiexec` | Semi-interactive shell via WMI (stealthier) | `capo kerberos wmiexec -u admin -p pass` |
| `smbclient` | Interactive SMB shell via smbclient.py | `capo kerberos smbclient -u user -p pass` |

```bash
# AS-REP roast with discovered users
capo kerberos asrep-roast --domain htb.local

# Kerberoast with creds
capo kerberos kerberoast -u svc_tgs -p 'GPPstillStandingStrong2k18' -d htb.local

# Pass-the-hash lateral movement
capo kerberos psexec -u Administrator -H aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
capo kerberos wmiexec -u Administrator -H <hash>

# DCSync attack
capo kerberos dcsync -u admin -p pass --dump-user krbtgt
```

## Bruteforce (`capo brute`)

Hydra wrappers for SSH and web authentication forms.

| Command | Description |
| :--- | :--- |
| `ssh` | SSH bruteforce/spray (`-u/-p` or `-U/-P`). |
| `http-post` | Bruteforce HTTP POST login forms. |
| `http-get` | Bruteforce HTTP GET login forms. |
| `web-form` | Generic Hydra web form module (supports custom modules). |

## State & Intelligence (`capo state`)

The "Brain" of the tool. Tracks everything found so far.

| Command | Description |
| :--- | :--- |
| `show` | Show full summary table of the target. (Includes Campaign if active) |
| `ports` | List open ports & services. |
| `creds` | List found credentials. |
| `users` | List found usernames. |
| `dirs` | List found web directories. |
| `history` | Show scan history (tool, command, timestamp, duration). |
| `workspace` | Show the workspace path for the current target. |
| `refresh-notes` | Regenerate `notes.md` from current state. |
| `sync-files` | Synthesize target + campaign data into `users.txt`/`passwords.txt` for `{USERFILE}` injection. |
| `export` | Export data to JSON/CSV/Markdown. |

## Methodologies (`capo methodology`)

Interactive checklists that auto-complete based on your findings.

| Command | Description |
| :--- | :--- |
| `list` | Show available workflows (e.g., `ad_kill_chain`, `web_app`). |
| `start` | Start a methodology for this target. |
| `status` | Show current methodology progress. |
| `next` | Show the next pending steps & commands. |
| `done` | Mark a step as manually complete. |
| `auto-check` | Check if any steps can be auto-completed based on new state data. |

```bash
capo methodology start ad_kill_chain
capo methodology next
capo methodology done recon
capo methodology auto-check
```

## Triggers (`capo triggers`)

Context-aware suggestion engine based on open ports and state.

| Command | Description |
| :--- | :--- |
| `list` | Show all built-in and custom port triggers. |
| `check` | Manually evaluate triggers for the current target's state. |
| `init` | Create a `~/.capo/custom_triggers.yaml` template. |

## Writeup Sync (`capo writeup`)

Ingest attack patterns from pentest writeups (Markdown) and auto-generate suggestion rules.

| Command | Description | Example |
| :--- | :--- | :--- |
| `add-source` | Register a folder of `.md` writeup files | `capo writeup add-source ~/writeups/htb` |
| `remove-source` | Unregister a writeup folder | `capo writeup remove-source ~/writeups/htb` |
| `list` | Show registered sources and sync status | `capo writeup list` |
| `sync` | Parse all sources, generate suggestion rules | `capo writeup sync` |
| `status` | Show parsed writeup counts and generated rules | `capo writeup status` |

```bash
# Point capo at your writeup collection
capo writeup add-source ~/Documents/Obsidian/CyberSecurity/Writeups

# Parse writeups and generate context-aware rules
capo writeup sync

# Check how many rules were generated
capo writeup status
```

## Exam Mode (`capo mode`)

| Command | Description |
| :--- | :--- |
| `set oscp` | Strict OSCP mode — disables LLM, enforces Metasploit (1 machine limit). |
| `set cpts` | CPTS mode — all features enabled including LLM (Phase 4). |
| `show` | Show current exam mode and active restrictions. |
| `use-msf` | Log a Metasploit usage for OSCP tracking. |

## Knowledge Base

| Command | Description |
| :--- | :--- |
| `capo search <term>` | Fuzzy search the cheatsheet database. |
| `capo query <service>` | Quick lookup for a specific service (e.g., `capo query kerberos`). |
| `capo categories` | List all available cheatsheet categories. |

```bash
capo search "asrep roasting" --copy   # Copy first result to clipboard
capo query smb
capo query git-dump
capo categories
```

## Capo Studio (Web UI)

```bash
# Launch the web UI on http://127.0.0.1:8000
capo studio
```

**Studio Views:**
- **Cheatsheets** — Browse and edit cheatsheet YAML files
- **Methodologies** — View and edit methodology workflows
- **Active Engagement** — Live target state, ports, creds, users
- **Knowledge Graph** — Interactive node/edge graph synced from state (drag to position, add manual nodes/edges)
- **Sessions** — Session management with command history, key steps, and findings (mirrors CLI `capo session`)
- **Suggestions** — Context-aware next steps based on current state + writeup rules

**Theme switching:** Dark / Dim / Light (bottom of sidebar)

## Reporting

| Command | Description |
| :--- | :--- |
| `generate` | Create a Markdown/HTML report from the state. (`--format html`) |
| `preview` | Preview the report in the terminal. |
| `timeline` | View the attack timeline. |

## REST API Quick Reference

The local API (`capo.api:app`) is available when Capo Studio is running.

**Core**

| Endpoint | Description |
| :--- | :--- |
| `GET /api/engagement/status` | Active target, campaign, and full state |
| `GET /api/state` | Current target/workspace/campaign context |
| `GET /api/suggestions` | Context-aware suggestions for current target |

**Cheatsheets & Methodologies**

| Endpoint | Description |
| :--- | :--- |
| `GET /api/cheatsheets` | List all cheatsheet filenames |
| `GET /api/cheatsheets/{file}` | Load a cheatsheet |
| `POST /api/cheatsheets/{file}` | Save edited cheatsheet |
| `GET /api/methodologies` | List all methodology filenames |
| `GET /api/methodologies/{file}` | Load a methodology |
| `POST /api/methodologies/{file}` | Save edited methodology |

**Triggers**

| Endpoint | Description |
| :--- | :--- |
| `GET /api/triggers/custom` | Return custom triggers |
| `POST /api/triggers/custom` | Save custom triggers |

**Sessions**

| Endpoint | Description |
| :--- | :--- |
| `GET /api/sessions` | List all sessions with stats |
| `POST /api/sessions` | Create + activate a new session |
| `GET /api/sessions/active` | Get active session with summary |
| `POST /api/sessions/{name}/activate` | Switch to a session |
| `GET /api/sessions/{name}` | Session detail + summary |
| `DELETE /api/sessions/{name}` | Delete session and all data |
| `GET /api/sessions/{name}/commands` | List commands (`?key_only&tool`) |
| `POST /api/sessions/{name}/commands` | Log a manual command |
| `PUT /api/sessions/commands/{id}/key` | Toggle key flag |
| `GET /api/sessions/{name}/findings` | List findings |
| `POST /api/sessions/{name}/findings` | Create a finding |
| `DELETE /api/sessions/findings/{id}` | Delete a finding |

**Knowledge Graph**

| Endpoint | Description |
| :--- | :--- |
| `GET /api/graph` | Full knowledge graph (auto-synced from state) |
| `POST /api/graph/nodes` | Create a manual node |
| `PUT /api/graph/nodes/{id}` | Update a node |
| `DELETE /api/graph/nodes/{id}` | Delete a manual node |
| `POST /api/graph/edges` | Create an edge |
| `PUT /api/graph/edges/{id}` | Update an edge |
| `DELETE /api/graph/edges/{id}` | Delete an edge |
| `POST /api/graph/positions` | Bulk update node positions |
| `POST /api/graph/clear` | Clear manual nodes/edges |
