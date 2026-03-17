# C.A.P.O Cheatsheet (Context-Aware Pentest Orchestrator)

## Workflow Basics

**1. Start a New Engagement**
```bash
# (Optional) Link targets to an Active Campaign for centralized AD data
capo target campaign my-ad-lab

# Set target IP (creates workspace & state)
capo target set 10.10.10.10

# (Optional) Set domain info if known
capo target set-domain example.com --dc-ip 10.10.10.10
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
```

---

## Target Management (`capo target`)

| Command | Description | Example |
| :--- | :--- | :--- |
| `campaign` | Set Active Campaign context | `capo target campaign my-lab` |
| `set` | Set target IP & init workspace | `capo target set 10.129.2.5` |
| `set-domain` | Set AD domain context | `capo target set-domain flight.htb` |
| `set-lhost` | Set your IP/Port for reverse shells | `capo target set-lhost 10.10.14.5 -p 443` |
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

```bash
capo scan quick --profile aggressive   # Lab/CTF speed
capo scan quick --profile stealth      # Fragile targets
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

## Daemon

```bash
# Start background watcher — polls state.json every 2s, fires suggestion tables on change
capo daemon
```

## Capo Studio (Web UI)

```bash
# Launch the web UI on http://127.0.0.1:8000
capo studio
```

## Reporting

| Command | Description |
| :--- | :--- |
| `generate` | Create a Markdown/HTML report from the state. |
| `timeline` | View the attack timeline. |

## REST API Quick Reference

The local API (`capo.api:app`) is available when the Capo daemon or Studio is running.

| Endpoint | Description |
| :--- | :--- |
| `GET /api/engagement/status` | Active target, campaign, and full state |
| `GET /api/state` | Current target/workspace/campaign context |
| `GET /api/suggestions` | Context-aware suggestions for current target |
| `GET /api/cheatsheets` | List all cheatsheet filenames |
| `GET /api/methodologies` | List all methodology filenames |
| `GET /api/triggers/custom` | Return custom triggers |
| `POST /api/triggers/custom` | Save custom triggers |
