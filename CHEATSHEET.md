# C.A.P.O Cheatsheet (Context-Aware Pentest Orchestrator)

## 🚀 Workflow Basics

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
```

---

## 🎯 Target Management (`capo target`)

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

## 🔍 Scanning (`capo scan`)

| Command | Description |
| :--- | :--- |
| `quick` | **Phase 1**: Quick syn scan of all 65535 TCP ports. Updates state with open ports. |
| `detailed` | **Phase 2**: Runs `nmap -sC -sV` only on ports found in the `quick` scan. |
| `full` | Runs `quick` -> `detailed` -> `triggers` in one go. |
| `udp` | Scans top UDP ports. |
| `vuln` | Runs safe NSE vulnerability scripts (OSCP-safe). |

## 🌐 Web Enumeration (`capo web`)

*Note: All commands pull `{IP}` and `{DOMAIN}` from state automatically.*

| Command | Description | Parameters |
| :--- | :--- | :--- |
| `fuzz` | Directory fuzzing with `ffuf`. | `--host ip\|domain`<br>`-d` (domain/subdomain host)<br>`--ext php,txt` (extensions)<br>`-w` (custom wordlist) |
| `vhost` | Virtual host discovery. | `-d` (base domain)<br>`-w` (custom wordlist) |
| `subdns` | DNS subdomain enumeration (`gobuster dns` with ffuf fallback). | `-d` (base domain)<br>`-w` (custom wordlist)<br>`-r` (custom resolver) |
| `recursive` | Recursive directory scan. | `--depth 2` |

### 🔓 If `.git` directory is found

When `capo suggest` / `capo web fuzz` output mentions an exposed `.git`, follow this runbook:

```bash
# 1. Confirm exposure
curl -s http://{IP}/.git/HEAD           # Expect: ref: refs/heads/...
curl -s http://{IP}/.git/config         # Contains remote URL + branch

# 2. Dump the repository
git-dumper http://{IP}/.git/ ./git-dump # Preferred (pip install git-dumper)
# Fallback if git-dumper unavailable:
wget --mirror -I .git http://{IP}/.git/ -P ./git-dump-wget

# 3. Review history
git -C ./git-dump log --oneline --all   # Browse all commits
git -C ./git-dump show {COMMIT_HASH}    # Inspect specific commit diff
git -C ./git-dump stash show -p         # Check stashed WIP changes

# 4. Hunt for secrets
grep -rEil 'password|secret|api.?key|token|private.?key' ./git-dump
trufflehog filesystem ./git-dump        # Automated scanner
# Alternative:
gitleaks detect -s ./git-dump --no-git
```

> **Cheatsheet shortcut:** `capo query git-detect` / `capo query git-dump` / `capo query git-grep-secrets`

## ⚔️ NetExec / SMB (`capo nxc`)

Wrappers for NetExec (CrackMapExec) that update the shared state.

| Command | Description |
| :--- | :--- |
| `null` | Test for SMB Null Session. |
| `guest` | Test for SMB Guest Session. |
| `shares` | List SMB shares. (Uses creds from triggers if not provided) |
| `users` | Enumerate domain users via SMB/LDAP. |
| `pass-pol` | Get password policy. |
| `rid-brute` | RID Cycling to find users. |
| `spray` | Password spray a userlist. |
| `winrm` | Check for WinRM access. |

## 🔐 Bruteforce (`capo brute`)

Hydra wrappers for SSH and web authentication forms.

| Command | Description |
| :--- | :--- |
| `ssh` | SSH bruteforce/spray (`-u/-p` or `-U/-P`). |
| `http-post` | Bruteforce HTTP POST login forms. |
| `http-get` | Bruteforce HTTP GET login forms. |
| `web-form` | Generic Hydra web form module (supports custom modules). |

## 🧠 State & Intelligence (`capo state`)

The "Brain" of the tool. Tracks everything found so far.

| Command | Description |
| :--- | :--- |
| `show` | Show full summary table of the target. (Includes Campaign if active) |
| `ports` | List open ports & services. |
| `creds` | List found credentials. |
| `users` | List found usernames. |
| `dirs` | List found web directories. |
| `sync-files` | **Crucial**: Synthesizes target & campaign data into global `users.txt`/`passwords.txt` files for `{USERFILE}` injection. |
| `export` | Export data to JSON/CSV/Markdown. |

## 📋 Methodologies (`capo methodology`)

Interactive checklists that auto-complete based on your findings.

| Command | Description |
| :--- | :--- |
| `list` | Show available workflows (e.g., `web-app`, `active-directory`). |
| `start` | Start a methodology for this target. |
| `next` | Show the next pending steps & commands. |
| `done` | Mark a step as manually complete. |
| `auto-check` | Check if any steps can be auto-completed based on new state data. |

## 📚 Knowledge Base

| Command | Description |
| :--- | :--- |
| `search` | Fuzzy search the cheatsheet database. |
| `query` | Quick lookup for a specific service (e.g., `capo query kerberos`). |

## 📄 Reporting

| Command | Description |
| :--- | :--- |
| `generate` | Create a markdown/HTML report from the state. |
| `timeline` | View the attack timeline. |
