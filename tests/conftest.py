"""Shared test fixtures for C.A.P.O tests."""

import json

import pytest

@pytest.fixture(autouse=True)
def clear_global_campaign(monkeypatch, tmp_path):
    """Ensure tests don't leak local active campaigns."""
    import capo.config
    # Explicitly clear any existing global campaign logic before each test
    from capo.campaign import campaign_manager
    original_active = campaign_manager._name
    campaign_manager.clear_campaign()
    
    yield
    
    if original_active:
        campaign_manager.set_campaign(original_active)
    else:
        campaign_manager.clear_campaign()


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a temporary workspace with standard OSCP directory structure."""
    ws = tmp_path / "10.10.10.100"
    for d in ("scans", "loot", "exploits", "evidence"):
        (ws / d).mkdir(parents=True)
    return ws


@pytest.fixture
def sample_state():
    """Return a realistic state dict based on HTB Forest field test."""
    return {
        "target": "10.129.95.210",
        "ip": "10.129.95.210",
        "domain": "htb.local",
        "os": "Windows Server 2016 Standard 14393",
        "hostname": "FOREST",
        "ports": [
            {"port": 53, "protocol": "tcp", "service": "domain", "version": "Simple DNS Plus", "state": "open"},
            {"port": 88, "protocol": "tcp", "service": "kerberos-sec", "version": "Microsoft Windows Kerberos", "state": "open"},
            {"port": 135, "protocol": "tcp", "service": "msrpc", "version": "Microsoft Windows RPC", "state": "open"},
            {"port": 139, "protocol": "tcp", "service": "netbios-ssn", "version": "Microsoft Windows netbios-ssn", "state": "open"},
            {"port": 389, "protocol": "tcp", "service": "ldap", "version": "Microsoft Windows Active Directory LDAP", "state": "open"},
            {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "Windows Server 2016 Standard 14393 microsoft-ds", "state": "open"},
            {"port": 464, "protocol": "tcp", "service": "kpasswd5", "version": "", "state": "open"},
            {"port": 593, "protocol": "tcp", "service": "ncacn_http", "version": "Microsoft Windows RPC over HTTP 1.0", "state": "open"},
            {"port": 636, "protocol": "tcp", "service": "ssl/ldap", "version": "", "state": "open"},
            {"port": 3268, "protocol": "tcp", "service": "ldap", "version": "Microsoft Windows Active Directory LDAP", "state": "open"},
            {"port": 3269, "protocol": "tcp", "service": "ssl/ldap", "version": "", "state": "open"},
            {"port": 5985, "protocol": "tcp", "service": "http", "version": "Microsoft HTTPAPI httpd 2.0", "state": "open"},
            {"port": 9389, "protocol": "tcp", "service": "mc-nmf", "version": ".NET Message Framing", "state": "open"},
            {"port": 47001, "protocol": "tcp", "service": "http", "version": "Microsoft HTTPAPI httpd 2.0", "state": "open"},
            {"port": 49667, "protocol": "tcp", "service": "msrpc", "version": "Microsoft Windows RPC", "state": "open"},
            {"port": 49685, "protocol": "tcp", "service": "msrpc", "version": "Microsoft Windows RPC", "state": "open"},
        ],
        "services": {
            "53/tcp": {"service": "domain", "version": "Simple DNS Plus"},
            "88/tcp": {"service": "kerberos-sec", "version": "Microsoft Windows Kerberos"},
            "445/tcp": {"service": "microsoft-ds", "version": "Windows Server 2016"},
        },
        "users": [
            "Administrator", "Guest", "svc-alfresco", "sebastien",
            "lucinda", "andy", "mark", "santi",
        ],
        "hashes": [
            {"hash": "$krb5asrep$23$svc-alfresco@HTB.LOCAL:abc123", "username": "svc-alfresco"},
        ],
        "credentials": [],
        "directories": [],
        "vhosts": [],
        "shares": [],
        "domain_info": {
            "domain_name": "htb.local",
            "dc_ip": "10.129.95.210",
            "dns_name": "",
        },
        "notes": [
            {"note": "AS-REP Roasting: svc-alfresco has UF_DONT_REQUIRE_PREAUTH set.", "timestamp": "2026-03-12T04:20:00+00:00"},
        ],
        "flags": {"local_txt": "", "proof_txt": ""},
        "scan_history": [
            {"tool": "nmap", "command": "nmap -Pn -p- --min-rate 5000 -T4 10.129.95.210", "output_file": "scans/nmap_quick.xml", "timestamp": "2026-03-12T04:00:50+00:00"},
            {"tool": "nmap", "command": "nmap -Pn -sC -sV -p 53,88,135,139,445 10.129.95.210", "output_file": "scans/nmap_detailed.xml", "timestamp": "2026-03-12T04:02:50+00:00"},
            {"tool": "netexec", "command": "nxc ldap 10.129.95.210 -u '' -p '' --users", "output_file": "scans/nxc_ldap.txt", "timestamp": "2026-03-12T04:16:15+00:00"},
        ],
        "created_at": "2026-03-12T03:58:00+00:00",
        "updated_at": "2026-03-12T04:20:00+00:00",
    }


@pytest.fixture
def state_file(tmp_workspace, sample_state):
    """Write a sample state.json into tmp_workspace and return its path."""
    sf = tmp_workspace / "state.json"
    sf.write_text(json.dumps(sample_state, indent=2), encoding="utf-8")
    return sf


# --- Sample tool outputs for parser tests ---

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -sC -sV -p 53,88,135,445 10.129.95.210" start="1741752170">
<host starttime="1741752170" endtime="1741752290">
<status state="up" reason="user-set"/>
<address addr="10.129.95.210" addrtype="ipv4"/>
<hostnames/>
<ports>
<port protocol="tcp" portid="53">
<state state="open" reason="syn-ack"/>
<service name="domain" product="Simple DNS Plus" ostype="Windows" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="88">
<state state="open" reason="syn-ack"/>
<service name="kerberos-sec" product="Microsoft Windows Kerberos" ostype="Windows" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="135">
<state state="open" reason="syn-ack"/>
<service name="msrpc" product="Microsoft Windows RPC" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack"/>
<service name="microsoft-ds" product="Windows Server 2016 Standard 14393 microsoft-ds" method="probed" conf="10"/>
</port>
</ports>
<os>
<osmatch name="Microsoft Windows Server 2016" accuracy="96">
<osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="2016"/>
</osmatch>
</os>
</host>
</nmaprun>"""

SAMPLE_NXC_LDAP_OUTPUT = """SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None)
LDAP        10.129.95.210   389    FOREST           [+] htb.local\\:
LDAP        10.129.95.210   389    FOREST           [*] Enumerated 4 domain users: htb.local
LDAP        10.129.95.210   389    FOREST           -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.95.210   389    FOREST           Administrator                 2021-08-31 07:51:58 0        Built-in account
LDAP        10.129.95.210   389    FOREST           svc-alfresco                  2026-03-12 11:22:56 0
LDAP        10.129.95.210   389    FOREST           sebastien                     2019-09-20 07:29:59 0
LDAP        10.129.95.210   389    FOREST           lucinda                       2019-09-20 07:44:13 0"""

SAMPLE_NXC_SHARES_OUTPUT = """SMB         10.10.10.100    445    DC01             [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC01             [+] corp.local\\guest:
SMB         10.10.10.100    445    DC01             ADMIN$          NO ACCESS       Remote Admin
SMB         10.10.10.100    445    DC01             C$              NO ACCESS       Default share
SMB         10.10.10.100    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.100    445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.10.100    445    DC01             SYSVOL          READ            Logon server share"""

SAMPLE_NXC_RID_OUTPUT = """SMB         10.10.10.100    445    DC01             [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC01             [+] corp.local\\:
SMB         10.10.10.100    445    DC01             498: CORP\\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.100    445    DC01             500: CORP\\Administrator (SidTypeUser)
SMB         10.10.10.100    445    DC01             501: CORP\\Guest (SidTypeUser)
SMB         10.10.10.100    445    DC01             1103: CORP\\bob (SidTypeUser)
SMB         10.10.10.100    445    DC01             1104: CORP\\alice (SidTypeUser)
SMB         10.10.10.100    445    DC01             513: CORP\\Domain Users (SidTypeGroup)"""

SAMPLE_NXC_NULL_OUTPUT = """SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB         10.129.95.210   445    FOREST           [+] htb.local\\:
SMB         10.129.95.210   445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED"""

SAMPLE_FFUF_JSON = """{
  "commandline": "ffuf -u http://10.10.10.100/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -fc 404 -o /tmp/ffuf.json -of json",
  "results": [
    {"input": {"FUZZ": "admin"}, "status": 200, "length": 1234, "url": "http://10.10.10.100/admin"},
    {"input": {"FUZZ": "login"}, "status": 302, "length": 0, "url": "http://10.10.10.100/login"},
    {"input": {"FUZZ": "uploads"}, "status": 403, "length": 287, "url": "http://10.10.10.100/uploads"},
    {"input": {"FUZZ": ".git"}, "status": 200, "length": 456, "url": "http://10.10.10.100/.git"}
  ]
}"""
