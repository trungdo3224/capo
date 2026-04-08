"""Tests for the enumerate engine and output parsers."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from capo.modules.enumerate import (
    EnumerateEngine,
    _parse_enum4linux_ng,
    _parse_ffuf_json,
    _parse_http_headers,
    _parse_ldapsearch_base,
    _parse_nxc_rid,
    _parse_nxc_shares,
    _parse_nxc_users,
    _parse_onesixtyone,
    _parse_rpcclient_enum,
    _parse_searchsploit,
    _parse_showmount,
    _parse_smbclient_list,
    _parse_snmpwalk,
    _parse_whatweb,
)


# ─── Parser unit tests ───


class TestNxcSharesParser:
    def test_extracts_shares(self):
        stdout = (
            "SMB  10.10.10.100  445  DC01  [*]  ADMIN$  READ  Remote Admin\n"
            "SMB  10.10.10.100  445  DC01  [*]  C$  READ  Default share\n"
            "SMB  10.10.10.100  445  DC01  [*]  backup  READ,WRITE  Backups\n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_nxc_shares(stdout, "")
        assert "share(s)" in result["summary"]


class TestNxcRidParser:
    def test_extracts_users(self):
        stdout = (
            "SMB  10.10.10.100  445  DC  500: CORP\\Administrator (SidTypeUser: \\Administrator)\n"
            "SMB  10.10.10.100  445  DC  501: CORP\\Guest (SidTypeUser: \\Guest)\n"
            "SMB  10.10.10.100  445  DC  1001: CORP\\svc-alfresco (SidTypeUser: \\svc-alfresco)\n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_nxc_rid(stdout, "")
        assert "3 user(s)" in result["summary"]
        assert "Administrator" in result["users"]
        assert "svc-alfresco" in result["users"]


class TestEnum4linuxNgParser:
    def test_extracts_users_shares_domain(self):
        stdout = (
            "  username: administrator\n"
            "  username: svc-print\n"
            "Domain Name: CORP\n"
            "  IPC$    Mapping: OK\n"
            "  backup  Mapping: OK\n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_enum4linux_ng(stdout, "")
        assert "2 user(s)" in result["summary"]
        assert "2 share(s)" in result["summary"]
        assert "domain: CORP" in result["summary"]


class TestSmbclientListParser:
    def test_extracts_shares(self):
        stdout = (
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tADMIN$          Disk      Remote Admin\n"
            "\tC$              Disk      Default share\n"
            "\tIPC$            IPC       IPC Service\n"
            "\tbackup          Disk      \n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_smbclient_list(stdout, "")
        assert "4 share(s)" in result["summary"]
        assert "ADMIN$" in result["shares"]


class TestShowmountParser:
    def test_extracts_exports(self):
        stdout = (
            "Export list for 10.10.10.100:\n"
            "/backup  (everyone)\n"
            "/home    192.168.1.0/24\n"
        )
        result = _parse_showmount(stdout, "")
        assert "2 export(s)" in result["summary"]
        assert "/backup" in result["summary"]

    def test_no_exports(self):
        result = _parse_showmount("Export list for 10.10.10.100:\n", "")
        assert "no exports" in result["summary"]


class TestWhatwebParser:
    def test_extracts_techs(self):
        stdout = "http://10.10.10.100 [200 OK] Apache[2.4.49], PHP[7.4.3], WordPress[5.8], Title[Blog]"
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_whatweb(stdout, "")
        assert "Apache" in result["summary"]

    def test_feeds_versioned_software_to_state(self):
        stdout = "http://10.10.10.100 [200 OK] Apache[2.4.49], PHP[7.4.3], WordPress[5.8]"
        mock_sm = MagicMock()
        with patch("capo.modules.enumerate.state_manager", mock_sm):
            result = _parse_whatweb(stdout, "")
        # Should have called add_software for versioned entries
        # source is a keyword arg, so check args + kwargs separately
        calls = [(c.args[0], c.args[1]) for c in mock_sm.add_software.call_args_list]
        assert ("Apache", "2.4.49") in calls
        assert ("PHP", "7.4.3") in calls
        assert ("WordPress", "5.8") in calls
        # All calls should pass source="whatweb"
        for c in mock_sm.add_software.call_args_list:
            assert c.kwargs.get("source") == "whatweb"


class TestHttpHeadersParser:
    def test_extracts_server_and_powered_by(self):
        stdout = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache/2.4.49\r\n"
            "X-Powered-By: PHP/7.4.3\r\n"
            "Content-Type: text/html\r\n"
        )
        result = _parse_http_headers(stdout, "")
        assert "Apache/2.4.49" in result["summary"]
        assert "PHP/7.4.3" in result["summary"]

    def test_no_server_header(self):
        result = _parse_http_headers("HTTP/1.1 200 OK\r\n", "")
        assert "no info" in result["summary"]


class TestFfufJsonParser:
    def test_parses_json_results(self):
        data = {
            "results": [
                {"input": {"FUZZ": "admin"}, "status": 200},
                {"input": {"FUZZ": "login"}, "status": 301},
            ]
        }
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_ffuf_json(json.dumps(data), "")
        assert "2 dir(s)" in result["summary"]

    def test_invalid_json(self):
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_ffuf_json("not json", "")
        assert "no dirs" in result["summary"]


class TestLdapsearchBaseParser:
    def test_extracts_naming_contexts(self):
        stdout = (
            "dn:\n"
            "namingContexts: DC=corp,DC=local\n"
            "namingContexts: CN=Configuration,DC=corp,DC=local\n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_ldapsearch_base(stdout, "")
        assert "DC=corp,DC=local" in result["summary"]


class TestRpcclientEnumParser:
    def test_extracts_users(self):
        stdout = (
            "user:[Administrator] rid:[0x1f4]\n"
            "user:[Guest] rid:[0x1f5]\n"
            "user:[krbtgt] rid:[0x1f6]\n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_rpcclient_enum(stdout, "")
        assert "3 user(s)" in result["summary"]
        assert "Administrator" in result["users"]


class TestOnesixtyone:
    def test_finds_communities(self):
        stdout = "10.10.10.100 [public] Linux server 5.4.0\n10.10.10.100 [private] Linux\n"
        result = _parse_onesixtyone(stdout, "")
        assert "public" in result["summary"]
        assert "private" in result["summary"]


class TestSearchsploit:
    def test_parses_results(self):
        stdout = (
            "---------------------------------------------------\n"
            " Exploit Title                            |  Path\n"
            "---------------------------------------------------\n"
            " Apache 2.4.49 - Path Traversal           | exploits/linux/remote/50383.sh\n"
            " Apache 2.4.50 - RCE                      | exploits/linux/remote/50406.py\n"
            "---------------------------------------------------\n"
        )
        result = _parse_searchsploit(stdout, "")
        assert "2 exploit(s)" in result["summary"]

    def test_no_results(self):
        stdout = "Exploits: No Results\nShellcodes: No Results\n"
        result = _parse_searchsploit(stdout, "")
        assert "no exploits" in result["summary"]


class TestSnmpwalkParser:
    def test_counts_oids(self):
        stdout = "\n".join([f"iso.3.6.1.2.1.1.{i} = STRING: value{i}" for i in range(5)])
        result = _parse_snmpwalk(stdout, "")
        assert "5 OID(s)" in result["summary"]


class TestNxcUsersParser:
    def test_extracts_users(self):
        stdout = (
            "SMB  10.10.10.100  445  DC  Administrator  badpwdcount: 0\n"
            "SMB  10.10.10.100  445  DC  svc-print  badpwdcount: 0\n"
        )
        with patch("capo.modules.enumerate.state_manager"):
            result = _parse_nxc_users(stdout, "")
        assert "2 user(s)" in result["summary"]


# ─── Engine tests ───


@pytest.fixture
def capo_home(tmp_path):
    home = tmp_path / ".capo"
    home.mkdir()
    (home / "workspaces").mkdir()
    return home


@pytest.fixture
def engine_with_state(capo_home):
    """Provide an EnumerateEngine with a fresh patched state and target set."""
    with patch("capo.config.CAPO_HOME", capo_home), \
         patch("capo.config.WORKSPACES_DIR", capo_home / "workspaces"):
        from capo.state import StateManager
        mgr = StateManager()
        mgr.set_target("10.10.10.100")
        # Add some open ports to state
        mgr.add_port(22, "tcp", "ssh", "OpenSSH 8.2", "open")
        mgr.add_port(80, "tcp", "http", "Apache 2.4.49", "open")
        mgr.add_port(445, "tcp", "microsoft-ds", "Windows Server", "open")
        mgr.add_port(161, "udp", "snmp", "", "open")

        with patch("capo.modules.enumerate.state_manager", mgr):
            engine = EnumerateEngine()
            yield engine, mgr


class TestEnumerateEngine:
    def test_resolve_services_all(self, engine_with_state):
        engine, mgr = engine_with_state
        matched = engine._resolve_services(None)
        service_names = [s[0] for s in matched]
        assert "smb" in service_names
        assert "http" in service_names
        assert "ssh" in service_names
        assert "snmp" in service_names

    def test_resolve_services_by_name(self, engine_with_state):
        engine, mgr = engine_with_state
        matched = engine._resolve_services(["smb"])
        assert len(matched) == 1
        assert matched[0][0] == "smb"
        assert matched[0][1] == 445

    def test_resolve_services_by_port(self, engine_with_state):
        engine, mgr = engine_with_state
        matched = engine._resolve_services(["80"])
        assert len(matched) == 1
        assert matched[0][0] == "http"

    def test_resolve_unknown_service(self, engine_with_state, capsys):
        engine, mgr = engine_with_state
        matched = engine._resolve_services(["nonexistent"])
        assert matched == []

    def test_resolve_port_not_open(self, engine_with_state, capsys):
        engine, mgr = engine_with_state
        matched = engine._resolve_services(["3389"])
        assert matched == []

    def test_inject_variables(self, engine_with_state):
        engine, mgr = engine_with_state
        cmd = engine._inject(
            "nxc smb {IP} -u {USER} -p {PASS} --shares",
            port=445,
            output_dir=Path("/tmp/out"),
            username="admin",
            password="pass123",
        )
        assert "10.10.10.100" in cmd
        assert "admin" in cmd
        assert "pass123" in cmd

    def test_run_cmd_skips_missing_tool(self, engine_with_state):
        engine, mgr = engine_with_state
        with patch("capo.modules.enumerate.shutil.which", return_value=None):
            cr = engine._run_cmd(
                name="test", tool="nonexistent_tool",
                cmd_template="nonexistent_tool {IP}",
                port=80, output_dir=Path("/tmp"),
                timeout=10, parser_name=None,
            )
        assert cr.status == "skipped"
        assert "not installed" in cr.findings

    def test_dc_detection_prioritizes_ad(self, capo_home):
        """When DC ports (88+389+445) are open, AD services run first."""
        with patch("capo.config.CAPO_HOME", capo_home), \
             patch("capo.config.WORKSPACES_DIR", capo_home / "workspaces"):
            from capo.state import StateManager
            mgr = StateManager()
            mgr.set_target("10.10.10.100")
            # DC-like port profile
            mgr.add_port(88, "tcp", "kerberos", "", "open")
            mgr.add_port(389, "tcp", "ldap", "", "open")
            mgr.add_port(445, "tcp", "microsoft-ds", "", "open")
            mgr.add_port(135, "tcp", "msrpc", "", "open")
            mgr.add_port(80, "tcp", "http", "IIS", "open")
            mgr.add_port(53, "udp", "dns", "", "open")

            with patch("capo.modules.enumerate.state_manager", mgr):
                engine = EnumerateEngine()
                matched = engine._resolve_services(None)
        svc_order = [s[0] for s in matched]
        # AD services should come before http
        assert svc_order.index("kerberos") < svc_order.index("http")
        assert svc_order.index("ldap") < svc_order.index("http")
        assert svc_order.index("smb") < svc_order.index("http")

    def test_no_ad_priority_without_kerberos(self, engine_with_state):
        """Normal machines (no kerberos) should NOT trigger AD reordering."""
        engine, mgr = engine_with_state
        matched = engine._resolve_services(None)
        # ssh comes before smb in YAML order — should stay that way
        svc_order = [s[0] for s in matched]
        assert svc_order.index("ssh") < svc_order.index("smb")

    def test_add_software_to_state(self, engine_with_state):
        engine, mgr = engine_with_state
        mgr.add_software("WordPress", "5.8", source="whatweb")
        mgr.add_software("Apache", "2.4.49", source="whatweb")
        # Dedup: same name+version should not duplicate
        mgr.add_software("WordPress", "5.8", source="page_scrape")
        sw = mgr.get("software", [])
        assert len(sw) == 2
        names = [s["name"] for s in sw]
        assert "WordPress" in names
        assert "Apache" in names

    def test_searchsploit_queries_software(self, engine_with_state):
        engine, mgr = engine_with_state
        # Add software to state (as whatweb/scrape would)
        mgr.add_software("WordPress", "5.8", source="whatweb")
        mgr.add_software("Drupal", "9.3.0", source="page_scrape")
        matched = [("http", 80, {})]
        with patch("capo.modules.enumerate.shutil.which", return_value="/usr/bin/searchsploit"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Exploits: No Results\nShellcodes: No Results\n",
                stderr="", returncode=0,
            )
            results = engine._run_searchsploit(Path("/tmp"), matched)
        # Should have queried for both port service+version AND software
        queried = {r.name.split(": ", 1)[1] for r in results}
        assert "WordPress 5.8" in queried
        assert "Drupal 9.3.0" in queried
        assert "http Apache 2.4.49" in queried  # from port data


# ─── Quiet mode tests ───


class TestQuietMode:
    def test_output_config_defaults_false(self):
        from capo.config import OutputConfig
        with patch("capo.config.CONFIG_FILE", Path("/nonexistent/config.json")):
            cfg = OutputConfig()
        assert cfg.quiet is False

    def test_output_config_loads_from_json(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text('{"quiet": true}')
        with patch("capo.config.CONFIG_FILE", cfg_file):
            from capo.config import OutputConfig
            cfg = OutputConfig()
        assert cfg.quiet is True

    def test_output_config_saves(self, tmp_path):
        cfg_file = tmp_path / "config.json"
        with patch("capo.config.CONFIG_FILE", cfg_file):
            from capo.config import OutputConfig
            cfg = OutputConfig()
            cfg.quiet = True
            cfg.save()

        import json
        data = json.loads(cfg_file.read_text())
        assert data["quiet"] is True

    def test_print_suggestion_suppressed(self, capsys):
        from capo.config import output_config
        from capo.utils.display import print_suggestion
        original = output_config.quiet
        try:
            output_config.quiet = True
            print_suggestion("test", ["cmd1"])
        finally:
            output_config.quiet = original
        captured = capsys.readouterr()
        assert "test" not in captured.out

    def test_print_success_suppressed(self, capsys):
        from capo.config import output_config
        from capo.utils.display import print_success
        original = output_config.quiet
        try:
            output_config.quiet = True
            print_success("done")
        finally:
            output_config.quiet = original
        captured = capsys.readouterr()
        assert "done" not in captured.out
