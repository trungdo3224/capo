"""Tests for tool output parsers — Nmap XML, NetExec regex, ffuf JSON."""

from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import (
    SAMPLE_FFUF_JSON,
    SAMPLE_NMAP_XML,
    SAMPLE_NXC_LDAP_OUTPUT,
    SAMPLE_NXC_NULL_OUTPUT,
    SAMPLE_NXC_RID_OUTPUT,
    SAMPLE_NXC_SHARES_OUTPUT,
)

# ────────────── Nmap XML Parser ──────────────

class TestNmapParser:
    """Tests for nmap_wrapper._parse_xml() and parse_output()."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_workspace):
        self.ws = tmp_workspace
        self.xml_file = self.ws / "scans" / "nmap_test.xml"
        self.xml_file.write_text(SAMPLE_NMAP_XML, encoding="utf-8")
        # parse_output looks for .xml sibling of the given output_file
        self.txt_file = self.ws / "scans" / "nmap_test.txt"
        self.txt_file.write_text("", encoding="utf-8")

    @patch("capo.modules.wrappers.nmap_wrapper.state_manager")
    def test_parses_open_ports(self, mock_state):
        from capo.modules.wrappers.nmap_wrapper import NmapWrapper

        mock_state.target = "10.129.95.210"
        mock_state.workspace = self.ws
        mock_state.get.return_value = []

        nmap = NmapWrapper()
        result = MagicMock(stdout="", returncode=0)
        nmap.parse_output(result, self.txt_file)

        assert mock_state.add_port.call_count == 4

    @patch("capo.modules.wrappers.nmap_wrapper.state_manager")
    def test_parses_service_names(self, mock_state):
        from capo.modules.wrappers.nmap_wrapper import NmapWrapper

        mock_state.target = "10.129.95.210"
        mock_state.workspace = self.ws
        mock_state.get.return_value = []

        nmap = NmapWrapper()
        result = MagicMock(stdout="", returncode=0)
        nmap.parse_output(result, self.txt_file)

        # add_port(portid, protocol, service_name, version, port_state) — all positional
        ports_added = {c.args[0] for c in mock_state.add_port.call_args_list}
        assert 53 in ports_added
        assert 88 in ports_added
        assert 445 in ports_added

    @patch("capo.modules.wrappers.nmap_wrapper.state_manager")
    def test_parses_os_detection(self, mock_state):
        from capo.modules.wrappers.nmap_wrapper import NmapWrapper

        mock_state.target = "10.129.95.210"
        mock_state.workspace = self.ws
        mock_state.get.return_value = []

        nmap = NmapWrapper()
        result = MagicMock(stdout="", returncode=0)
        nmap.parse_output(result, self.txt_file)

        mock_state.set.assert_any_call("os", "Microsoft Windows Server 2016")

    @patch("capo.modules.wrappers.nmap_wrapper.state_manager")
    def test_handles_missing_xml(self, mock_state):
        from capo.modules.wrappers.nmap_wrapper import NmapWrapper

        mock_state.target = "10.129.95.210"
        mock_state.workspace = self.ws
        mock_state.get.return_value = []

        nmap = NmapWrapper()
        result = MagicMock(stdout="", returncode=0)
        missing = self.ws / "scans" / "nonexistent.txt"
        nmap.parse_output(result, missing)  # should not raise

    @patch("capo.modules.wrappers.nmap_wrapper.state_manager")
    def test_handles_empty_xml(self, mock_state):
        from capo.modules.wrappers.nmap_wrapper import NmapWrapper

        mock_state.target = "10.129.95.210"
        mock_state.workspace = self.ws
        mock_state.get.return_value = []

        empty_xml = self.ws / "scans" / "empty.xml"
        empty_xml.write_text("<?xml version='1.0'?><nmaprun></nmaprun>", encoding="utf-8")
        empty_txt = self.ws / "scans" / "empty.txt"
        empty_txt.write_text("", encoding="utf-8")

        nmap = NmapWrapper()
        result = MagicMock(stdout="", returncode=0)
        nmap.parse_output(result, empty_txt)
        assert mock_state.add_port.call_count == 0


# ────────────── NetExec Parser ──────────────

class TestNxcParser:
    """Tests for nxc_wrapper.parse_output() with simulated SQLite queries."""

    @patch("capo.modules.wrappers.nxc_wrapper.state_manager")
    def test_parses_domain_and_hostname(self, mock_state):
        from capo.modules.wrappers.nxc_wrapper import NetExecWrapper

        mock_state.get_var.return_value = "10.129.95.210"
        mock_state.target = "10.129.95.210"
        mock_state.get.return_value = ""
        mock_state.state = {}

        nxc = NetExecWrapper()
        
        def mock_query(db_name, query, params=()):
            if "hosts" in query: return [{"id": 1, "hostname": "FOREST", "domain": "CORP.LOCAL", "os": "Windows Server"}]
            return []

        # Mock _query_nxc_db with side_effect
        with patch.object(nxc, "_query_nxc_db", side_effect=mock_query) as mock_query_spy:
            result = MagicMock(stdout="(Pwn3d!)", returncode=0)
            nxc.parse_output(result, None)

            mock_state.set.assert_any_call("hostname", "FOREST")
            mock_state.add_domain.assert_any_call("CORP.LOCAL")
            mock_state.set.assert_any_call("os", "Windows Server")

    @patch("capo.modules.wrappers.nxc_wrapper.state_manager")
    def test_parses_users_from_db(self, mock_state):
        from capo.modules.wrappers.nxc_wrapper import NetExecWrapper

        mock_state.get_var.return_value = "10.129.95.210"
        mock_state.target = "10.10.10.100"
        mock_state.get.return_value = ""
        mock_state.state = {}

        nxc = NetExecWrapper()
        
        def mock_query(db_name, query, params=()):
            if "hosts" in query: return [{"id": 1, "hostname": "FOO", "domain": "BAR", "os": ""}]
            if db_name == "smb" and "users" in query: return [{"username": "Administrator"}, {"username": "bob"}]
            if db_name == "ldap" and "users" in query: return [{"username": "alice"}]
            if "shares" in query: return []
            return []

        with patch.object(nxc, "_query_nxc_db", side_effect=mock_query):
            result = MagicMock(stdout="Output", returncode=0)
            nxc.parse_output(result, None)

            user_calls = [c.args[0] for c in mock_state.add_user.call_args_list]
            assert "Administrator" in user_calls
            assert "bob" in user_calls
            assert "alice" in user_calls

    @patch("capo.modules.wrappers.nxc_wrapper.state_manager")
    def test_parses_shares_from_db(self, mock_state):
        from capo.modules.wrappers.nxc_wrapper import NetExecWrapper

        mock_state.get_var.return_value = "10.129.95.210"
        mock_state.target = "10.10.10.100"
        mock_state.get.return_value = ""
        mock_state.state = {}

        nxc = NetExecWrapper()
        
        def mock_query(db_name, query, params=()):
            if "hosts" in query: return [{"id": 5, "hostname": "FOO", "domain": "BAR", "os": ""}]
            if "users" in query: return []
            if "shares" in query: 
                assert params[0] == 5 # Should pass the host ID
                return [{"name": "IPC$", "remark": "Remote IPC", "read": True, "write": False}]
            return []

        with patch.object(nxc, "_query_nxc_db", side_effect=mock_query):
            result = MagicMock(stdout="Output", returncode=0)
            nxc.parse_output(result, None)

            mock_state.add_share.assert_called_with("IPC$", "READ", "Remote IPC")

    @patch("capo.modules.wrappers.nxc_wrapper.state_manager")
    def test_handles_missing_stdout(self, mock_state):
        from capo.modules.wrappers.nxc_wrapper import NetExecWrapper

        mock_state.get_var.return_value = "10.129.95.210"

        nxc = NetExecWrapper()
        result = MagicMock(stdout="", returncode=0)
        nxc.parse_output(result, None)
        assert mock_state.add_user.call_count == 0


# ────────────── ffuf JSON Parser ──────────────

class TestFfufParser:
    """Tests for web_wrapper.parse_output() with ffuf JSON output."""

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_parses_directories(self, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        mock_state.target = "10.10.10.100"
        mock_state.get.return_value = ""

        web = WebFuzzWrapper()
        result = MagicMock(stdout=SAMPLE_FFUF_JSON, returncode=0)

        json_file = tmp_path / "ffuf_test.json"
        json_file.write_text(SAMPLE_FFUF_JSON, encoding="utf-8")
        web.parse_output(result, json_file)

        dir_calls = [c.args[0] for c in mock_state.add_directory.call_args_list]
        assert any("admin" in d for d in dir_calls)

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_parses_all_four_results(self, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        mock_state.target = "10.10.10.100"
        mock_state.get.return_value = ""

        web = WebFuzzWrapper()
        result = MagicMock(stdout=SAMPLE_FFUF_JSON, returncode=0)

        json_file = tmp_path / "ffuf_test.json"
        json_file.write_text(SAMPLE_FFUF_JSON, encoding="utf-8")
        web.parse_output(result, json_file)

        assert mock_state.add_directory.call_count == 4

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_handles_empty_ffuf_json(self, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        mock_state.target = "10.10.10.100"
        mock_state.get.return_value = ""

        web = WebFuzzWrapper()
        result = MagicMock(stdout='{"results": []}', returncode=0)

        json_file = tmp_path / "ffuf_empty.json"
        json_file.write_text('{"results": []}', encoding="utf-8")
        web.parse_output(result, json_file)

        assert mock_state.add_directory.call_count == 0
