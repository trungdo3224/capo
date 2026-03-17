"""Tests for web subdomain enumeration logic."""

from unittest.mock import MagicMock, patch


class TestWebSubdns:
    """Unit tests for subdns fuzzing behavior and parsing."""

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    @patch("capo.modules.wrappers.web_wrapper.shutil.which")
    def test_subdns_uses_gobuster_when_available(self, mock_which, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("www\nadmin\napi\n", encoding="utf-8")

        mock_which.return_value = "/usr/bin/gobuster"
        mock_state.target = "10.10.10.10"
        mock_state.get.return_value = "corp.local"

        web = WebFuzzWrapper()
        web._output_file = MagicMock(return_value=tmp_path / "subdns_test")
        web._subdns_gobuster = MagicMock()
        web._subdns_ffuf = MagicMock()

        web.subdns_fuzz(domain="corp.local", wordlist=str(wordlist), target="10.10.10.10")

        web._subdns_gobuster.assert_called_once()
        web._subdns_ffuf.assert_not_called()

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    @patch("capo.modules.wrappers.web_wrapper.shutil.which")
    def test_subdns_falls_back_to_ffuf(self, mock_which, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        wordlist = tmp_path / "subs.txt"
        wordlist.write_text("www\nadmin\napi\n", encoding="utf-8")

        mock_which.return_value = None
        mock_state.target = "10.10.10.10"
        mock_state.get.return_value = "corp.local"

        web = WebFuzzWrapper()
        web._output_file = MagicMock(return_value=tmp_path / "subdns_test")
        web._subdns_gobuster = MagicMock()
        web._subdns_ffuf = MagicMock()

        web.subdns_fuzz(domain="corp.local", wordlist=str(wordlist), target="10.10.10.10")

        web._subdns_ffuf.assert_called_once()
        web._subdns_gobuster.assert_not_called()

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_parse_gobuster_dns_adds_vhosts(self, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        out = tmp_path / "gobuster.txt"
        out.write_text(
            "Found: admin.corp.local\n"
            "Found: api.corp.local\n"
            "Found: api.corp.local\n",  # duplicate
            encoding="utf-8",
        )
        mock_state.get.return_value = "10.10.10.10"
        mock_state.target = "10.10.10.10"

        web = WebFuzzWrapper()
        web._parse_gobuster_dns(out, "corp.local")

        added = [c.args[0] for c in mock_state.add_vhost.call_args_list]
        assert "admin.corp.local" in added
        assert "api.corp.local" in added
        assert added.count("api.corp.local") == 1

    @patch("capo.modules.wrappers.web_wrapper.state_manager")
    def test_parse_output_subdns_mode_adds_fqdns(self, mock_state, tmp_path):
        from capo.modules.wrappers.web_wrapper import WebFuzzWrapper

        txt_out = tmp_path / "ffuf_subdns.txt"
        txt_out.write_text("", encoding="utf-8")
        json_out = txt_out.with_suffix(".json")
        json_out.write_text(
            """{
  \"results\": [
    {\"input\": {\"FUZZ\": \"admin\"}, \"status\": 200},
    {\"input\": {\"FUZZ\": \"api.corp.local\"}, \"status\": 200}
  ]
}""",
            encoding="utf-8",
        )

        web = WebFuzzWrapper()
        web._parse_mode = "subdns"
        web._subdns_domain = "corp.local"

        result = MagicMock(stdout="", returncode=0)
        web.parse_output(result, txt_out)

        added = [c.args[0] for c in mock_state.add_vhost.call_args_list]
        assert "admin.corp.local" in added
        assert "api.corp.local" in added
