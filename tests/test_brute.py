"""Tests for Hydra brute wrapper."""

from unittest.mock import MagicMock, patch

import pytest

from capo.errors import CapoError


class TestBruteWrapper:
    @patch("capo.modules.wrappers.brute_wrapper.state_manager")
    def test_ssh_single_credentials_command(self, mock_state):
        from capo.modules.wrappers.brute_wrapper import BruteWrapper

        mock_state.target = "10.10.10.10"

        brute = BruteWrapper()
        brute._output_file = MagicMock(return_value=MagicMock(with_suffix=lambda s: MagicMock()))
        brute.execute = MagicMock()

        brute.ssh(username="admin", password="Summer2024!", target="10.10.10.10", port=22, tasks=3)

        cmd = brute.execute.call_args.args[0]
        assert cmd[:5] == ["hydra", "-I", "-f", "-t", "3"]
        assert "-l" in cmd and "admin" in cmd
        assert "-p" in cmd and "Summer2024!" in cmd
        assert cmd[-1] == "ssh"

    @patch("capo.modules.wrappers.brute_wrapper.state_manager")
    def test_ssh_wordlists_command(self, mock_state):
        from capo.modules.wrappers.brute_wrapper import BruteWrapper

        mock_state.target = "10.10.10.10"

        brute = BruteWrapper()
        brute._output_file = MagicMock(return_value=MagicMock(with_suffix=lambda s: MagicMock()))
        brute.execute = MagicMock()

        brute.ssh(userlist="users.txt", passlist="pass.txt", target="10.10.10.10")

        cmd = brute.execute.call_args.args[0]
        assert "-L" in cmd and "users.txt" in cmd
        assert "-P" in cmd and "pass.txt" in cmd

    @patch("capo.modules.wrappers.brute_wrapper.state_manager")
    def test_http_post_https_module_selection(self, mock_state):
        from capo.modules.wrappers.brute_wrapper import BruteWrapper

        mock_state.target = "10.10.10.10"

        brute = BruteWrapper()
        brute.web_form = MagicMock()

        brute.http_post_form(
            form="/login:user=^USER^&pass=^PASS^:F=invalid",
            username="admin",
            password="x",
            https=True,
            target="10.10.10.10",
        )

        assert brute.web_form.call_args.kwargs["module"] == "https-post-form"

    @patch("capo.modules.wrappers.brute_wrapper.state_manager")
    def test_parse_output_extracts_credentials(self, mock_state):
        from capo.modules.wrappers.brute_wrapper import BruteWrapper

        output = (
            "[22][ssh] host: 10.10.10.10   login: root   password: toor\n"
            "[80][http-post-form] host: 10.10.10.10   login: admin   password: admin123\n"
        )
        result = MagicMock(stdout=output, returncode=0)

        brute = BruteWrapper()
        brute.parse_output(result, None)

        calls = [(c.args[0], c.args[1], c.args[2]) for c in mock_state.add_credential.call_args_list]
        assert ("root", "toor", "ssh") in calls
        assert ("admin", "admin123", "http-post-form") in calls

    @patch("capo.modules.wrappers.brute_wrapper.state_manager")
    def test_missing_auth_inputs_raises(self, mock_state):
        from capo.modules.wrappers.brute_wrapper import BruteWrapper

        mock_state.target = "10.10.10.10"
        brute = BruteWrapper()

        with pytest.raises(CapoError):
            brute.ssh(target="10.10.10.10")
