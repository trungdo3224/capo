"""Tests for the StateManager — persistence, validation, dedup, and helpers."""

import json
from unittest.mock import patch

import pytest

from capo.errors import TargetError


@pytest.fixture
def capo_home(tmp_path):
    """Override CAPO_HOME to use a temp directory."""
    home = tmp_path / ".capo"
    home.mkdir()
    (home / "workspaces").mkdir()
    return home


@pytest.fixture
def fresh_manager(capo_home):
    """Create a fresh StateManager with patched CAPO_HOME."""
    with patch("capo.config.CAPO_HOME", capo_home), \
         patch("capo.config.WORKSPACES_DIR", capo_home / "workspaces"):
        from capo.state import StateManager
        mgr = StateManager()
        yield mgr


class TestSetTarget:
    """Tests for target validation and workspace creation."""

    def test_valid_ipv4(self, fresh_manager):
        ws = fresh_manager.set_target("10.10.10.100")
        assert fresh_manager.target == "10.10.10.100"
        assert ws.exists()
        assert (ws / "scans").is_dir()
        assert (ws / "loot").is_dir()
        assert (ws / "evidence").is_dir()
        assert (ws / "notes.md").exists()

    def test_valid_hostname(self, fresh_manager):
        ws = fresh_manager.set_target("dc01.corp.local")
        assert fresh_manager.target == "dc01.corp.local"

    def test_invalid_target_raises(self, fresh_manager):
        with pytest.raises(TargetError, match="Invalid target format"):
            fresh_manager.set_target("not a valid target!!")

    def test_invalid_spaces_rejected(self, fresh_manager):
        with pytest.raises(TargetError):
            fresh_manager.set_target("10.10.10 .100")

    def test_empty_string_rejected(self, fresh_manager):
        with pytest.raises(TargetError):
            fresh_manager.set_target("")


class TestPortManagement:
    """Tests for add_port dedup and get_open_ports."""

    def test_add_port_and_retrieve(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_port(80, "tcp", "http", "Apache 2.4.41", "open")
        assert 80 in fresh_manager.get_open_ports()

    def test_add_port_dedup(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_port(80, "tcp", "http", "Apache 2.4.41", "open")
        fresh_manager.add_port(80, "tcp", "http", "Apache 2.4.50", "open")
        ports_80 = [p for p in fresh_manager.state["ports"] if p["port"] == 80]
        assert len(ports_80) == 1
        assert "2.4.50" in ports_80[0]["version"]

    def test_services_summary(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_port(22, "tcp", "ssh", "OpenSSH 8.2", "open")
        fresh_manager.add_port(80, "tcp", "http", "Apache", "open")
        summary = fresh_manager.get_services_summary()
        assert summary[22] == "ssh"
        assert summary[80] == "http"


class TestUserManagement:
    """Tests for add_user dedup and users.txt file generation."""

    def test_add_user_and_dedup(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_user("admin")
        fresh_manager.add_user("admin")
        fresh_manager.add_user("bob")
        assert fresh_manager.state["users"] == ["admin", "bob"]

    def test_add_user_writes_file(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_user("alice")
        users_file = fresh_manager.workspace / "loot" / "users.txt"
        assert users_file.exists()
        assert "alice" in users_file.read_text(encoding="utf-8")

    def test_empty_username_ignored(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_user("")
        assert fresh_manager.state["users"] == []


class TestGetVar:
    """Tests for variable injection via get_var."""

    def test_ip_variable(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        assert fresh_manager.get_var("IP") == "10.10.10.100"
        assert fresh_manager.get_var("RHOST") == "10.10.10.100"
        assert fresh_manager.get_var("TARGET") == "10.10.10.100"

    def test_domain_variable(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_domain("corp.local")
        assert fresh_manager.get_var("DOMAIN") == "corp.local"

    def test_user_variable_first(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_user("admin")
        fresh_manager.add_user("bob")
        assert fresh_manager.get_var("USER") == "admin"

    def test_unknown_var_returns_empty(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        assert fresh_manager.get_var("NONEXISTENT") == ""


class TestPersistence:
    """Tests for state persistence across loads."""

    def test_state_persists_to_json(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_port(443, "tcp", "https", "nginx", "open")
        fresh_manager.add_user("admin")

        # Read the state.json directly
        state_path = fresh_manager.workspace / "state.json"
        data = json.loads(state_path.read_text(encoding="utf-8"))
        assert data["target"] == "10.10.10.100"
        assert len(data["ports"]) == 1
        assert data["users"] == ["admin"]

    def test_export_state_returns_json(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        exported = fresh_manager.export_state()
        data = json.loads(exported)
        assert data["ip"] == "10.10.10.100"


class TestScanHistory:
    """Tests for scan history recording."""

    def test_add_scan_record(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_scan_record("nmap", "nmap -p- 10.10.10.100", "scans/quick.xml", 12.5)
        history = fresh_manager.state["scan_history"]
        assert len(history) == 1
        assert history[0]["tool"] == "nmap"
        assert history[0]["duration"] == 12.5

    def test_add_note(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_note("Found SQL injection in /login")
        assert len(fresh_manager.state["notes"]) == 1
        assert "SQL injection" in fresh_manager.state["notes"][0]["note"]


class TestHashesAndCreds:
    """Tests for hash and credential tracking."""

    def test_add_hash(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_hash("$krb5asrep$23$user@DOMAIN:abc", "user")
        assert len(fresh_manager.state["hashes"]) == 1
        hashes_file = fresh_manager.workspace / "loot" / "hashes.txt"
        assert hashes_file.exists()

    def test_add_credential(self, fresh_manager):
        fresh_manager.set_target("10.10.10.100")
        fresh_manager.add_credential("admin", "Password123", "smb")
        creds = fresh_manager.state["credentials"]
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"
