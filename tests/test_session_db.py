"""Tests for the session database module."""

import pytest

from capo.modules.session_db import SessionDB


@pytest.fixture
def db(tmp_path):
    """Create a fresh SessionDB with a temp database."""
    return SessionDB(db_path=tmp_path / "test_sessions.db")


class TestSessionCRUD:
    def test_create_session(self, db):
        session = db.create_session("Forest", "10.10.10.161", "htb.local", "HTB")
        assert session["name"] == "Forest"
        assert session["target_ip"] == "10.10.10.161"
        assert session["domain"] == "htb.local"
        assert session["campaign"] == "HTB"
        assert session["status"] == "active"

    def test_create_duplicate_raises(self, db):
        db.create_session("Forest", "10.10.10.161")
        with pytest.raises(ValueError, match="already exists"):
            db.create_session("Forest", "10.10.10.162")

    def test_activate_session(self, db):
        db.create_session("Forest", "10.10.10.161")
        session = db.activate_session("Forest")
        assert session["name"] == "Forest"
        assert db.active_session_name == "Forest"
        assert db.active_session_id is not None

    def test_activate_nonexistent_raises(self, db):
        with pytest.raises(ValueError, match="not found"):
            db.activate_session("NoSuchSession")

    def test_deactivate_session(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.deactivate_session()
        assert db.active_session_name is None
        assert db.active_session_id is None
        assert db.get_active_session() is None

    def test_get_session(self, db):
        db.create_session("Forest", "10.10.10.161")
        session = db.get_session("Forest")
        assert session is not None
        assert session["name"] == "Forest"

    def test_get_session_not_found(self, db):
        assert db.get_session("Ghost") is None

    def test_list_sessions(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.create_session("Sauna", "10.10.10.175")
        sessions = db.list_sessions()
        assert len(sessions) == 2
        names = {s["name"] for s in sessions}
        assert names == {"Forest", "Sauna"}

    def test_list_sessions_empty(self, db):
        assert db.list_sessions() == []

    def test_delete_session(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.delete_session("Forest")
        assert db.get_session("Forest") is None
        assert db.list_sessions() == []

    def test_delete_active_session_clears(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.delete_session("Forest")
        assert db.active_session_name is None

    def test_delete_nonexistent_raises(self, db):
        with pytest.raises(ValueError, match="not found"):
            db.delete_session("Ghost")


class TestCommandRecording:
    def test_record_command_no_session(self, db):
        result = db.record_command("nmap", "nmap -p- 10.10.10.161")
        assert result == -1

    def test_record_command(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        cmd_id = db.record_command("nmap", "nmap -p- 10.10.10.161", duration=5.2)
        assert cmd_id > 0

    def test_list_commands(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.record_command("nmap", "nmap -p- 10.10.10.161")
        db.record_command("nxc", "nxc smb 10.10.10.161")

        cmds = db.list_commands()
        assert len(cmds) == 2
        assert cmds[0]["tool"] == "nmap"
        assert cmds[1]["tool"] == "nxc"

    def test_list_commands_by_session_name(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.record_command("nmap", "nmap 10.10.10.161")

        db.create_session("Sauna", "10.10.10.175")
        db.activate_session("Sauna")
        db.record_command("nmap", "nmap 10.10.10.175")

        forest_cmds = db.list_commands(session_name="Forest")
        assert len(forest_cmds) == 1
        assert "10.10.10.161" in forest_cmds[0]["command"]

    def test_list_commands_key_only(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        c1 = db.record_command("nmap", "nmap -p- 10.10.10.161")
        c2 = db.record_command("evil-winrm", "evil-winrm -i 10.10.10.161")
        db.mark_key(c2)

        key_cmds = db.list_commands(key_only=True)
        assert len(key_cmds) == 1
        assert key_cmds[0]["id"] == c2

    def test_list_commands_filter_tool(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.record_command("nmap", "nmap 10.10.10.161")
        db.record_command("nxc", "nxc smb 10.10.10.161")

        nmap_cmds = db.list_commands(tool="nmap")
        assert len(nmap_cmds) == 1
        assert nmap_cmds[0]["tool"] == "nmap"

    def test_get_command(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        cmd_id = db.record_command("nmap", "nmap 10.10.10.161", exit_code=0, duration=3.5)

        cmd = db.get_command(cmd_id)
        assert cmd is not None
        assert cmd["tool"] == "nmap"
        assert cmd["exit_code"] == 0
        assert cmd["duration"] == 3.5

    def test_get_command_not_found(self, db):
        assert db.get_command(999) is None

    def test_mark_key(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        cmd_id = db.record_command("nmap", "nmap 10.10.10.161")

        db.mark_key(cmd_id, True)
        cmd = db.get_command(cmd_id)
        assert cmd["is_key"] == 1

        db.mark_key(cmd_id, False)
        cmd = db.get_command(cmd_id)
        assert cmd["is_key"] == 0

    def test_manual_source(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        cmd_id = db.record_command("manual", "ssh user@10.10.10.161", source="manual")
        cmd = db.get_command(cmd_id)
        assert cmd["source"] == "manual"

    def test_command_updates_session_timestamp(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        before = db.get_session("Forest")["updated_at"]
        db.record_command("nmap", "nmap 10.10.10.161")
        after = db.get_session("Forest")["updated_at"]
        assert after >= before


class TestFindings:
    def test_add_finding_no_session(self, db):
        result = db.add_finding("test finding")
        assert result == -1

    def test_add_finding(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        fid = db.add_finding("Found AS-REP roastable user", category="credential", severity="high")
        assert fid > 0

    def test_add_finding_with_command(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        cmd_id = db.record_command("impacket-GetNPUsers", "GetNPUsers htb.local/")
        fid = db.add_finding("AS-REP hash obtained", command_id=cmd_id, category="credential")

        findings = db.list_findings()
        assert len(findings) == 1
        assert findings[0]["command_id"] == cmd_id

    def test_list_findings(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.add_finding("Finding 1")
        db.add_finding("Finding 2")

        findings = db.list_findings()
        assert len(findings) == 2

    def test_list_findings_by_session(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.add_finding("Forest finding")

        db.create_session("Sauna", "10.10.10.175")
        db.activate_session("Sauna")
        db.add_finding("Sauna finding")

        forest_findings = db.list_findings(session_name="Forest")
        assert len(forest_findings) == 1
        assert forest_findings[0]["title"] == "Forest finding"

    def test_delete_finding(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        fid = db.add_finding("To be deleted")
        db.delete_finding(fid)
        assert db.list_findings() == []

    def test_cascade_delete(self, db):
        """Deleting a session should delete all its commands and findings."""
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.record_command("nmap", "nmap 10.10.10.161")
        db.add_finding("Test finding")

        db.delete_session("Forest")
        # Commands and findings should be gone
        assert db.list_commands(session_name="Forest") == []
        assert db.list_findings(session_name="Forest") == []


class TestSummary:
    def test_summary_empty_session(self, db):
        db.create_session("Forest", "10.10.10.161")
        summary = db.session_summary("Forest")
        assert summary["name"] == "Forest"
        assert summary["total_commands"] == 0
        assert summary["key_steps"] == 0
        assert summary["findings_count"] == 0

    def test_summary_with_data(self, db):
        db.create_session("Forest", "10.10.10.161", "htb.local")
        db.activate_session("Forest")

        c1 = db.record_command("nmap", "nmap 10.10.10.161")
        c2 = db.record_command("evil-winrm", "evil-winrm -i 10.10.10.161")
        db.mark_key(c2)
        db.add_finding("Got shell", command_id=c2, severity="high")

        summary = db.session_summary("Forest")
        assert summary["total_commands"] == 2
        assert summary["key_steps"] == 1
        assert summary["findings_count"] == 1
        assert summary["first_command_at"] is not None
        assert summary["last_command_at"] is not None

    def test_summary_no_session(self, db):
        assert db.session_summary("Ghost") == {}

    def test_summary_defaults_to_active(self, db):
        db.create_session("Forest", "10.10.10.161")
        db.activate_session("Forest")
        db.record_command("nmap", "nmap 10.10.10.161")

        summary = db.session_summary()
        assert summary["name"] == "Forest"
        assert summary["total_commands"] == 1


class TestPersistence:
    def test_session_file_persistence(self, tmp_path):
        """Active session should persist across SessionDB instances."""
        db1 = SessionDB(db_path=tmp_path / "sessions.db")
        db1.create_session("Forest", "10.10.10.161")
        db1.activate_session("Forest")

        # New instance should auto-load active session
        db2 = SessionDB(db_path=tmp_path / "sessions.db")
        assert db2.active_session_name == "Forest"
        assert db2.active_session_id is not None

    def test_commands_persist(self, tmp_path):
        db1 = SessionDB(db_path=tmp_path / "sessions.db")
        db1.create_session("Forest", "10.10.10.161")
        db1.activate_session("Forest")
        db1.record_command("nmap", "nmap 10.10.10.161")

        db2 = SessionDB(db_path=tmp_path / "sessions.db")
        cmds = db2.list_commands(session_name="Forest")
        assert len(cmds) == 1


class TestMultipleSessions:
    def test_switch_sessions(self, db):
        db.create_session("Forest", "10.10.10.161", "htb.local")
        db.create_session("Sauna", "10.10.10.175", "egotistical-bank.local")

        db.activate_session("Forest")
        db.record_command("nmap", "nmap 10.10.10.161")

        db.activate_session("Sauna")
        db.record_command("nmap", "nmap 10.10.10.175")

        # Each session has its own commands
        assert len(db.list_commands(session_name="Forest")) == 1
        assert len(db.list_commands(session_name="Sauna")) == 1

        # Active session is Sauna
        assert db.active_session_name == "Sauna"
        assert len(db.list_commands()) == 1  # defaults to active
