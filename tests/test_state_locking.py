"""Tests for state file locking and concurrent merge logic."""

import json

import pytest

from capo.state import StateManager


@pytest.fixture
def sm(tmp_path, monkeypatch):
    """Create a StateManager with isolated workspace."""
    import capo.config
    monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)
    monkeypatch.setattr(capo.config, "WORKSPACES_DIR", tmp_path / "workspaces")
    (tmp_path / "workspaces").mkdir()

    manager = StateManager()
    manager.set_target("10.10.10.1")
    return manager


class TestMergeState:
    """Test _merge_state() merging logic."""

    def test_list_dedup_union(self, sm):
        """Lists merge as deduplicated union — no entries lost."""
        disk = {"users": ["alice", "bob"], "ports": [22, 80]}
        sm._state = {"users": ["bob", "carol"], "ports": [80, 443]}
        merged = sm._merge_state(disk)

        assert set(merged["users"]) == {"alice", "bob", "carol"}
        assert set(merged["ports"]) == {22, 80, 443}

    def test_list_preserves_order(self, sm):
        """Disk entries come first, then in-memory additions."""
        disk = {"users": ["alice", "bob"]}
        sm._state = {"users": ["carol", "alice"]}
        merged = sm._merge_state(disk)

        assert merged["users"] == ["alice", "bob", "carol"]

    def test_dict_shallow_merge(self, sm):
        """Dicts are shallow-merged (in-memory wins on conflicts)."""
        disk = {"flags": {"local_txt": "abc123", "proof_txt": ""}}
        sm._state = {"flags": {"proof_txt": "xyz789"}}
        merged = sm._merge_state(disk)

        assert merged["flags"]["local_txt"] == "abc123"
        assert merged["flags"]["proof_txt"] == "xyz789"

    def test_scalar_in_memory_wins(self, sm):
        """Scalars use the in-memory value."""
        disk = {"hostname": "old-host", "os": "Linux"}
        sm._state = {"hostname": "new-host", "os": "Linux"}
        merged = sm._merge_state(disk)

        assert merged["hostname"] == "new-host"

    def test_new_keys_added(self, sm):
        """Keys present only in disk state are preserved."""
        disk = {"custom_field": "disk_only"}
        sm._state = {"hostname": "test"}
        merged = sm._merge_state(disk)

        assert merged["custom_field"] == "disk_only"
        assert merged["hostname"] == "test"


class TestLockFile:
    """Test lock file creation."""

    def test_lock_file_path(self, sm):
        lock = sm._lock_file()
        assert str(lock.lock_file).endswith("state.json.lock")

    def test_save_creates_lock_briefly(self, sm):
        sm.add_user("testuser")
        lock_path = sm._state_file().parent / "state.json.lock"
        # Lock file may or may not persist (filelock cleans up)
        # But state.json must exist and contain the user
        state = json.loads(sm._state_file().read_text())
        assert "testuser" in state["users"]


class TestConcurrentMerge:
    """Simulate concurrent writes to verify merge behavior."""

    def test_simulated_concurrent_save(self, sm):
        """Simulate: Process A saves users, then Process B saves ports.
        Both should be present in the final state."""
        # Process A adds users
        sm.add_user("alice")
        sm.add_user("bob")

        # Simulate Process B: directly write ports to disk
        state_file = sm._state_file()
        disk_state = json.loads(state_file.read_text())
        disk_state["ports"].append({"port": 22, "protocol": "tcp", "service": "ssh"})
        disk_state["ports"].append({"port": 80, "protocol": "tcp", "service": "http"})
        state_file.write_text(json.dumps(disk_state, indent=2))

        # Now Process A adds another user — this triggers reload+merge
        sm.add_user("carol")

        # Verify: both users AND ports are present
        final = json.loads(state_file.read_text())
        assert "alice" in final["users"]
        assert "bob" in final["users"]
        assert "carol" in final["users"]
        assert any(p["port"] == 22 for p in final["ports"])
        assert any(p["port"] == 80 for p in final["ports"])

    def test_disk_changes_not_lost(self, sm):
        """Data written to disk by another process isn't overwritten."""
        sm.add_user("original")

        # Another process writes a credential to disk
        state_file = sm._state_file()
        disk = json.loads(state_file.read_text())
        disk["credentials"].append({"username": "admin", "password": "P@ss", "service": "ssh"})
        state_file.write_text(json.dumps(disk, indent=2))

        # Our process adds another user (triggers merge)
        sm.add_user("new_user")

        final = json.loads(state_file.read_text())
        assert {"username": "admin", "password": "P@ss", "service": "ssh"} in final["credentials"]
        assert "original" in final["users"]
        assert "new_user" in final["users"]
