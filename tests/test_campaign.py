"""Tests for CampaignManager and multi-host AD clustering."""

import json

import pytest

from capo.campaign import CampaignManager
from capo.state import StateManager


@pytest.fixture
def cm(tmp_path, monkeypatch):
    """Isolated CampaignManager."""
    import capo.config
    
    monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)
    monkeypatch.setattr(capo.config, "CAMPAIGNS_DIR", tmp_path / "campaigns")
    monkeypatch.setattr(capo.config, "CURRENT_CAMPAIGN_FILE", tmp_path / "current_campaign.txt")
    (tmp_path / "campaigns").mkdir()
    
    from capo.campaign import CampaignManager
    import capo.campaign
    manager = CampaignManager()
    manager._state = {}
    manager.set_campaign("test-campaign")
    
    monkeypatch.setattr(capo.campaign, "campaign_manager", manager)
    
    return manager


@pytest.fixture
def sm(tmp_path, monkeypatch, cm):
    """Isolated StateManager using the active isolated CampaignManager."""
    import capo.config
    
    monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)
    monkeypatch.setattr(capo.config, "WORKSPACES_DIR", tmp_path / "workspaces")
    (tmp_path / "workspaces").mkdir()
    
    from capo.state import StateManager
    import capo.state
    
    manager = StateManager()
    manager._state = {}
    manager.set_target("10.10.10.1")
    
    return manager


class TestCampaignState:
    
    def test_campaign_creates_directories(self, cm, tmp_path):
        assert cm.active is True
        assert cm.name == "test-campaign"
        assert (tmp_path / "campaigns" / "test-campaign").exists()
        assert (tmp_path / "campaigns" / "test-campaign" / "campaign.json").exists()
        assert (tmp_path / "campaigns" / "test-campaign" / "loot").is_dir()

    def test_add_host_to_campaign(self, cm):
        cm.add_host("10.10.10.5")
        cm.add_host("10.10.10.10")
        assert "10.10.10.5" in cm._state["hosts"]
        assert "10.10.10.10" in cm._state["hosts"]

    def test_campaign_domain_info(self, cm):
        cm.update_domain_info(domain_name="test.local", dc_ip="10.10.10.1")
        assert cm.get_var("DOMAIN") == "test.local"
        assert cm.get_var("DC_IP") == "10.10.10.1"
        
    def test_campaign_writes_loot_files(self, cm):
        cm.add_user("admin")
        cm.add_credential("admin", "Password123!")
        
        users_file = cm._dir / "loot" / "users.txt"
        pass_file = cm._dir / "loot" / "passwords.txt"
        
        assert users_file.read_text().strip() == "admin"
        assert pass_file.read_text().strip() == "Password123!"


class TestStateDelegation:
    
    def test_sm_delegates_domain_info_to_cm(self, sm, cm):
        """When campaign is active, SM should pull domain info from CM."""
        cm.update_domain_info(domain_name="forest.htb")
        assert sm.get_var("DOMAIN") == "forest.htb"
        
    def test_sm_delegates_users_to_cm(self, sm, cm):
        """StateManager.add_user() should write to CampaignManager if active."""
        sm.add_user("jsmith")
        
        # Should be in campaign state
        assert "jsmith" in cm._state["users"]
        
        # In the new design, StateManager doesn't write local users if campaign is active
        # so check to ensure the file isn't created or the dict is empty
        assert not sm._state.get("users")
        
    def test_sm_delegates_credentials_to_cm(self, sm, cm):
        cm._state["credentials"] = []  # Clear previous test state
        sm.add_credential("jsmith", "Fall2024!")
        
        # Check campaign
        creds = cm._state["credentials"]
        assert len(creds) == 1
        assert creds[0]["username"] == "jsmith"
        assert creds[0]["password"] == "Fall2024!"
        
        # Check host
        assert "credentials" not in sm._state or len(sm._state["credentials"]) == 0

    def test_sm_retains_ports_locally(self, sm, cm):
        """Ports should remain in the host workspace, not go to the campaign."""
        sm.add_port(445, "tcp", "microsoft-ds")
        
        # In host
        assert any(p["port"] == 445 for p in sm._state["ports"])
        # Not in campaign
        assert "ports" not in cm._state


class TestListVariables:
    
    def test_get_var_userfile_active_campaign(self, sm, cm):
        """USERFILE should point to campaign's loot directory."""
        cm.add_user("admin")
        userfile = sm.get_var("USERFILE")
        assert "campaigns/test-campaign/loot/users.txt" in userfile
        
    def test_get_var_passfile_active_campaign(self, sm, cm):
        cm.add_credential("admin", "hunter2")
        passfile = sm.get_var("PASSFILE")
        assert "campaigns/test-campaign/loot/passwords.txt" in passfile
        
    def test_get_var_resolves_to_host_when_no_campaign(self, tmp_path, monkeypatch):
        """Verify fallback behavior when CampaignManager is NOT active."""
        import capo.config
        monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)
        monkeypatch.setattr(capo.config, "WORKSPACES_DIR", tmp_path / "workspaces")
        monkeypatch.setattr(capo.config, "CAMPAIGNS_DIR", tmp_path / "campaigns")
        monkeypatch.setattr(capo.config, "CURRENT_CAMPAIGN_FILE", tmp_path / "current_campaign.txt")
        (tmp_path / "workspaces").mkdir()
        
        from capo.campaign import CampaignManager
        from capo.state import StateManager
        import capo.state
        
        cm_inactive = CampaignManager()
        cm_inactive.clear_campaign()
        cm_inactive._state = {}
        
        monkeypatch.setattr(capo.campaign, "campaign_manager", cm_inactive)
        
        sm_standalone = StateManager()
        sm_standalone._state = {}
        sm_standalone.set_target("10.10.10.2")
        sm_standalone.add_user("local_admin")
        sm_standalone.add_credential("local_admin", "local_pass")
        
        # Check host states
        assert "local_admin" in sm_standalone._state.get("users", [])
        userfile = sm_standalone.get_var("USERFILE")
        assert "workspaces/10.10.10.2/loot/users.txt" in userfile
        
        passfile = sm_standalone.get_var("PASSFILE")
        assert "workspaces/10.10.10.2/loot/passwords.txt" in passfile
