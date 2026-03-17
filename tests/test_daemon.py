"""Tests for the YAML daemon evaluation engine."""

import pytest

from capo.modules.daemon import SuggestionRule


class TestDaemonRuleEvaluation:
    def test_legacy_port_and_state_conditions(self):
        """Test the old require_ports and require_state conditions."""
        rule_data = {
            "name": "Legacy Rule",
            "conditions": {
                "require_ports": [80],
                "require_state": ["has_domain"]
            },
            "command_template": "echo {IP}"
        }
        rule = SuggestionRule(rule_data)
        
        # Missing port and domain
        assert not rule.evaluate({"ports": []})
        
        # Has port, missing domain
        assert not rule.evaluate({"ports": [{"port": 80, "protocol": "tcp"}], "domain": ""})
        
        # Met conditions
        assert rule.evaluate({"ports": [{"port": 80, "protocol": "tcp"}], "domain": "test.local"})

    def test_jmespath_basic_condition(self):
        """Test a simple JMESPath query."""
        rule_data = {
            "name": "JMES Rule",
            "conditions": {
                "jmespath": "length(users) > `0`"
            },
            "command_template": "echo {USERFILE}"
        }
        rule = SuggestionRule(rule_data)
        
        # No users
        assert not rule.evaluate({"users": []})
        
        # User exists
        assert rule.evaluate({"users": ["root"]})

    def test_jmespath_complex_condition(self):
        """Test a more advanced JMESPath query combining arrays and properties."""
        rule_data = {
            "name": "JMES Complex Rule",
            "conditions": {
                "jmespath": "length(ports[?port==`80`]) > `0` && domain != null"
            },
            "command_template": "echo complex"
        }
        rule = SuggestionRule(rule_data)
        
        # Missing domain, has port 80
        assert not rule.evaluate({
            "ports": [{"port": 80}],
            "domain": None
        })
        
        # Missing port 80, has domain
        assert not rule.evaluate({
            "ports": [{"port": 443}],
            "domain": "test.local"
        })
        
        # Both conditions met
        assert rule.evaluate({
            "ports": [{"port": 80}, {"port": 443}],
            "domain": "test.local"
        })

    def test_jmespath_syntax_error_handled_gracefully(self):
        """Test that malformed JMESPath strings fail closed and do not crash."""
        rule_data = {
            "name": "Broken Rule",
            "conditions": {
                "jmespath": "invalid(syntax]!"
            },
            "command_template": "echo oops"
        }
        rule = SuggestionRule(rule_data)
        
        # Should return False despite invalid query
        assert not rule.evaluate({"users": ["root"]})

    def test_variable_requirements_enforced(self):
        """Test that rules enforcing variables in templates correctly require state variables."""
        rule_data = {
            "name": "Passfile Rule",
            "conditions": {},
            "command_template": "spray -P {PASSFILE}"
        }
        rule = SuggestionRule(rule_data)
        
        # Should fail because {PASSFILE} requires credentials in state
        assert not rule.evaluate({"users": ["admin"]})
        
        # Now has credentials
        assert rule.evaluate({"credentials": [{"username": "admin", "password": "password"}]})
