"""
Configuration loader for Scrutics.
Loads user-defined classification rules from YAML.
"""

import os
import yaml

# Look for config in project root, then home directory
CONFIG_SEARCH_PATHS = [
    os.path.join(os.getcwd(), "scrutics_rules.yaml"),
    os.path.join(os.path.dirname(__file__), "default_rules.yaml"),
]


def load_rules() -> list:
    """
    Load classification rules from the first config file found.
    Returns a list of rule dicts. Empty list if no rules defined.
    """
    for path in CONFIG_SEARCH_PATHS:
        if os.path.exists(path):
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
                rules = data.get("rules", [])
                if rules:
                    return rules
    return []


def match_rule(rules: list, port: int = None, mac: str = None, proto: str = None) -> dict | None:
    """
    Check if any user-defined rule matches the given indicators.
    Returns the matching rule dict or None.
    """
    for rule in rules:
        port_match = True
        mac_match = True
        proto_match = True

        if "port" in rule and port is not None:
            port_match = (rule["port"] == port)
        elif "port" in rule:
            port_match = False

        if "mac_prefix" in rule and mac is not None:
            normalized = mac.upper().replace("-", ":")
            port_match = normalized.startswith(rule["mac_prefix"].upper())
        elif "mac_prefix" in rule:
            mac_match = False

        if "protocol" in rule and proto is not None:
            proto_match = (rule["protocol"].upper() == proto.upper())

        if port_match and mac_match and proto_match:
            return rule

    return None
