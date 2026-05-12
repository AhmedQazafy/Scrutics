"""Protocol-based device classification with config rule support."""

from scrutics.config.loader import load_rules, match_rule

ICS_PORTS = {
    502:   {"protocol": "Modbus TCP",      "role": "PLC / RTU / Modbus Gateway"},
    102:   {"protocol": "S7comm",          "role": "Siemens PLC"},
    44818: {"protocol": "EtherNet/IP",     "role": "Rockwell / Allen-Bradley Device"},
    2222:  {"protocol": "EtherNet/IP IO",  "role": "Rockwell IO Device"},
    20000: {"protocol": "DNP3",            "role": "Utility RTU / IED"},
    1911:  {"protocol": "Niagara Fox",     "role": "Building Automation Controller"},
    4840:  {"protocol": "OPC-UA",          "role": "OPC-UA Server / Gateway"},
    9600:  {"protocol": "OMRON FINS",      "role": "Omron PLC"},
    18245: {"protocol": "GE SRTP",         "role": "GE PLC"},
    2404:  {"protocol": "IEC 60870-5-104", "role": "Power Grid RTU / IED"},
    1962:  {"protocol": "PCWorx",          "role": "Phoenix Contact PLC"},
    47808: {"protocol": "BACnet/IP",       "role": "Building Automation Device"},
}
IT_PORTS = {80, 443, 22, 23, 21, 25, 53, 110, 143, 3389, 5900}
CONFIDENCE_HIGH   = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW    = "LOW"
_USER_RULES = load_rules()


def reload_rules():
    global _USER_RULES
    _USER_RULES = load_rules()


def classify_by_ports(ports_seen: set, mac: str = None) -> dict:
    for port in ports_seen:
        rule = match_rule(_USER_RULES, port=port, mac=mac)
        if rule:
            return {
                "protocols": [rule.get("classify_as", "Custom Protocol")],
                "role": rule.get("role", "Custom Device"),
                "is_ot": rule.get("is_ot", None),
                "confidence": rule.get("confidence", CONFIDENCE_HIGH),
                "matched_rule": "user",
            }
    if mac:
        rule = match_rule(_USER_RULES, mac=mac)
        if rule:
            return {
                "protocols": [rule.get("classify_as", "Custom Protocol")],
                "role": rule.get("role", "Custom Device"),
                "is_ot": rule.get("is_ot", None),
                "confidence": rule.get("confidence", CONFIDENCE_MEDIUM),
                "matched_rule": "user",
            }
    matched_ics = [
        {**ICS_PORTS[p], "port": p} for p in ports_seen if p in ICS_PORTS
    ]
    it_only = ports_seen.issubset(IT_PORTS) and not matched_ics

    if matched_ics:
        role = "SCADA Server / HMI (multi-protocol)" if len(matched_ics) > 1 else matched_ics[0]["role"]
        return {
            "protocols": [m["protocol"] for m in matched_ics],
            "role": role, "is_ot": True,
            "confidence": CONFIDENCE_HIGH, "matched_rule": "builtin",
        }
    elif it_only:
        return {
            "protocols": ["IT (standard ports only)"], "role": "IT Device",
            "is_ot": False, "confidence": CONFIDENCE_MEDIUM, "matched_rule": "builtin",
        }
    return {
        "protocols": ["Unknown"], "role": "Unclassified -- review manually",
        "is_ot": None, "confidence": CONFIDENCE_LOW, "matched_rule": None,
    }
