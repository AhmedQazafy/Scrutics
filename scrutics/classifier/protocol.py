"""
Protocol-based device classification.
Maps observed network protocols and ports to device type inferences.
User-defined rules from config are checked first before built-in rules.
All classification is done passively from observed traffic only.
"""

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
    """
    Classify a device based on observed destination ports and optional MAC.
    Checks user-defined rules first, then built-in ICS port map.
    """
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

    matched_ics = []
    for port in ports_seen:
        if port in ICS_PORTS:
            matched_ics.append({**ICS_PORTS[port], "port": port})

    it_only = ports_seen.issubset(IT_PORTS) and not matched_ics

    if matched_ics:
        if len(matched_ics) > 1:
            role = "SCADA Server / HMI (multi-protocol)"
            confidence = CONFIDENCE_HIGH
        else:
            role = matched_ics[0]["role"]
            confidence = CONFIDENCE_HIGH
        return {
            "protocols": [m["protocol"] for m in matched_ics],
            "role": role,
            "is_ot": True,
            "confidence": confidence,
            "matched_rule": "builtin",
        }

    elif it_only:
        return {
            "protocols": ["IT (standard ports only)"],
            "role": "IT Device",
            "is_ot": False,
            "confidence": CONFIDENCE_MEDIUM,
            "matched_rule": "builtin",
        }

    else:
        return {
            "protocols": ["Unknown"],
            "role": "Unclassified — review manually",
            "is_ot": None,
            "confidence": CONFIDENCE_LOW,
            "matched_rule": None,
        }


def infer_role_from_behavior(packet_count: int, is_initiator: bool, peers: int) -> str:
    if peers > 10 and is_initiator:
        return "Likely HMI / SCADA polling engine"
    if not is_initiator and peers <= 2:
        return "Likely PLC or sensor (responds only)"
    if peers == 1 and packet_count > 100:
        return "Likely sensor / RTU (single peer, high frequency)"
    return "Role unclear — insufficient behavioral data"
