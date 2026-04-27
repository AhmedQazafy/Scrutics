"""
Protocol-based device classification.
Maps observed network protocols and ports to device type inferences.
All classification is done passively from observed traffic only.
"""

# Port-to-protocol map for known ICS/OT protocols
ICS_PORTS = {
    502:  {"protocol": "Modbus TCP",     "role": "PLC / RTU / Modbus Gateway"},
    102:  {"protocol": "S7comm",         "role": "Siemens PLC"},
    44818: {"protocol": "EtherNet/IP",   "role": "Rockwell / Allen-Bradley Device"},
    2222: {"protocol": "EtherNet/IP IO", "role": "Rockwell IO Device"},
    20000: {"protocol": "DNP3",          "role": "Utility RTU / IED"},
    1911: {"protocol": "Niagara Fox",    "role": "Building Automation Controller"},
    4840: {"protocol": "OPC-UA",         "role": "OPC-UA Server / Gateway"},
    9600: {"protocol": "OMRON FINS",     "role": "Omron PLC"},
    18245: {"protocol": "GE SRTP",       "role": "GE PLC"},
    2404: {"protocol": "IEC 60870-5-104","role": "Power Grid RTU / IED"},
    1962: {"protocol": "PCWorx",         "role": "Phoenix Contact PLC"},
}

# Standard IT ports — devices using only these are likely IT, not OT
IT_PORTS = {80, 443, 22, 23, 21, 25, 53, 110, 143, 3389, 5900}

# Confidence levels
CONFIDENCE_HIGH   = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW    = "LOW"


def classify_by_ports(ports_seen: set) -> dict:
    """
    Given a set of ports observed for a device, return classification result.

    Returns:
        {
            "protocols": [...],
            "role": "...",
            "is_ot": True/False,
            "confidence": "HIGH" / "MEDIUM" / "LOW"
        }
    """
    matched_ics = []
    for port in ports_seen:
        if port in ICS_PORTS:
            matched_ics.append({**ICS_PORTS[port], "port": port})

    it_only = ports_seen.issubset(IT_PORTS) and not matched_ics

    if matched_ics:
        # Multiple ICS protocols = likely SCADA server or HMI
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
        }

    elif it_only:
        return {
            "protocols": ["IT (standard ports only)"],
            "role": "IT Device",
            "is_ot": False,
            "confidence": CONFIDENCE_MEDIUM,
        }

    else:
        return {
            "protocols": ["Unknown"],
            "role": "Unclassified — review manually",
            "is_ot": None,
            "confidence": CONFIDENCE_LOW,
        }


def infer_role_from_behavior(packet_count: int, is_initiator: bool, peers: int) -> str:
    """
    Infer likely device role from behavioral patterns observed in traffic.
    This is a heuristic layer on top of port classification.

    - High peer count + initiates = likely HMI or SCADA polling engine
    - Only responds, never initiates = likely PLC or sensor
    - Single peer, regular intervals = likely sensor or RTU
    """
    if peers > 10 and is_initiator:
        return "Likely HMI / SCADA polling engine"
    if not is_initiator and peers <= 2:
        return "Likely PLC or sensor (responds only)"
    if peers == 1 and packet_count > 100:
        return "Likely sensor / RTU (single peer, high frequency)"
    return "Role unclear — insufficient behavioral data"
