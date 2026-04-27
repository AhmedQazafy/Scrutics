"""
OUI (Organizationally Unique Identifier) lookup.
Maps the first 3 bytes of a MAC address to a vendor name.

Load priority:
  1. Full IEEE OUI database (oui.txt) if present alongside this file
     → run scripts/download_oui.py to fetch it (requires internet)
  2. Bundled ICS vendor database (ics_oui.txt) — always present in repo
     → covers all major OT/ICS vendors for air-gapped deployments

This tool is designed for OT environments that may have no internet access.
The bundled database is sufficient for Phase 1 fingerprinting.
"""

import os

# Paths
_DIR = os.path.dirname(__file__)
OUI_FULL_PATH    = os.path.join(_DIR, "oui.txt")       # full IEEE db (optional)
OUI_BUNDLED_PATH = os.path.join(_DIR, "ics_oui.txt")   # bundled ICS db (always present)

# Vendors known to produce industrial/OT equipment
OT_VENDORS = {
    "siemens", "schneider", "rockwell", "allen-bradley", "moxa",
    "phoenix contact", "beckhoff", "advantech", "wago", "hilscher",
    "prosoft", "red lion", "kepware", "opto 22", "b&r", "pilz",
    "sick", "turck", "murrelektronik", "eaton", "abb", "honeywell",
    "emerson", "yokogawa", "ge", "mitsubishi", "omron", "delta",
    "invensys", "foxboro", "endress", "ifm", "pepperl", "contemporary controls",
    "hirschmann", "belden", "cisco", "lantronix", "digi international"
}


def _parse_oui_file(path: str) -> dict:
    """Parse an IEEE-format OUI text file into { 'AABBCC': 'Vendor Name' }."""
    oui_map = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.split("(hex)")
                if len(parts) == 2:
                    oui = parts[0].strip().replace("-", "").upper()
                    vendor = parts[1].strip()
                    oui_map[oui] = vendor
    return oui_map


def load_oui_db() -> dict:
    """
    Load OUI database. Uses full IEEE db if available, otherwise bundled ICS db.
    Never attempts a network download — use scripts/download_oui.py for that.
    """
    if os.path.exists(OUI_FULL_PATH):
        print(f"[*] Loading full OUI database from {OUI_FULL_PATH}")
        return _parse_oui_file(OUI_FULL_PATH)

    if os.path.exists(OUI_BUNDLED_PATH):
        print(f"[*] Loading bundled ICS OUI database from {OUI_BUNDLED_PATH}")
        return _parse_oui_file(OUI_BUNDLED_PATH)

    print("[!] No OUI database found. Run scripts/download_oui.py to fetch the full database.")
    print("[!] Falling back to empty OUI map — vendor lookup will return 'Unknown'.")
    return {}


def lookup_vendor(mac: str, oui_db: dict) -> str:
    """
    Look up vendor for a MAC address.
    Accepts any common format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    Returns vendor string or 'Unknown'.
    """
    normalized = mac.upper().replace(":", "").replace("-", "")
    oui = normalized[:6]
    return oui_db.get(oui, "Unknown")


def is_ot_vendor(vendor: str) -> bool:
    """Returns True if the vendor is known to produce OT/industrial equipment."""
    vendor_lower = vendor.lower()
    return any(ot in vendor_lower for ot in OT_VENDORS)
