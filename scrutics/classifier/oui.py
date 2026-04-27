"""
OUI (Organizationally Unique Identifier) lookup.
Maps the first 3 bytes of a MAC address to a vendor name.
Uses the IEEE public OUI database.
"""

import os
import requests

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_CACHE_PATH = os.path.join(os.path.dirname(__file__), "oui.txt")

# Vendors known to produce industrial/OT equipment
OT_VENDORS = {
    "siemens", "schneider", "rockwell", "allen-bradley", "moxa",
    "phoenix contact", "beckhoff", "advantech", "wago", "hilscher",
    "prosoft", "red lion", "kepware", "opto 22", "b&r", "pilz",
    "sick", "turck", "murrelektronik", "eaton", "abb", "honeywell",
    "emerson", "yokogawa", "ge", "mitsubishi", "omron", "delta",
    "invensys", "foxboro", "endress", "ifm", "pepperl"
}


def download_oui_db():
    """Download the IEEE OUI database if not cached locally."""
    print("[*] Downloading OUI database from IEEE...")
    response = requests.get(OUI_URL, timeout=30)
    response.raise_for_status()
    with open(OUI_CACHE_PATH, "w", encoding="utf-8", errors="ignore") as f:
        f.write(response.text)
    print(f"[+] OUI database saved to {OUI_CACHE_PATH}")


def load_oui_db() -> dict:
    """
    Parse the OUI text file into a dict: { 'AABBCC': 'Vendor Name' }
    Downloads the file if not present.
    """
    if not os.path.exists(OUI_CACHE_PATH):
        download_oui_db()

    oui_map = {}
    with open(OUI_CACHE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.split("(hex)")
                if len(parts) == 2:
                    oui = parts[0].strip().replace("-", "").upper()
                    vendor = parts[1].strip()
                    oui_map[oui] = vendor
    return oui_map


def lookup_vendor(mac: str, oui_db: dict) -> str:
    """
    Look up the vendor for a MAC address.
    MAC can be in any common format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    Returns vendor string or 'Unknown'.
    """
    normalized = mac.upper().replace(":", "").replace("-", "")
    oui = normalized[:6]
    return oui_db.get(oui, "Unknown")


def is_ot_vendor(vendor: str) -> bool:
    """Returns True if the vendor is known to produce OT/industrial equipment."""
    vendor_lower = vendor.lower()
    return any(ot in vendor_lower for ot in OT_VENDORS)
