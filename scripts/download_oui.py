"""
Download the full IEEE OUI database and place it next to the classifier.
Run this once on a machine with internet access.

Usage:
    python scripts/download_oui.py

The downloaded oui.txt will be used automatically by Scrutics
in preference to the bundled ics_oui.txt.
"""

import os
import requests

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
DEST = os.path.join(
    os.path.dirname(__file__),
    "..", "scrutics", "classifier", "oui.txt"
)

def main():
    print(f"[*] Downloading OUI database from {OUI_URL}")
    try:
        response = requests.get(OUI_URL, timeout=30)
        response.raise_for_status()
        with open(DEST, "w", encoding="utf-8", errors="ignore") as f:
            f.write(response.text)
        lines = response.text.count("(hex)")
        print(f"[+] Done. {lines} OUI entries saved to {os.path.abspath(DEST)}")
    except requests.HTTPError as e:
        print(f"[!] HTTP error: {e}")
        print("[!] IEEE may be blocking the request. Try downloading manually:")
        print(f"    {OUI_URL}")
        print(f"    Save as: scrutics/classifier/oui.txt")
    except Exception as e:
        print(f"[!] Failed: {e}")

if __name__ == "__main__":
    main()
