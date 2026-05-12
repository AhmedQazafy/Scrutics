"""Startup dependency checker — clear error messages instead of tracebacks."""

import sys

REQUIRED = {
    "scapy":   "pip install scapy --break-system-packages",
    "textual": "pip install textual --break-system-packages",
    "yaml":    "pip install pyyaml --break-system-packages",
}


def check_dependencies(headless: bool = False) -> bool:
    check = dict(REQUIRED)
    if headless:
        check.pop("textual", None)
    missing = []
    for pkg, cmd in check.items():
        try:
            __import__(pkg)
        except ImportError:
            missing.append((pkg, cmd))
    if not missing:
        return True
    print("\n  [!] Scrutics: missing required dependencies\n")
    for pkg, cmd in missing:
        print(f"  Missing : {pkg}")
        print(f"  Install : {cmd}\n")
    print("  Or run: bash setup.sh\n")
    return False
