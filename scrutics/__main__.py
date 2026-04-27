"""
Scrutics — Passive OT/ICS Asset Discovery
Entry point: python -m scrutics
"""

import argparse
import time
import datetime
from scrutics.capture.engine import CaptureEngine
from scrutics.db.inventory import AssetInventory


def print_table(inventory: AssetInventory):
    """Print the current asset inventory as a formatted table."""
    assets = inventory.get_all()
    if not assets:
        print("[!] No assets discovered yet.")
        return

    print(f"\n{'─'*100}")
    print(f"{'IP':<18} {'MAC':<20} {'VENDOR':<25} {'PROTOCOL':<20} {'ROLE':<30} {'CONF':<8} {'PKTS'}")
    print(f"{'─'*100}")

    for a in sorted(assets, key=lambda x: x.ip):
        proto = (", ".join(a.protocols))[:18] if a.protocols else "Unknown"
        vendor = a.vendor[:23]
        role = a.role[:28]
        ot_flag = "⚠ OT" if a.is_ot else "   IT" if a.is_ot is False else "   ?"
        print(f"{a.ip:<18} {a.mac:<20} {vendor:<25} {proto:<20} {role:<30} {a.confidence:<8} {a.packet_count} {ot_flag}")

    print(f"{'─'*100}")
    print(f"Total assets: {inventory.count()}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Scrutics — Passive OT/ICS network asset discovery"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Network interface to capture on (e.g. eth0, en0)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=60,
        help="Capture duration in seconds (default: 60)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Export results to CSV file path"
    )
    args = parser.parse_args()

    inventory = AssetInventory()
    engine = CaptureEngine(interface=args.interface, inventory=inventory)

    try:
        engine.start(timeout=args.timeout)
    except KeyboardInterrupt:
        pass

    print_table(inventory)

    if args.output:
        inventory.export_csv(args.output)
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_path = f"scrutics_{timestamp}.csv"
        inventory.export_csv(default_path)


if __name__ == "__main__":
    main()
