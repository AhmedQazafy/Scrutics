"""
Scrutics CLI — headless and scriptable interface.

Usage:
  python3 -m scrutics                              # TUI
  python3 -m scrutics --live eth0                  # TUI, pre-loads live capture
  python3 -m scrutics --live eth0 --headless       # no TUI, CSV output only
  python3 -m scrutics --live eth0 --duration 0     # run until Ctrl+C (0 = infinite)
  python3 -m scrutics --file capture.pcap          # analyze file
  python3 -m scrutics --file eve.json --headless   # headless file analysis
"""

import argparse
import sys
import os
import signal
import datetime
import threading
import csv

from scrutics.db.inventory import AssetInventory

VERSION = "v0.2.0-dev"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scrutics",
        description="Scrutics -- Passive OT/ICS Network Asset Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
output:
  All results saved to: output/scrutics_TIMESTAMP/
    assets.csv    -- full asset inventory with confidence scores
    events.csv    -- classification event log
    anomalies.csv -- behavioral anomaly feed
        """
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", metavar="INTERFACE",
                      help="Network interface to capture on (e.g. eth0, br-abc123)")
    mode.add_argument("--file", metavar="FILEPATH",
                      help="File to analyze (.pcap, .pcapng, .log, .json)")
    parser.add_argument("--duration", type=int, default=60, metavar="SECONDS",
                        help="Capture duration. 0 = run indefinitely until Ctrl+C. (default: 60)")
    parser.add_argument("--baseline", type=int, default=60, metavar="SECONDS",
                        help="Baseline observation window in seconds (default: 60)")
    parser.add_argument("--output", default="output", metavar="DIR",
                        help="Output directory (default: ./output)")
    parser.add_argument("--headless", action="store_true",
                        help="Run without TUI -- CSV output only. Useful for scripts.")
    parser.add_argument("--version", action="version", version=f"Scrutics {VERSION}")
    return parser


def _make_session_dir(base: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"scrutics_{ts}")
    os.makedirs(path, exist_ok=True)
    return path


def _export_events(engine, session_dir: str):
    path = os.path.join(session_dir, "events.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "message"])
        for ts, msg, _ in engine.get_event_buffer():
            writer.writerow([ts, msg])
    return path


def _export_anomalies(engine, session_dir: str):
    anomalies = engine.baseline.get_anomalies()
    if not anomalies:
        return None
    path = os.path.join(session_dir, "anomalies.csv")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "ip", "type", "severity", "detail"])
        writer.writeheader()
        for a in anomalies:
            writer.writerow({
                "timestamp": datetime.datetime.fromtimestamp(
                    a.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S"),
                "ip": a.get("ip",""), "type": a.get("type",""),
                "severity": a.get("severity",""), "detail": a.get("detail",""),
            })
    return path


def _print_table(inventory: AssetInventory):
    assets = sorted(inventory.get_all(), key=lambda x: x.ip)
    if not assets:
        print("[!] No assets discovered.")
        return
    print(f"\n{'─'*110}")
    print(f"{'IP':<18} {'MAC':<20} {'VENDOR':<22} {'PROTOCOL':<18} {'ROLE':<28} {'CONF%':<7} {'TYPE'}")
    print(f"{'─'*110}")
    for a in assets:
        proto  = ", ".join(a.protocols)[:18] if a.protocols else "Unknown"
        type_s = "OT" if a.is_ot is True else "IT" if a.is_ot is False else "?"
        print(f"{a.ip:<18} {a.mac:<20} {a.vendor[:22]:<22} {proto:<18} "
              f"{a.role[:28]:<28} {a.confidence_pct:<7}% {type_s}")
    print(f"{'─'*110}")
    print(f"Total: {inventory.count()} assets\n")


def run_headless(args) -> int:
    from scrutics.capture.engine import CaptureEngine
    inventory  = AssetInventory()
    engine     = CaptureEngine(inventory=inventory, baseline_window=args.baseline)
    session_dir = _make_session_dir(args.output)
    stop_event  = threading.Event()

    def on_progress(count: int):
        if count % 100 == 0:
            print(f"\r  packets: {count}  assets: {inventory.count()}", end="", flush=True)
    engine.progress_callback = on_progress

    def handle_sigint(sig, frame):
        print("\n[*] Stopping...")
        stop_event.set()
    signal.signal(signal.SIGINT, handle_sigint)

    if args.live:
        dur_str = "infinite (Ctrl+C to stop)" if args.duration == 0 else f"{args.duration}s"
        print(f"\n[*] Scrutics {VERSION} -- Headless Mode")
        print(f"[*] Interface : {args.live}")
        print(f"[*] Duration  : {dur_str}")
        print(f"[*] Baseline  : {args.baseline}s")
        print(f"[*] Output    : {session_dir}\n")

        capture_done = threading.Event()
        def run_capture():
            try:
                engine.start_live(interface=args.live, timeout=args.duration)
            except Exception as e:
                print(f"\n[!] Error: {e}")
            finally:
                capture_done.set()

        threading.Thread(target=run_capture, daemon=True).start()
        while not capture_done.is_set() and not stop_event.is_set():
            capture_done.wait(timeout=1.0)

    elif args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}")
            return 1
        print(f"\n[*] Scrutics {VERSION} -- Headless Mode")
        print(f"[*] Analyzing : {args.file}")
        print(f"[*] Output    : {session_dir}\n")
        try:
            engine.start_file(args.file)
        except Exception as e:
            print(f"[!] Error: {e}")
            return 1

    print()
    _print_table(inventory)
    if inventory.count() == 0:
        return 2

    inventory.export_csv(os.path.join(session_dir, "assets.csv"))
    _export_events(engine, session_dir)
    anomalies = engine.baseline.get_anomalies()
    if anomalies:
        ap = _export_anomalies(engine, session_dir)
        print(f"[!] {len(anomalies)} anomalies -- see {ap}")
    else:
        print("[+] No anomalies detected.")

    print(f"\n[+] Session saved to: {session_dir}")
    return 0


def should_use_tui(args) -> bool:
    if args.headless:        return False
    if not sys.stdout.isatty(): return False
    return True
