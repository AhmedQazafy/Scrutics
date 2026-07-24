"""
Scrutics CLI — headless and scriptable interface.

Usage:
  python3 -m scrutics                                    # TUI
  python3 -m scrutics --live eth0                        # TUI, pre-loads live capture
  python3 -m scrutics --live eth0 --headless             # headless live capture
  python3 -m scrutics --live eth0 --duration 0 --headless  # infinite until Ctrl+C
  python3 -m scrutics --file capture.pcap --headless     # headless file analysis
  python3 -m scrutics --file big.pcap --no-baseline      # inventory only, no anomalies

Runtime reload:
  Edit scrutics_rules.yaml while live capture runs — Scrutics reloads it
  automatically when the file parses and validates successfully.
  On Linux, SIGHUP is also supported for headless workflows.
"""

import argparse
import itertools
import sys
import os
import signal
import datetime
import threading

from scrutics.db.inventory import AssetInventory

VERSION = "v0.3.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scrutics",
        description="Scrutics -- Passive OT/ICS Network Asset Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
output:
  All results saved to: output/scrutics_TIMESTAMP/
    assets.csv    -- full asset inventory with confidence scores
    events.csv    -- classification event log  (written continuously)
    anomalies.csv -- behavioral anomaly feed   (written continuously)
        """
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", metavar="INTERFACE",
                      help="Network interface to capture on (e.g. eth0, br-abc123)")
    mode.add_argument("--file", metavar="FILEPATH",
                      help="File to analyze (.pcap, .pcapng, .log, .json)")
    parser.add_argument("--duration", type=int, default=60, metavar="SECONDS",
                        help="Capture duration in seconds. 0 = infinite until Ctrl+C. (default: 60)")
    parser.add_argument("--baseline", type=int, default=60, metavar="SECONDS",
                        help="Baseline observation window in seconds (default: 60)")
    parser.add_argument("--output", default="output", metavar="DIR",
                        help="Output directory (default: ./output)")
    parser.add_argument("--headless", action="store_true",
                        help="Run without TUI — CSV output only. Useful for scripts and servers.")
    parser.add_argument("--no-baseline", action="store_true", dest="no_baseline",
                        help="Skip behavioral baseline and anomaly detection. "
                             "Inventory and classification only. "
                             "Recommended for large PCAP files.")
    parser.add_argument("--version", action="version", version=f"Scrutics {VERSION}")
    return parser


def _make_session_dir(base: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"scrutics_{ts}")
    os.makedirs(path, exist_ok=True)
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


def _run_spinner(done_event: threading.Event, abort_event: threading.Event,
                 message: str = "Processing"):
    """ASCII spinner for silent phases. Stops on done or abort."""
    frames = itertools.cycle(["/", "-", "\\", "|"])
    while not done_event.is_set():
        if abort_event.is_set():
            print()
            return
        print(f"\r  {next(frames)}  {message} ...", end="", flush=True)
        done_event.wait(0.12)
    print(f"\r  ✓  {message}    ", flush=True)


def _periodic_table(inventory: AssetInventory, done_event: threading.Event,
                    stop_event: threading.Event, interval: int = 60):
    """Print asset snapshot every `interval` seconds during live headless capture."""
    elapsed = 0
    while not done_event.is_set() and not stop_event.is_set():
        done_event.wait(timeout=1.0)
        elapsed += 1
        if elapsed % interval == 0 and inventory.count() > 0:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"\n\n[{ts}] Asset snapshot ({elapsed}s elapsed):")
            _print_table(inventory)


def run_headless(args) -> int:
    from scrutics.capture.engine import CaptureEngine
    from scrutics.db.writer import RollingWriter
    from scrutics.integrations.sinks import SinkManager
    from scrutics.config.loader import load_sinks_config
    import scrutics.signals as signals

    inventory   = AssetInventory()
    session_dir = _make_session_dir(args.output)
    engine      = CaptureEngine(inventory=inventory, baseline_window=args.baseline)
    engine.writer      = RollingWriter(session_dir)
    engine.no_baseline = getattr(args, "no_baseline", False)

    try:
        sinks_cfg = load_sinks_config(strict=True)
        if sinks_cfg:
            engine.sink_manager = SinkManager(sinks_cfg)
    except Exception as e:
        print(f"[!] Config error: {e}")
        return 1

    def _reload():
        from scrutics.classifier.protocol import reload_rules
        try:
            reload_rules()
            new_sinks = load_sinks_config(strict=True)
            if engine.sink_manager:
                errors = engine.sink_manager.reload(new_sinks)
            elif new_sinks:
                engine.sink_manager = SinkManager(new_sinks)
                errors = []
            else:
                errors = []
            if errors:
                raise ValueError("; ".join(errors))
            print("\n[+] Rules and sinks reloaded.", flush=True)
        except Exception as e:
            print(f"\n[!] Reload failed (old rules kept): {e}", flush=True)

    signals.set_reload_callback(_reload)
    signals.start_file_watch()

    stop_event = threading.Event()

    def handle_sigint(sig, frame):
        print("\n[*] Stopping...")
        stop_event.set()
    signal.signal(signal.SIGINT, handle_sigint)

    # ── Live capture ──────────────────────────────────────────────────────────
    if args.live:
        dur_str = "infinite (Ctrl+C to stop)" if args.duration == 0 else f"{args.duration}s"
        print(f"\n[*] Scrutics {VERSION} -- Headless Mode")
        print(f"[*] Interface : {args.live}")
        print(f"[*] Duration  : {dur_str}")
        print(f"[*] Baseline  : {'disabled' if engine.no_baseline else f'{args.baseline}s'}")
        print(f"[*] Output    : {session_dir}")
        if engine.sink_manager:
            print(f"[*] Sinks     : {engine.sink_manager.count} configured")
        print()

        def on_progress(count: int):
            if count % 100 == 0:
                print(f"\r  packets: {count}  assets: {inventory.count()}",
                      end="", flush=True)
        engine.progress_callback = on_progress

        capture_done = threading.Event()

        def run_capture():
            try:
                engine.start_live(interface=args.live, timeout=args.duration)
            except Exception as e:
                print(f"\n[!] Capture error: {e}")
            finally:
                capture_done.set()

        threading.Thread(target=run_capture, daemon=True).start()
        threading.Thread(
            target=_periodic_table,
            args=(inventory, capture_done, stop_event, 60),
            daemon=True,
        ).start()

        try:
            while not capture_done.is_set() and not stop_event.is_set():
                capture_done.wait(timeout=1.0)
        finally:
            pass  # always fall through to export

    # ── File analysis ─────────────────────────────────────────────────────────
    elif args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}")
            return 1
        print(f"\n[*] Scrutics {VERSION} -- Headless Mode")
        print(f"[*] Analyzing : {args.file}")
        print(f"[*] Baseline  : {'disabled' if engine.no_baseline else f'{args.baseline}s window'}")
        print(f"[*] Output    : {session_dir}\n")

        spin_done  = threading.Event()
        file_error = [None]

        def run_file():
            try:
                engine.start_file(args.file)
            except Exception as e:
                file_error[0] = e
            finally:
                spin_done.set()

        threading.Thread(target=run_file, daemon=True).start()
        _run_spinner(spin_done, stop_event, f"Analyzing {os.path.basename(args.file)}")

        if stop_event.is_set():
            print("[*] Interrupted — saving partial results.")
        elif file_error[0]:
            print(f"[!] Error: {file_error[0]}")
            return 1

    # ── Export — always runs regardless of how capture ended ──────────────────
    print()
    _print_table(inventory)

    try:
        inventory.export_csv(os.path.join(session_dir, "assets.csv"))

        if not engine.no_baseline:
            anomaly_count = len(engine.baseline.get_anomalies())
            if anomaly_count:
                print(f"[!] {anomaly_count} anomalies -- see {session_dir}/anomalies.csv")
            else:
                print("[+] No anomalies detected.")

        print(f"\n[+] Session saved to: {session_dir}")
        return 0 if inventory.count() > 0 else 2

    finally:
        if engine.sink_manager:
            engine.sink_manager.close()
        signals.stop_file_watch()


def should_use_tui(args) -> bool:
    if args.headless:           return False
    if not sys.stdout.isatty(): return False
    return True
