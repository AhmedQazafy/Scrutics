"""
Scrutics entry point.
No args + interactive terminal -> TUI
--headless or piped stdout     -> CLI
--live/--file without headless -> TUI with mode pre-loaded
"""
import sys
from scrutics.deps import check_dependencies
from scrutics.cli import build_parser, run_headless, should_use_tui


def main():
    if len(sys.argv) == 1:
        if not check_dependencies(headless=False):
            sys.exit(1)
        from scrutics.ui.tui import run
        run()
        return

    args = build_parser().parse_args()
    headless = not should_use_tui(args)

    if not check_dependencies(headless=headless):
        sys.exit(1)

    if not headless:
        import os
        if args.live:
            os.environ["SCRUTICS_AUTO_LIVE"]     = args.live
            os.environ["SCRUTICS_AUTO_DURATION"] = str(args.duration)
            os.environ["SCRUTICS_AUTO_BASELINE"] = str(args.baseline)
            os.environ["SCRUTICS_AUTO_OUTPUT"]   = args.output
        elif args.file:
            os.environ["SCRUTICS_AUTO_FILE"]   = args.file
            os.environ["SCRUTICS_AUTO_OUTPUT"] = args.output
        from scrutics.ui.tui import run
        run()
    else:
        sys.exit(run_headless(args))


if __name__ == "__main__":
    main()
