"""Command-line interface for ViShare_Quick alpha_0.1."""

import argparse
import sys

from vishare_quick import __version__
from vishare_quick.diagnostics import run_diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vishare",
        description=(
            "ViShare_Quick: cross-platform CLI foundation for future "
            "Android Quick Share interoperability."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "doctor",
        help="show basic Python and operating-system diagnostics",
        description="Display basic environment diagnostics. No network scan is performed.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        for label, value in run_diagnostics():
            print(f"{label}: {value}")
        print("\nAlpha 0.1 is a foundation build. Quick Share discovery and file transfer are not implemented.")
        return 0

    # argparse shows help when explicitly requested; no command defaults to help.
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
