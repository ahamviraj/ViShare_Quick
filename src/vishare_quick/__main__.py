"""Allow running with: python -m vishare_quick.

A frozen executable launched without arguments opens the local receiver
interface, so a file-manager double-click does something useful instead of
printing help and closing the console.
"""

import sys

from vishare_quick.cli import main


def should_open_ui(argv: list[str], *, frozen: bool) -> bool:
    """True for the file-manager launch of a frozen build."""
    return frozen and len(argv) == 1


def pause_if_double_clicked(
    argv: list[str],
    *,
    frozen: bool,
    interactive: bool,
) -> bool:
    """Keep a double-clicked executable's console open after printing help.

    This is retained for callers that intentionally run the help path without
    the graphical interface. Pause only when frozen, no arguments are present,
    and a real terminal is attached on both ends, so piped and scripted
    invocations never block.
    """
    if not (frozen and len(argv) == 1 and interactive):
        return False
    try:
        input("\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass
    return True


def _is_interactive() -> bool:
    try:
        return bool(
            sys.stdin is not None
            and sys.stdout is not None
            and sys.stdin.isatty()
            and sys.stdout.isatty()
        )
    except (AttributeError, OSError, ValueError):
        return False


if __name__ == "__main__":
    frozen = bool(getattr(sys, "frozen", False))
    opens_ui = should_open_ui(sys.argv, frozen=frozen)
    exit_code = main(["ui"] if opens_ui else None)
    if not opens_ui:
        pause_if_double_clicked(
            sys.argv,
            frozen=frozen,
            interactive=_is_interactive(),
        )
    raise SystemExit(exit_code)
