"""Allow running with: python -m vishare_quick."""

import sys

from vishare_quick.cli import main


def pause_if_double_clicked(
    argv: list[str],
    *,
    frozen: bool,
    interactive: bool,
) -> bool:
    """Keep a double-clicked executable's console open after printing help.

    A frozen one-file build launched from a file manager has no arguments, so
    the CLI prints its help and exits, closing the new console window before it
    can be read. Pause only for that case: frozen, no arguments, and a real
    terminal on both ends, so piped and scripted invocations never block.
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
    exit_code = main()
    pause_if_double_clicked(
        sys.argv,
        frozen=bool(getattr(sys, "frozen", False)),
        interactive=_is_interactive(),
    )
    raise SystemExit(exit_code)
