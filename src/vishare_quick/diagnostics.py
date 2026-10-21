"""Safe, basic environment diagnostics for ViShare_Quick."""

import platform
import sys

from vishare_quick import __version__


def run_diagnostics() -> list[tuple[str, str]]:
    """Return basic runtime diagnostics without probing the network."""
    return [
        ("Application", "ViShare_Quick"),
        ("Version", __version__),
        ("Operating system", platform.platform()),
        ("OS family", platform.system()),
        ("Architecture", platform.machine() or "unknown"),
        ("Python version", platform.python_version()),
        ("Python executable", sys.executable),
    ]
