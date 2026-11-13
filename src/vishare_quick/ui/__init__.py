"""Static resources for the local ViShare Quick interface."""

from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"

__all__ = ["STATIC_DIR"]
