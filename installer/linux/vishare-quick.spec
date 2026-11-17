import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
datas = collect_data_files("vishare_quick.ui")

a = Analysis(
    [str(ROOT / "src/vishare_quick/__main__.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "webview.platforms.gtk",
        "gi.repository.WebKit2",
        "gi.repository.Soup",
    ],
    hookspath=[str(ROOT / "installer/linux")],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
a.binaries = [
    binary
    for binary in a.binaries
    if os.path.basename(binary[0]) not in {"libstdc++.so.6", "libgcc_s.so.1"}
]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="vishare-quick",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
