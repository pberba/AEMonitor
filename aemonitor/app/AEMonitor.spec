# PyInstaller spec for AEMonitor.app. From the repository root:
#   uv run --group app pyinstaller --noconfirm aemonitor/app/AEMonitor.spec
# Set AEMONITOR_CODESIGN_IDENTITY to sign with a Developer ID; otherwise the bundle is
# ad-hoc signed and only meant to run on the machine that built it.
import os
import tomllib

from PyInstaller.utils.hooks import collect_data_files

ROOT = os.path.dirname(os.path.dirname(SPECPATH))
with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
    VERSION = tomllib.load(f)["project"]["version"]

a = Analysis(
    [os.path.join(SPECPATH, "__main__.py")],
    pathex=[ROOT],
    # The decompiler's terminology tables are package data, not imports
    datas=collect_data_files("applescript_decompiler"),
    excludes=["pytest", "tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AEMonitor",
    console=False,
    codesign_identity=os.environ.get("AEMONITOR_CODESIGN_IDENTITY"),
)
coll = COLLECT(exe, a.binaries, a.datas, name="AEMonitor")
app = BUNDLE(
    coll,
    name="AEMonitor.app",
    bundle_identifier="io.github.pberba.aemonitor",
    version=VERSION,
    info_plist={
        "CFBundleShortVersionString": VERSION,
        "LSMinimumSystemVersion": "12.0",
    },
)
