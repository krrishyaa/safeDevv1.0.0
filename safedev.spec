# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

streamlit_datas = collect_data_files("streamlit")
safedev_datas = collect_data_files("safedev")
extra_datas = [
    ("safedev/rules/rules.json", "safedev/rules"),
    ("safedev/ui/dashboard.py", "safedev/ui"),
]

hiddenimports = sorted(
    set(
        collect_submodules("streamlit")
        + collect_submodules("safedev")
        + [
            "pandas",
            "reportlab",
            "reportlab.lib",
            "reportlab.pdfbase",
            "reportlab.platypus",
        ]
    )
)

a = Analysis(
    ["safedev\\cli.py"],
    pathex=[],
    binaries=[],
    datas=streamlit_datas + safedev_datas + extra_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="safedev",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
