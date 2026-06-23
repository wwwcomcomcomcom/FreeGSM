# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('h2')
hiddenimports += collect_submodules('hpack')
hiddenimports += collect_submodules('hyperframe')


a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=[('C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python312\\Lib\\site-packages\\pydivert\\windivert_dll\\WinDivert64.dll', 'pydivert/windivert_dll'), ('C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python312\\Lib\\site-packages\\pydivert\\windivert_dll\\WinDivert64.sys', 'pydivert/windivert_dll')],
    datas=[],
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
    name='FreeGSM-DoH',
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
    uac_admin=True,
)
