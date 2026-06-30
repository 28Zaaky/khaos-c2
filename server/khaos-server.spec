import sys as _sys

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('config.yaml', '.'),
        ('khaos.db',    '.'),
        ('routers',     'routers'),
        ('models',      'models'),
        ('services',    'services'),
    ],
    hiddenimports=[
        'uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto',
        'uvicorn.loops.asyncio', 'uvicorn.protocols', 'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto', 'uvicorn.protocols.http.h11_impl',
        'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto',
        'uvicorn.protocols.websockets.websockets_impl',
        'uvicorn.lifespan', 'uvicorn.lifespan.on', 'uvicorn.lifespan.off',
        'uvicorn.config', 'uvicorn.main',
        'anyio', 'anyio._backends._asyncio', 'anyio._backends._trio',
        'asyncio', 'email.mime.text', 'email.mime.multipart',
        'starlette', 'starlette.middleware.cors',
        'sqlalchemy.dialects.sqlite', 'sqlalchemy.pool',
        'passlib', 'jose', 'jose.jwt',
        'cryptography', 'cryptography.hazmat.primitives.hashes',
        'multipart', 'python_multipart',
        'routers.auth', 'routers.beacon', 'routers.agents',
        'routers.tasks', 'routers.build', 'routers.stage', 'routers.creds',
        'models.agent', 'models.user',
        'services.agent_manager', 'services.channel_reader',
        'services.dns_server', 'services.ws_manager', 'services.crypto',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='khaos-server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=_sys.platform != 'win32',  # False sur Windows, True sur Linux
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
