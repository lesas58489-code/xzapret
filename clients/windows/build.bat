@echo off
REM Build XZAP Client .exe for Windows
REM Requirements: pip install pyinstaller cryptography

echo Building XZAP Client...

cd /d "%~dp0\..\..\"

python -m PyInstaller --onefile --windowed ^
    --name "XZAP Client" ^
    --add-data "lists;lists" ^
    --add-data "xzap;xzap" ^
    --hidden-import xzap.client ^
    --hidden-import xzap.tunnel ^
    --hidden-import xzap.crypto ^
    --hidden-import xzap.socks5 ^
    --hidden-import xzap.routing ^
    --hidden-import xzap.tls ^
    --hidden-import xzap.transport.fragmented ^
    --hidden-import xzap.transport.tcp ^
    --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
    clients/windows/xzap_client.pyw

echo.
if exist "dist\XZAP Client.exe" (
    echo SUCCESS: dist\XZAP Client.exe
    echo Copy "XZAP Client.exe" to any Windows PC — no Python needed.
) else (
    echo FAILED — check errors above.
)
pause
