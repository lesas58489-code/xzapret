@echo off
echo XZAP via Cloudflare (SSH tunnel to Warsaw)
echo SOCKS5 proxy: 127.0.0.1:1080
echo.
echo Configure browser proxy: SOCKS5 127.0.0.1:1080
echo Press Ctrl+C to stop.
echo.
ssh -N -D 1080 warsaw
pause
