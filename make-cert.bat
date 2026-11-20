@echo off
cd /d "%~dp0"
if not exist certs mkdir certs
where openssl >nul 2>nul || (echo openssl was not found. Install "Git for Windows" ^(it includes openssl^) or see README for mkcert. & pause & exit /b 1)
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do set IP=%%a
set IP=%IP: =%
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout certs\key.pem -out certs\cert.pem -subj "/CN=Prac360" -addext "subjectAltName=DNS:localhost,DNS:%COMPUTERNAME%,IP:127.0.0.1,IP:%IP%"
echo Done. Restart the server: it now uses HTTPS.
pause
