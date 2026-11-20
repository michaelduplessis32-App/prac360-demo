#!/bin/sh
# Makes a self-signed HTTPS certificate for this computer (needs openssl). Browsers will warn once; choose "Advanced → Continue".
cd "$(dirname "$0")"; mkdir -p certs
IP=$(hostname -I 2>/dev/null | awk '{print $1}'); [ -z "$IP" ] && IP=$(ipconfig getifaddr en0 2>/dev/null)
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout certs/key.pem -out certs/cert.pem -subj "/CN=Prac360" \
  -addext "subjectAltName=DNS:localhost,DNS:$(hostname),IP:127.0.0.1${IP:+,IP:$IP}" && echo "Done. Restart the server: it now uses HTTPS."
