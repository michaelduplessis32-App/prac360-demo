#!/bin/sh
cd "$(dirname "$0")"
command -v node >/dev/null 2>&1 || { echo "Node.js is not installed. Install the LTS version from https://nodejs.org and run this again."; exit 1; }
node server.js
