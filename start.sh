#!/bin/zsh
# Launch the local PS4 exploit host.
#   ./start.sh              -> http://<your-ip>:8080
#   ./start.sh --port 80    -> http://<your-ip>/   (will ask for sudo)
cd "$(dirname "$0")" || exit 1
exec python3 serve.py "$@"
