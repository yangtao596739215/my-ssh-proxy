#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

: "${PORT:=2222}"
: "${SOCKET_DIR:=/tmp/my-ssh-proxy}"
: "${ALLOW_BOOTSTRAP:=true}"

echo "[server] starting port=${PORT} socket-dir=${SOCKET_DIR} allow-bootstrap=${ALLOW_BOOTSTRAP}"
exec go run ./cmd/server \
  -port "${PORT}" \
  -socket-dir "${SOCKET_DIR}" \
  -allow-bootstrap="${ALLOW_BOOTSTRAP}"


