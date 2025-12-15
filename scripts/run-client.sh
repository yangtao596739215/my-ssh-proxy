#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

: "${SERVER_ADDR:=127.0.0.1:2222}"
: "${LISTEN_ADDR:=127.0.0.1:9000}"

if [[ -z "${BACKEND_KEY:-}" ]]; then
  echo "ERROR: 需要设置 BACKEND_KEY（来自 backen 启动日志）" >&2
  exit 1
fi

echo "[client] starting server=${SERVER_ADDR} backend-key=${BACKEND_KEY} listen=${LISTEN_ADDR}"
exec go run ./cmd/client \
  -server "${SERVER_ADDR}" \
  -backend-key "${BACKEND_KEY}" \
  -listen "${LISTEN_ADDR}"


