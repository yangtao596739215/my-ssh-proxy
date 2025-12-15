#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

: "${SERVER_ADDR:=127.0.0.1:2222}"
: "${BACKEN_USER:=proxy}"
: "${LOCAL_TARGET:=127.0.0.1:9000}"
: "${SSH_SERVER:=true}" # 默认开启内置 sshserver，便于 VS Code Remote-SSH

args=(
  -server "${SERVER_ADDR}"
  -user "${BACKEN_USER}"
  -local "${LOCAL_TARGET}"
)

if [[ "${SSH_SERVER}" == "true" ]]; then
  args+=(-sshserver)
fi

echo "[backen] starting server=${SERVER_ADDR} user=${BACKEN_USER} local=${LOCAL_TARGET} sshserver=${SSH_SERVER}"
echo "[backen] backend-key 将随机生成，查看日志获取"
exec go run ./cmd/backen "${args[@]}"


