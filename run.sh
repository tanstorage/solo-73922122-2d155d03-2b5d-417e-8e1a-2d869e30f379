#!/usr/bin/env bash
# 本机直接启动（Docker 方式见 docker-compose.yml）
# 默认两个工作进程，与容器部署一致；可用 WORKERS=1 ./run.sh 调整
set -euo pipefail
cd "$(dirname "$0")"
exec python3 -m uvicorn app.main:app \
  --host 0.0.0.0 --port "${PORT:-8000}" --workers "${WORKERS:-2}"
