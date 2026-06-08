#!/usr/bin/env bash
# ============================================================
# SecureCodeReview — 一鍵啟動腳本（Linux / macOS / WSL）
# 使用方式:
#   ./start.sh              # OpenAI 後端
#   ./start.sh --ollama     # 含 Ollama 本地模型
#   ./start.sh --ingest     # 強制重建知識庫（含 CVE）
#   ./start.sh --eval       # 執行 50 案例評估
# ============================================================
set -euo pipefail

OLLAMA_PROFILE=false
INGEST_CVE=false
RUN_EVAL=false

for arg in "$@"; do
  case $arg in
    --ollama)  OLLAMA_PROFILE=true ;;
    --ingest)  INGEST_CVE=true ;;
    --eval)    RUN_EVAL=true ;;
  esac
done

echo "=== SecureCodeReview 啟動 ==="

# 1. 確認 .env 存在
if [ ! -f ".env" ]; then
  echo "[!] 找不到 .env，從 .env.example 複製..."
  cp .env.example .env
  echo "[!] 請編輯 .env 填入 OPENAI_API_KEY 後重新執行。"
  exit 1
fi

# 2. 拉取 CVE 知識庫（選用）
if [ "$INGEST_CVE" = true ]; then
  echo "[CVE] 抓取 CVE 知識庫（需要 30+ 秒）..."
  python -m backend.rag.fetch_cve
  echo "[CVE] CVE 資料已下載。"
fi

# 3. 啟動 Docker Compose
if [ "$OLLAMA_PROFILE" = true ]; then
  echo "[Docker] 啟動含 Ollama 的完整服務..."
  docker-compose --profile ollama up -d
  echo "[Ollama] 等待 Ollama 啟動..."
  sleep 10
  docker exec "$(docker-compose ps -q ollama)" ollama pull codellama:7b || true
else
  echo "[Docker] 啟動 OpenAI 後端服務..."
  docker-compose up -d backend
fi

# 4. 等待後端就緒
echo "[健康檢查] 等待後端服務..."
for i in $(seq 1 20); do
  if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo "[✓] 後端就緒！"
    break
  fi
  echo "  嘗試 $i/20..."
  sleep 3
done

# 5. 執行評估（選用）
if [ "$RUN_EVAL" = true ]; then
  echo "[評估] 執行 50 案例評估..."
  BACKEND=$(grep "^LLM_BACKEND" .env | cut -d'=' -f2 | tr -d '[:space:]')
  BACKEND=${BACKEND:-openai}
  docker-compose exec backend python -m backend.eval.run_eval --backend "$BACKEND"
fi

echo ""
echo "=== 啟動完成 ==="
echo "  Web UI:    http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
if [ "$OLLAMA_PROFILE" = true ]; then
  echo "  Ollama:    http://localhost:11434"
fi
echo ""
echo "停止服務: docker-compose down"
