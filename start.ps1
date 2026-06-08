# ==============================================================
# SecureCodeReview — 一鍵啟動腳本（Windows PowerShell）
# 使用方式:
#   .\start.ps1              # OpenAI 後端
#   .\start.ps1 -Ollama      # 含 Ollama 本地模型
#   .\start.ps1 -Ingest      # 強制重建知識庫（含 CVE）
#   .\start.ps1 -Eval        # 執行 50 案例評估
# ==============================================================
param(
    [switch]$Ollama,
    [switch]$Ingest,
    [switch]$Eval
)

$ErrorActionPreference = "Stop"

Write-Host "=== SecureCodeReview 啟動 ===" -ForegroundColor Cyan

# 1. 確認 .env 存在
if (-not (Test-Path ".env")) {
    Write-Host "[!] 找不到 .env，從 .env.example 複製..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "[!] 請編輯 .env 填入 OPENAI_API_KEY 後重新執行。" -ForegroundColor Red
    exit 1
}

# 2. 拉取 CVE 知識庫（選用）
if ($Ingest) {
    Write-Host "[CVE] 抓取 CVE 知識庫（需要 30+ 秒，使用公開模式速率限制）..." -ForegroundColor Yellow
    python -m backend.rag.fetch_cve
    Write-Host "[CVE] CVE 資料已下載。" -ForegroundColor Green
}

# 3. 啟動 Docker Compose
if ($Ollama) {
    Write-Host "[Docker] 啟動含 Ollama 的完整服務..." -ForegroundColor Cyan
    docker-compose --profile ollama up -d
    Write-Host "[Ollama] 等待 Ollama 啟動（30s）..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    $ollamaId = docker-compose ps -q ollama
    if ($ollamaId) {
        docker exec $ollamaId ollama pull codellama:7b
    }
} else {
    Write-Host "[Docker] 啟動 OpenAI 後端服務..." -ForegroundColor Cyan
    docker-compose up -d backend
}

# 4. 等待後端就緒
Write-Host "[健康檢查] 等待後端服務..." -ForegroundColor Yellow
$ready = $false
for ($i = 1; $i -le 20; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -eq 200) {
            Write-Host "[✓] 後端就緒！" -ForegroundColor Green
            $ready = $true
            break
        }
    } catch {}
    Write-Host "  嘗試 $i/20..." -ForegroundColor Gray
    Start-Sleep -Seconds 3
}

if (-not $ready) {
    Write-Host "[警告] 後端未在預期時間內就緒，請檢查 docker-compose logs backend" -ForegroundColor Red
}

# 5. 執行評估（選用）
if ($Eval) {
    Write-Host "[評估] 執行 50 案例評估..." -ForegroundColor Cyan
    $backendVal = (Get-Content ".env" | Select-String "^LLM_BACKEND").ToString().Split("=")[1].Trim()
    if (-not $backendVal) { $backendVal = "openai" }
    docker-compose exec backend python -m backend.eval.run_eval --backend $backendVal
}

Write-Host ""
Write-Host "=== 啟動完成 ===" -ForegroundColor Green
Write-Host "  Web UI:    http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs:  http://localhost:8000/docs" -ForegroundColor White
if ($Ollama) {
    Write-Host "  Ollama:    http://localhost:11434" -ForegroundColor White
}
Write-Host ""
Write-Host "停止服務: docker-compose down" -ForegroundColor Gray
