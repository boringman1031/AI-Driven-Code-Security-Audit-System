# AI 驅動的程式碼安全審查系統

**繁體中文** | [English](README.md)

本系統是一套概念驗證（PoC）工具，結合大型語言模型（LLM）與檢索增強生成（RAG）技術，自動偵測多種程式語言中的安全漏洞。

## 系統概述

SecureCodeReview 整合先進 LLM 能力與精選安全知識庫（CWE、OWASP Top 10、CVE），提供準確且具上下文感知的程式碼安全審查。系統支援雙後端架構（OpenAI GPT-4o-mini 與 Ollama 本地模型），並採用語言感知 Prompt v4 策略，根據偵測到的程式語言動態調整分析重點。

## 主要功能

- 多語言漏洞偵測：Python、JavaScript、TypeScript、Java、C/C++、PHP、Go、Rust 等
- 雙 LLM 後端：OpenAI API 或 Ollama 本地模型（隱私保護）
- RAG 知識庫：CWE Top 25、OWASP Top 10、50+ 條 NIST NVD 真實 CVE 案例
- 語言感知 Prompt v4：針對各程式語言的客製化分析策略，含 Self-Critique 步驟
- 多種輸入模式：程式碼片段、上傳檔案、GitHub Repository URL、本機目錄掃描
- 目錄掃描即時進度條（輪詢式 UI）
- 掃描歷史與 HTML 報告產生
- 嚴重程度篩選（Critical / High / Medium / Low）
- Docker Compose 一鍵部署

## 系統架構

```
使用者輸入（片段 / 檔案 / GitHub URL / 目錄）
        |
        v
  FastAPI 後端
        |
      +---+---+
      |       |
   RAG        LLM 分析器
  Retriever   （OpenAI / Ollama）
      |       |
   ChromaDB   Prompt v4
（CWE/OWASP   （語言感知
   /CVE）      + Self-Critique）
      |       |
      +---+---+
        |
        v
  HTML 報告 + JSON 結果
```

## 環境需求

- Docker 與 Docker Compose
- Python 3.11+（本機開發）
- OpenAI API Key（或本機安裝 Ollama）

## 快速啟動

### 方式一：Docker（推薦）

```bash
# 下載儲存庫
git clone https://github.com/boringman1031/AI-Driven-Code-Security-Audit-System.git
cd AI-Driven-Code-Security-Audit-System

# 設定環境變數
cp .env.example .env
# 編輯 .env，填入 OPENAI_API_KEY

# 使用 OpenAI 後端啟動
./start.sh

# 使用 Ollama 本地模型啟動
./start.sh --ollama

# Windows PowerShell
.\start.ps1
.\start.ps1 -Ollama
```

開啟瀏覽器，前往 http://localhost:8000。

### 方式二：本機開發

```bash
pip install -r requirements.txt
cp .env.example .env
# 編輯 .env

# 攝入知識庫
python -m backend.rag.ingester

# 選用：抓取 CVE 資料（約需 40 秒，公開速率限制）
python -m backend.rag.fetch_cve

# 啟動伺服器
uvicorn backend.main:app --reload --port 8000
```

## 知識庫

| 集合      | 來源                  | 條目數  |
|-----------|-----------------------|---------|
| CWE       | MITRE CWE             | 20+     |
| OWASP     | OWASP Top 10（2021）  | 10      |
| CVE       | NIST NVD API v2.0     | 50+     |

重新更新 CVE 知識庫：

```bash
python -m backend.rag.fetch_cve
python -m backend.rag.ingester --rebuild
```

## Prompt 設計（v4）

系統採用四代 Prompt 迭代演進：

| 版本 | 核心改進                                    |
|------|---------------------------------------------|
| v1   | 基礎漏洞偵測                                |
| v2   | 思維鏈（Chain-of-Thought）推理步驟          |
| v3   | Self-Critique 降低幻覺率                    |
| v4   | 語言感知分析，動態調整重點區域              |

各語言分析重點範例：
- C/C++：記憶體安全（CWE-787、CWE-416、CWE-125），資料流追蹤
- Python/JavaScript：注入攻擊（CWE-89、CWE-78），不安全反序列化
- Java：反序列化（CWE-502），XXE（CWE-611），存取控制
- PHP：檔案包含、任意上傳（CWE-434），CSRF

## 評估結果

系統包含涵蓋 6 種程式語言的 50 案例評估框架：

| 語言                | 含漏洞 | 無漏洞 | 合計 |
|---------------------|-------|-------|------|
| Python              | 8     | 4     | 12   |
| JavaScript/TypeScript | 6   | 3     | 9    |
| Java                | 5     | 3     | 8    |
| C/C++               | 6     | 3     | 9    |
| PHP                 | 4     | 3     | 7    |
| Go/Rust             | 3     | 2     | 5    |
| **合計**            | **32**| **18**| **50**|

目標指標：Precision >= 0.83、Recall >= 0.80、F1 >= 0.82、CWE 匹配率 >= 0.80

執行評估：

```bash
python -m backend.eval.run_eval --backend openai
python -m backend.eval.limitations
```

## 架構限制分析

| 限制類別       | 具體描述                                          | 緩解策略                        |
|----------------|---------------------------------------------------|---------------------------------|
| LLM 幻覺率     | 約 4.2% 的 CWE ID 為無效引用                     | Self-Critique 步驟（Prompt v3+）|
| 分析延遲       | GPT-4o-mini：3-8 秒/檔；Ollama：45-90 秒/檔      | 非同步背景處理                  |
| Token 成本     | 30 案例評估約 $0.18 USD                           | 截斷策略 + 摘要前處理           |
| 語言偏差       | C/C++ F1 約 0.50，Python F1 約 0.89               | 語言感知 Prompt v4              |
| 脈絡視窗       | 每檔案截斷至 12,000 字元                          | 未來工作：滑動視窗分塊          |
| RAG 精度       | Top-4 結果中約 1 條無關                           | 未來工作：Reranker 模型         |

## 專案結構

```
.
├── backend/
│   ├── analyzer/          # LLM 分析器模組（OpenAI / Ollama）
│   │   ├── language_focus.py  # Prompt v4 語言感知重點
│   │   ├── openai_analyzer.py
│   │   └── ollama_analyzer.py
│   ├── eval/              # 評估框架
│   │   ├── ground_truth.py    # 50 案例 ground truth
│   │   ├── run_eval.py        # 評估執行腳本
│   │   └── limitations.py    # 架構限制分析
│   ├── input_handler/     # 程式碼輸入模組
│   ├── rag/               # 檢索增強生成
│   │   ├── fetch_cve.py   # NIST NVD CVE 抓取器
│   │   ├── ingester.py    # 知識庫攝入
│   │   ├── retriever.py   # 上下文檢索
│   │   └── vector_store.py
│   ├── reporter/          # HTML 報告產生
│   ├── routers/           # FastAPI 端點
│   └── main.py
├── frontend/              # Web UI（原生 JavaScript）
├── knowledge/             # CWE 與 OWASP JSON 資料
├── templates/             # Jinja2 HTML 報告範本
├── tests/eval/samples/    # 50 個評估程式碼樣本
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── start.sh               # Linux/macOS 啟動腳本
└── start.ps1              # Windows PowerShell 啟動腳本
```

## API 端點

| 方法   | 路徑                         | 說明                             |
|--------|------------------------------|----------------------------------|
| POST   | /api/scan                    | 掃描程式碼片段或 GitHub URL      |
| POST   | /api/scan/upload             | 上傳並掃描單一檔案               |
| POST   | /api/scan/directory          | 提交目錄掃描（非同步）           |
| GET    | /api/scan/{scan_id}/status   | 查詢目錄掃描進度                 |
| GET    | /api/reports                 | 列出所有掃描報告                 |
| GET    | /api/reports/{scan_id}       | 取得 HTML 報告                   |
| GET    | /health                      | 健康檢查                         |
| GET    | /docs                        | 互動式 API 文件                  |

## 技術堆疊

- 後端：FastAPI、LangChain、ChromaDB
- LLM：OpenAI GPT-4o-mini / Ollama（codellama:7b）
- RAG：ChromaDB 向量資料庫、sentence-transformers 嵌入
- 前端：原生 HTML/CSS/JavaScript
- 容器化：Docker、Docker Compose

## 授權

本專案為學術用途之概念驗證系統。
