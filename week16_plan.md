# Week 16 Final Delivery Plan
## SecureCodeReview — AI-Driven Code Security Audit System

> **截止日期：** Week 16 Final Deadline  
> **交付類型：** Final Integrated Report & PoC Artifact（共同團隊提交）  
> **目標等級：** Outstanding (O) — 觸發自動回溯升等 Week 14 / 15

---

## 一、交付物清單

| 交付物 | 形式 | 說明 |
|---|---|---|
| Final Integrated Report | PDF / HTML | 系統設計、評估結果、架構限制，全面整合 |
| PoC Artifact | 可執行系統 | Docker Compose 一鍵啟動，含 Demo 腳本 |
| 評估結果資料 | JSON / CSV | 30+ 測試案例的量化結果 |

---

## 二、距離 Outstanding 還差什麼？

從 Week 14 / 15 的基礎出發，下表列出 Outstanding 等級需補齊的項目：

| 面向 | 當前狀態 | Week 16 目標 |
|---|---|---|
| 知識庫 | CWE 20 條 + OWASP 10 條 | **新增 CVE 真實案例 50 條**（NIST NVD API） |
| Prompt | v3（Self-Critique） | **v4（語言感知，動態分析策略）** |
| 前端 | 基本 UI（3 個輸入 Tab） | **補完目錄掃描進度條 + 掃描歷史** |
| 評估指標 | F1 0.79（30 案例） | **擴充至 50 案例，F1 目標 ≥ 0.82** |
| 架構限制分析 | 無 | **新增：幻覺率、延遲、Token 成本分析** |
| Docker | 基本 Dockerfile | **完整 docker-compose + 一鍵啟動腳本** |
| 整合報告 | 無 | **Week 16 核心產出** |

---

## 三、分工實作計畫

### Phase A：CVE 知識庫攝入（新增功能）

**目標：** 擴充 RAG 知識庫，加入真實 CVE 案例，提升 CWE 匹配率（0.73 → 目標 0.82）

**實作路徑：** `backend/rag/ingester.py` 新增 `ingest_cve()` 函數

```python
# 使用 NIST NVD REST API v2.0
# https://services.nvd.nist.gov/rest/json/cves/2.0

GET https://services.nvd.nist.gov/rest/json/cves/2.0?
    keywordSearch=buffer+overflow&
    cvssV3Severity=CRITICAL&
    resultsPerPage=20
```

**攝入內容格式：**
```json
{
  "cve_id": "CVE-2021-44228",
  "description": "...",
  "cwe_ids": ["CWE-917"],
  "cvss_score": 10.0,
  "affected_products": "Apache Log4j 2.x",
  "attack_vector": "Network"
}
```

**預計條目：** 50 條高影響 CVE（CVSS ≥ 7.0）

---

### Phase B：Prompt v4 — 語言感知分析策略

**核心改進：** 根據程式碼語言，動態調整 Prompt 的分析重點

```
偵測語言
    │
    ├─ C / C++    → 強化：記憶體安全分析
    │               重點 CWE：CWE-416、CWE-787、CWE-125、CWE-190
    │               增加資料流追蹤步驟（malloc → use → free 路徑）
    │
    ├─ Python /   → 強化：注入攻擊 + 依賴安全
    │  JavaScript    重點 CWE：CWE-89、CWE-78、CWE-79、CWE-94
    │
    ├─ Java       → 強化：反序列化 + 存取控制
    │               重點 CWE：CWE-502、CWE-306、CWE-611
    │
    └─ PHP        → 強化：Web 特定攻擊面
                    重點 CWE：CWE-22、CWE-434、CWE-352
```

**實作位置：** `backend/analyzer/openai_analyzer.py`

---

### Phase C：前端補完

**新增功能（`frontend/`）：**

1. **目錄掃描進度條**
   - `POST /api/scan/directory` 端點回傳 `scan_id`
   - 前端輪詢 `GET /api/scan/{scan_id}/status`
   - 顯示「已掃描 X / Y 個檔案」進度條

2. **掃描歷史**
   - 讀取 `data/reports/` 目錄，列出所有過往報告
   - `GET /api/reports` 回傳報告清單

3. **UI 細節**
   - 掃描完成後自動展開第一個 Critical 漏洞卡片
   - 支援依嚴重程度篩選漏洞

---

### Phase D：架構限制分析（報告必備章節）

這是 Outstanding 報告的關鍵區別因素，需誠實記錄系統的限制：

| 限制類別 | 具體描述 | 量化數據 | 緩解策略 |
|---|---|---|---|
| **LLM 幻覺率** | 模型可能產生不存在的 CWE ID 或錯誤的行號 | 約 4.2%（12/285 個 Finding） | Self-Critique 步驟部分緩解 |
| **分析延遲** | GPT-4o-mini 平均每檔案 3-8 秒 | Ollama 本機約 45-90 秒/檔 | 批次非同步處理（Week 16 改進） |
| **Token 成本** | 30 案例評估消耗約 $0.18 USD | 大型 Repo 掃描可達 $1-3 | 截斷策略 + 摘要前處理 |
| **語言偏差** | 訓練資料以英語程式碼為主 | C/C++ F1 0.50 vs Python F1 0.89 | 語言感知 Prompt（Phase B） |
| **脈絡視窗** | 單一檔案截斷 12,000 字元 | 大型檔案可能漏掉後段漏洞 | 滑動視窗分塊（未來工作） |
| **RAG 精度** | ChromaDB 語意搜尋可能帶入不相關的 CWE | Top-4 結果中約 1 條無關 | Reranker 模型（未來工作） |

---

### Phase E：整合評估（50 案例）

擴充測試集，確保評估結果的統計顯著性：

| 語言 | 有漏洞案例 | 無漏洞案例 | 合計 |
|---|---|---|---|
| Python | 8 | 4 | 12 |
| JavaScript / TypeScript | 6 | 3 | 9 |
| Java | 5 | 3 | 8 |
| C / C++ | 6 | 3 | 9 |
| PHP | 4 | 3 | 7 |
| Go / Rust / 其他 | 3 | 2 | 5 |
| **合計** | **32** | **18** | **50** |

**目標指標：**
- Precision ≥ 0.83
- Recall ≥ 0.80
- F1 ≥ 0.82
- CWE Match Rate ≥ 0.80

---

## 四、Final Integrated Report 章節規劃

> 作業要求：覆蓋「完整系統設計、安全評估結果、架構限制」

| 章節 | 內容 | 預計頁數 |
|---|---|---|
| 1. 摘要 | 系統概述、主要成就、核心指標 | 0.5 |
| 2. 問題背景與動機 | 傳統靜態分析的不足、LLM 的機會 | 1.0 |
| 3. 相關工作 | VulBERTa、LineVul、ChatGPT for Vuln Detection | 1.5 |
| 4. 系統設計 | 完整架構圖、每個模組設計決策 | 2.0 |
| 5. 實作細節 | Prompt 設計迭代、RAG 知識庫策展、雙後端切換 | 2.0 |
| 6. 評估結果 | 50 案例量化結果、錯誤案例分析、對比基準 | 2.0 |
| 7. 架構限制 | 幻覺率、延遲、Token 成本、語言偏差 | 1.5 |
| 8. 未來工作 | 滑動視窗、Reranker、CI/CD 整合 | 0.5 |
| 9. 結論 | 貢獻總結 | 0.5 |
| 參考文獻 | 8+ 篇 | 0.5 |
| **總計** | | **~12 頁** |

---

## 五、每日進度追蹤

```
Week 16
│
├─ Day 1-2：Phase A — CVE 知識庫攝入（ingest_cve 實作 + 測試）
│
├─ Day 3：Phase B — Prompt v4 語言感知（實作 + A/B 測試）
│
├─ Day 4：Phase C — 前端補完（目錄掃描進度條 + 歷史）
│
├─ Day 5-6：Phase D + E — 架構限制分析 + 50 案例評估
│
└─ Day 7：整合報告撰寫 + Docker 最終測試
```

---

## 六、Docker 一鍵啟動腳本（Phase F）

最終 PoC 示範方式：

```bash
# 1. 設定環境
copy .env.example .env
# 填入 OPENAI_API_KEY

# 2. 啟動（OpenAI 後端）
docker-compose up backend

# 3. 啟動（含 Ollama 本地模型）
docker-compose --profile ollama up

# 4. 開啟 Web UI
# http://localhost:8000
```

---

## 七、Outstanding 評分要素對應

根據作業要求，以下確認 Outstanding 等級的核心要素覆蓋狀況：

| 評分面向 | 對應實作 | 狀態 |
|---|---|---|
| Advanced Technical Application | LangChain RAG + Dual LLM Backend + FastAPI | ✓ Week 14/15 |
| Prompt Methodology | CoT + Self-Critique + 語言感知（v1→v4） | ⚙ v4 Week 16 |
| Real-world Security Challenge | 多語言漏洞偵測，覆蓋 CWE Top 25 | ✓ Week 14/15 |
| System Design Documentation | 完整架構圖 + 設計決策說明 | 📋 Week 16 報告 |
| Security Evaluation Results | 50 案例 Precision/Recall/F1 | 📋 Week 16 |
| Architectural Limitations | 6 類限制量化分析 | 📋 Week 16 報告 |
| PoC Artifact | Docker Compose 可執行系統 | ⚙ Week 16 完善 |
