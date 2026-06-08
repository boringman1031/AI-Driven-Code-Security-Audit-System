"""
從 NIST NVD REST API v2.0 抓取 CVE 資料，儲存至 knowledge/cve_entries.json。

使用方式:
  python -m backend.rag.fetch_cve              # 抓取並儲存
  python -m backend.rag.fetch_cve --dry-run    # 僅顯示條目數，不寫入檔案

公開模式（無 API Key）每 6 秒最多一次請求。
"""

import json
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 搜尋關鍵字與對應 CWE 分類（確保覆蓋不同語言的漏洞類型）
_QUERIES: list[dict] = [
    {"keyword": "buffer overflow",     "severity": "CRITICAL", "limit": 10},
    {"keyword": "SQL injection",       "severity": "CRITICAL", "limit": 10},
    {"keyword": "cross-site scripting","severity": "HIGH",     "limit": 8},
    {"keyword": "deserialization",     "severity": "CRITICAL", "limit": 8},
    {"keyword": "path traversal",      "severity": "HIGH",     "limit": 7},
    {"keyword": "command injection",   "severity": "CRITICAL", "limit": 7},
]

_DELAY_SECONDS = 6  # 公開模式速率限制：每 6 秒一次


def _fetch_page(keyword: str, severity: str, limit: int) -> list[dict]:
    """呼叫 NVD API 抓取一頁 CVE，回傳原始 vulnerabilities 清單。"""
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "cvssV3Severity": severity,
        "resultsPerPage": limit,
    })
    url = f"{NVD_BASE}?{params}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecureCodeReview-CVE-Fetcher/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return payload.get("vulnerabilities", [])
    except urllib.error.HTTPError as e:
        print(f"  [警告] HTTP {e.code} — {keyword} ({severity}) 略過")
        return []
    except Exception as e:  # noqa: BLE001
        print(f"  [警告] 請求失敗 — {e}")
        return []


def _parse_entry(vuln: dict) -> dict | None:
    """將 NVD 原始結構轉換為精簡的 CVE 條目，失敗回傳 None。"""
    try:
        cve = vuln["cve"]
        cve_id: str = cve["id"]

        # 描述（取英文）
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )

        # CVSS v3 分數
        cvss_score: float = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            items = metrics.get(key, [])
            if items:
                cvss_score = items[0].get("cvssData", {}).get("baseScore", 0.0)
                break

        # CWE 對應
        cwe_ids: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val: str = wd.get("value", "")
                if val.startswith("CWE-") and val != "CWE-noinfo":
                    cwe_ids.append(val)

        # 受影響產品（取前三個）
        affected: list[str] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected.append(f"{parts[3]} {parts[4]}")
                        if len(affected) >= 3:
                            break
                if len(affected) >= 3:
                    break
            if len(affected) >= 3:
                break

        # 攻擊向量
        attack_vector = "Unknown"
        for key in ("cvssMetricV31", "cvssMetricV30"):
            items = metrics.get(key, [])
            if items:
                attack_vector = items[0].get("cvssData", {}).get("attackVector", "Unknown")
                break

        return {
            "cve_id": cve_id,
            "description": desc[:1000],  # 截斷至 1000 字元
            "cwe_ids": list(dict.fromkeys(cwe_ids)),  # 去重
            "cvss_score": cvss_score,
            "affected_products": ", ".join(affected) if affected else "N/A",
            "attack_vector": attack_vector,
        }
    except (KeyError, TypeError, IndexError):
        return None


def fetch_cves(dry_run: bool = False, output_path: str = "knowledge/cve_entries.json") -> list[dict]:
    """主要抓取流程，回傳所有解析成功的 CVE 條目。"""
    all_entries: list[dict] = []
    seen_ids: set[str] = set()

    for i, q in enumerate(_QUERIES):
        keyword = q["keyword"]
        severity = q["severity"]
        limit = q["limit"]

        print(f"[CVE] 抓取 '{keyword}' (severity={severity}, limit={limit})...")
        vulns = _fetch_page(keyword, severity, limit)

        count = 0
        for v in vulns:
            entry = _parse_entry(v)
            if entry and entry["cve_id"] not in seen_ids:
                seen_ids.add(entry["cve_id"])
                all_entries.append(entry)
                count += 1

        print(f"  ✓ 取得 {count} 條（累計 {len(all_entries)}）")

        # 速率限制：最後一批不需等待
        if i < len(_QUERIES) - 1:
            print(f"  [速率限制] 等待 {_DELAY_SECONDS} 秒...")
            time.sleep(_DELAY_SECONDS)

    print(f"\n[CVE] 共抓取 {len(all_entries)} 條 CVE 條目。")

    if not dry_run:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=2)
        print(f"[CVE] 已儲存至 {output_path}")

    return all_entries


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="從 NIST NVD API 抓取 CVE 知識庫")
    parser.add_argument("--dry-run", action="store_true", help="僅顯示條目數，不寫入檔案")
    parser.add_argument("--output", default="knowledge/cve_entries.json", help="輸出 JSON 路徑")
    args = parser.parse_args()
    fetch_cves(dry_run=args.dry_run, output_path=args.output)
