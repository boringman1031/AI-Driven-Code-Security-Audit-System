"""
知識庫攝入模組。

執行方式:
  python -m backend.rag.ingester           # 首次建立
  python -m backend.rag.ingester --rebuild  # 強制重建
  python -m backend.rag.ingester --fetch-cve  # 先抓取 CVE 再攝入
"""
import json
import argparse
from pathlib import Path
from backend.rag.vector_store import VectorStore
from backend.config import get_settings


def _load_json(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ingest_cwe(vs: VectorStore, knowledge_dir: str, rebuild: bool) -> None:
    if not rebuild and vs.collection_count("cwe") > 0:
        print("[RAG] CWE 知識庫已存在，跳過攝入。")
        return

    if rebuild:
        try:
            vs.delete_collection("cwe")
        except Exception:
            pass

    path = Path(knowledge_dir) / "cwe_entries.json"
    entries = _load_json(path)

    documents, metadatas, ids = [], [], []
    for entry in entries:
        doc = (
            f"CWE-{entry['id']}: {entry['name']}\n"
            f"描述: {entry['description']}\n"
            f"影響: {entry.get('impact', '')}\n"
            f"修復建議: {entry.get('mitigation', '')}"
        )
        documents.append(doc)
        metadatas.append({"cwe_id": f"CWE-{entry['id']}", "name": entry["name"]})
        ids.append(f"cwe-{entry['id']}")

    vs.add_documents("cwe", documents, metadatas, ids)
    print(f"[RAG] 已攝入 {len(documents)} 條 CWE 條目。")


def ingest_owasp(vs: VectorStore, knowledge_dir: str, rebuild: bool) -> None:
    if not rebuild and vs.collection_count("owasp") > 0:
        print("[RAG] OWASP 知識庫已存在，跳過攝入。")
        return

    if rebuild:
        try:
            vs.delete_collection("owasp")
        except Exception:
            pass

    path = Path(knowledge_dir) / "owasp_top10.json"
    entries = _load_json(path)

    documents, metadatas, ids = [], [], []
    for entry in entries:
        doc = (
            f"{entry['id']}: {entry['name']}\n"
            f"描述: {entry['description']}\n"
            f"風險: {entry.get('risk', '')}\n"
            f"防禦措施: {entry.get('prevention', '')}"
        )
        documents.append(doc)
        metadatas.append({"owasp_id": entry["id"], "name": entry["name"]})
        safe_id = entry["id"].replace(":", "").replace(" ", "-").lower()
        ids.append(f"owasp-{safe_id}")

    vs.add_documents("owasp", documents, metadatas, ids)
    print(f"[RAG] 已攝入 {len(documents)} 條 OWASP 條目。")


def ingest_cve(vs: VectorStore, knowledge_dir: str, rebuild: bool) -> None:
    """攝入 CVE 真實案例知識庫（需先執行 fetch_cve.py 產生 cve_entries.json）。"""
    if not rebuild and vs.collection_count("cve") > 0:
        print("[RAG] CVE 知識庫已存在，跳過攝入。")
        return

    if rebuild:
        try:
            vs.delete_collection("cve")
        except Exception:
            pass

    path = Path(knowledge_dir) / "cve_entries.json"
    if not path.is_file():
        print(f"[RAG] 找不到 {path}，跳過 CVE 攝入。請先執行 python -m backend.rag.fetch_cve")
        return

    entries = _load_json(path)

    documents, metadatas, ids = [], [], []
    for entry in entries:
        cwe_str = ", ".join(entry.get("cwe_ids", [])) or "未分類"
        doc = (
            f"{entry['cve_id']} (CVSS {entry.get('cvss_score', 0):.1f})\n"
            f"CWE 分類: {cwe_str}\n"
            f"攻擊向量: {entry.get('attack_vector', 'Unknown')}\n"
            f"受影響產品: {entry.get('affected_products', 'N/A')}\n"
            f"描述: {entry.get('description', '')}"
        )
        documents.append(doc)
        metadatas.append({
            "cve_id": entry["cve_id"],
            "cvss_score": float(entry.get("cvss_score", 0)),
            "cwe_ids": cwe_str,
            "attack_vector": entry.get("attack_vector", "Unknown"),
        })
        ids.append(entry["cve_id"].lower())

    vs.add_documents("cve", documents, metadatas, ids)
    print(f"[RAG] 已攝入 {len(documents)} 條 CVE 條目。")


def run_ingestion(rebuild: bool = False, fetch_cve: bool = False) -> None:
    if fetch_cve:
        from backend.rag.fetch_cve import fetch_cves
        from backend.config import get_settings as _gs
        _settings = _gs()
        output = str(Path(_settings.knowledge_dir) / "cve_entries.json")
        fetch_cves(dry_run=False, output_path=output)

    settings = get_settings()
    vs = VectorStore(settings.chroma_dir)
    ingest_cwe(vs, settings.knowledge_dir, rebuild)
    ingest_owasp(vs, settings.knowledge_dir, rebuild)
    ingest_cve(vs, settings.knowledge_dir, rebuild)
    print("[RAG] 知識庫攝入完成。")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="攝入安全知識庫到向量資料庫")
    parser.add_argument("--rebuild", action="store_true", help="強制重建，刪除現有資料")
    parser.add_argument("--fetch-cve", action="store_true", help="先從 NIST NVD API 抓取 CVE 再攝入")
    args = parser.parse_args()
    run_ingestion(rebuild=args.rebuild, fetch_cve=args.fetch_cve)
