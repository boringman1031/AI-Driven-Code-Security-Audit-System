"""
50 案例評估執行腳本（Phase E）。

功能：
  - 對 tests/eval/samples/ 下的測試程式碼執行掃描
  - 計算 Precision、Recall、F1、CWE Match Rate
  - 輸出結果至 data/eval_results/eval_results.json

使用方式:
  python -m backend.eval.run_eval --backend openai
  python -m backend.eval.run_eval --backend ollama --output data/eval_results
"""
import argparse
import json
import time
from pathlib import Path
from collections import defaultdict

from backend.eval.ground_truth import GROUND_TRUTH
from backend.analyzer.openai_analyzer import OpenAIAnalyzer
from backend.analyzer.ollama_analyzer import OllamaAnalyzer
from backend.rag.vector_store import VectorStore
from backend.rag.retriever import Retriever
from backend.config import get_settings

SAMPLES_DIR = Path("tests/eval/samples")


def _make_analyzer(backend: str):
    return OllamaAnalyzer() if backend == "ollama" else OpenAIAnalyzer()


def _make_retriever() -> Retriever:
    s = get_settings()
    return Retriever(VectorStore(s.chroma_dir))


def _cwe_match(predicted_cwes: list[str], expected_cwes: list[str]) -> bool:
    """預測的 CWE 是否覆蓋至少一個期望的 CWE。"""
    pred_set = set(predicted_cwes)
    exp_set = set(expected_cwes)
    return bool(pred_set & exp_set)


def run_eval(backend: str = "openai", output_dir: str = "data/eval_results") -> dict:
    analyzer = _make_analyzer(backend)
    retriever = _make_retriever()
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    tp = fp = fn = tn = 0
    cwe_match_count = 0
    cwe_total_vuln = 0

    results: list[dict] = []
    timing_records: list[dict] = []
    code_samples: list[str] = []
    errors: list[str] = []

    lang_tp: dict[str, int] = defaultdict(int)
    lang_fp: dict[str, int] = defaultdict(int)
    lang_fn: dict[str, int] = defaultdict(int)
    lang_tn: dict[str, int] = defaultdict(int)

    total = len(GROUND_TRUTH)
    print(f"[評估] 開始評估 {total} 個案例（backend={backend}）\n")

    for i, case in enumerate(GROUND_TRUTH, 1):
        case_id = case["id"]
        filename = case["filename"]
        lang = case["language"]
        has_vuln = case["has_vulnerability"]

        code_path = SAMPLES_DIR / filename
        if not code_path.is_file():
            print(f"  [{i:2d}/{total}] {case_id} — 找不到測試檔案 {code_path}，略過")
            errors.append(f"{case_id}: 找不到 {code_path}")
            continue

        code = code_path.read_text(encoding="utf-8", errors="replace")
        code_samples.append(code)

        print(f"  [{i:2d}/{total}] {case_id} ({lang}) — ", end="", flush=True)

        t0 = time.perf_counter()
        try:
            ctx = retriever.get_context(code)
            findings = analyzer.analyze(code, filename, ctx)
        except Exception as e:  # noqa: BLE001
            elapsed = time.perf_counter() - t0
            print(f"❌ 錯誤: {e}")
            errors.append(f"{case_id}: {e}")
            timing_records.append({"case_id": case_id, "elapsed_sec": elapsed, "error": str(e)})
            continue

        elapsed = time.perf_counter() - t0
        timing_records.append({"case_id": case_id, "elapsed_sec": round(elapsed, 2)})

        pred_vuln = len(findings) > 0
        pred_cwes = [c for f in findings for c in f.cwe_references]

        result_entry = {
            "case_id": case_id,
            "language": lang,
            "filename": filename,
            "has_vulnerability": has_vuln,
            "predicted_vulnerable": pred_vuln,
            "findings": [f.to_dict() for f in findings],
            "elapsed_sec": round(elapsed, 2),
        }
        results.append(result_entry)

        # 混淆矩陣
        if pred_vuln and has_vuln:
            tp += 1; lang_tp[lang] += 1
        elif pred_vuln and not has_vuln:
            fp += 1; lang_fp[lang] += 1
        elif not pred_vuln and has_vuln:
            fn += 1; lang_fn[lang] += 1
        else:
            tn += 1; lang_tn[lang] += 1

        # CWE 匹配率（僅計算含漏洞案例）
        if has_vuln and case.get("expected_cwe"):
            cwe_total_vuln += 1
            if _cwe_match(pred_cwes, case["expected_cwe"]):
                cwe_match_count += 1

        status = "✓" if (pred_vuln == has_vuln) else "✗"
        print(f"{status}  ({elapsed:.1f}s) findings={len(findings)}")

    # ── 計算總體指標 ──────────────────────────────────────────────
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    cwe_match_rate = cwe_match_count / cwe_total_vuln if cwe_total_vuln > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    # ── 各語言指標 ───────────────────────────────────────────────
    lang_metrics: dict[str, dict] = {}
    for lang in set(list(lang_tp.keys()) + list(lang_fp.keys()) + list(lang_fn.keys()) + list(lang_tn.keys())):
        ltp = lang_tp[lang]; lfp = lang_fp[lang]
        lfn = lang_fn[lang]; ltn = lang_tn[lang]
        lp = ltp / (ltp + lfp) if (ltp + lfp) > 0 else 0.0
        lr = ltp / (ltp + lfn) if (ltp + lfn) > 0 else 0.0
        lf = 2 * lp * lr / (lp + lr) if (lp + lr) > 0 else 0.0
        lang_metrics[lang] = {
            "tp": ltp, "fp": lfp, "fn": lfn, "tn": ltn,
            "precision": round(lp, 3), "recall": round(lr, 3), "f1": round(lf, 3),
        }

    report = {
        "backend": backend,
        "total_cases": total,
        "evaluated": len(results),
        "errors": len(errors),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "overall": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "cwe_match_rate": round(cwe_match_rate, 4),
        },
        "by_language": lang_metrics,
        "error_details": errors,
    }

    # 輸出
    with open(out_path / "eval_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    with open(out_path / "timing_records.json", "w", encoding="utf-8") as f:
        json.dump(timing_records, f, ensure_ascii=False, indent=2)
    with open(out_path / "ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(GROUND_TRUTH, f, ensure_ascii=False, indent=2)
    with open(out_path / "eval_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _print_eval_summary(report)
    return report


def _print_eval_summary(report: dict) -> None:
    o = report["overall"]
    cm = report["confusion_matrix"]
    print(f"""
=== 評估結果摘要 ===
  Backend  : {report['backend']}
  案例總數  : {report['total_cases']} (評估 {report['evaluated']}，錯誤 {report['errors']})
  混淆矩陣  : TP={cm['tp']}  FP={cm['fp']}  FN={cm['fn']}  TN={cm['tn']}
  Precision : {o['precision']:.4f}
  Recall    : {o['recall']:.4f}
  F1 Score  : {o['f1']:.4f}
  Accuracy  : {o['accuracy']:.4f}
  CWE Match : {o['cwe_match_rate']:.4f}
""")
    print("  各語言 F1：")
    for lang, m in sorted(report["by_language"].items()):
        print(f"    {lang:14s}: F1={m['f1']:.3f}  (P={m['precision']:.3f}  R={m['recall']:.3f})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="執行 50 案例安全評估")
    parser.add_argument("--backend", choices=["openai", "ollama"], default="openai")
    parser.add_argument("--output", default="data/eval_results")
    args = parser.parse_args()
    run_eval(backend=args.backend, output_dir=args.output)
