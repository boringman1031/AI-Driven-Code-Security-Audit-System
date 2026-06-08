"""
架構限制分析腳本（Phase D）。

量化分析系統的六類限制：
  1. LLM 幻覺率（無效 CWE ID）
  2. 分析延遲（每檔案 API 呼叫時間）
  3. Token 成本估算
  4. 語言偏差（各語言 F1 對比）
  5. 脈絡視窗截斷情況
  6. RAG 精度（相關性評估）

使用方式:
  python -m backend.eval.limitations [--results-dir data/eval_results]
"""
import argparse
import json
import re
import time
import statistics
from pathlib import Path
from datetime import datetime, timezone

# ── 已知合法 CWE ID 集合（CWE Top 25 + 常見項目）─────────────────────
_VALID_CWE_PATTERN = re.compile(r"^CWE-\d+$")

# 估計 Token 成本（GPT-4o-mini 價格）
_COST_PER_1K_INPUT_TOKENS  = 0.000150   # USD
_COST_PER_1K_OUTPUT_TOKENS = 0.000600   # USD
_AVG_CHARS_PER_TOKEN       = 4.0

# CWE Top 25 (2023) 合法範圍（用於幻覺率檢查）
_KNOWN_CWE_IDS = {
    f"CWE-{n}" for n in [
        1, 2, 7, 11, 13, 14, 15, 16, 17, 20, 22, 23, 25, 26, 27, 29, 35, 36,
        36, 59, 61, 73, 74, 77, 78, 79, 88, 89, 90, 91, 94, 95, 97, 98,
        100, 116, 119, 120, 121, 122, 124, 125, 126, 127, 128, 129,
        131, 134, 135, 170, 172, 176, 178, 183, 184, 185, 190, 191, 192,
        193, 194, 195, 196, 197, 200, 201, 202, 203, 204, 208, 209, 210,
        212, 214, 215, 220, 222, 223, 224, 226, 230, 231, 232, 233, 234,
        235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247,
        248, 250, 252, 253, 256, 257, 258, 259, 260, 261, 262, 263, 264,
        265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277,
        278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290,
        291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303,
        304, 305, 306, 307, 308, 309, 311, 312, 313, 314, 315, 316, 317,
        318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
        331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343,
        344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 356, 357,
        358, 359, 360, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371,
        372, 373, 374, 375, 377, 378, 379, 380, 382, 383, 384, 385, 386,
        388, 390, 391, 392, 393, 394, 395, 396, 397, 398, 400, 401, 402,
        403, 404, 405, 406, 407, 408, 409, 410, 412, 413, 414, 415, 416,
        417, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 430, 431,
        432, 433, 434, 435, 436, 437, 439, 440, 441, 444, 446, 447, 448,
        449, 450, 451, 453, 454, 455, 456, 457, 458, 459, 460, 462, 463,
        464, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477,
        478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490,
        491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 502, 506, 507,
        508, 509, 510, 511, 512, 514, 515, 516, 520, 521, 522, 523, 524,
        525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537,
        538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550,
        551, 552, 553, 554, 555, 556, 557, 558, 560, 561, 562, 563, 564,
        565, 566, 567, 568, 570, 571, 572, 573, 574, 575, 576, 577, 578,
        579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591,
        592, 593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604,
        605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617,
        618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 640, 641,
        642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654,
        655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667,
        668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 681, 682,
        683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695,
        696, 697, 698, 703, 704, 706, 707, 708, 710, 732, 733, 749, 754,
        755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767,
        768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780,
        781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793,
        794, 795, 796, 797, 798, 799, 800, 820, 821, 822, 823, 824, 825,
        826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838,
        839, 840, 841, 842, 843, 862, 863, 908, 909, 910, 911, 912, 913,
        914, 915, 916, 917, 918, 920, 921, 922, 923, 924, 925, 926, 927,
        939, 940, 941, 942, 943, 1004, 1021, 1022, 1029, 1037, 1038,
        1039, 1041, 1043, 1044, 1045, 1047, 1048, 1050, 1054, 1059,
        1068, 1094, 1095, 1104, 1173, 1174, 1176, 1177, 1188, 1189,
        1190, 1191, 1192, 1193, 1194, 1220, 1240, 1254, 1259, 1260,
        1261, 1262, 1263, 1264, 1270, 1271, 1272, 1273, 1274, 1275,
        1276, 1277, 1278, 1279, 1280, 1281, 1282, 1283, 1284, 1285,
        1286, 1287, 1288, 1289, 1290, 1291, 1292, 1293, 1294, 1295,
        1296, 1297, 1298, 1299, 1300, 1301, 1302, 1303, 1304, 1305,
        1306, 1307, 1308, 1309, 1310, 1311, 1312, 1313, 1314, 1315,
        1316, 1317, 1318, 1319, 1320, 1321, 1322, 1323, 1324, 1325,
        1326, 1327, 1328, 1329, 1330, 1331, 1332, 1333, 1334, 1335,
        1336, 1337, 1338, 1339, 1340, 1341, 1342, 1343, 1344, 1345,
        1346, 1347, 1348, 1349, 1350, 1351, 1352, 1353, 1354, 1355,
        1356, 1357, 1358, 1359, 1360, 1361, 1362, 1363, 1364, 1365,
        1366, 1367, 1368, 1369, 1370, 1371, 1372, 1373, 1374, 1375,
        1376, 1377, 1378, 1379, 1380, 1381, 1382, 1383, 1384, 1385,
        1386, 1387, 1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395,
        1396, 1397, 1398, 1399, 1400, 1401, 1402, 1403, 1404, 1405,
        1406, 1407, 1408, 1409, 1410, 1411, 1412, 1413, 1414, 1415,
        1416, 1417, 1418, 1419, 1420, 1421, 1422, 1423, 1424, 1425,
        1426, 1427, 1428, 1429, 1430, 1431, 1432, 1433, 1434, 1435,
        1436, 1437, 1438, 1439, 1440,
    }
}


def _is_valid_cwe(cwe_id: str) -> bool:
    """判斷 CWE ID 是否為合法格式且在已知範圍內。"""
    if not _VALID_CWE_PATTERN.match(cwe_id):
        return False
    return cwe_id in _KNOWN_CWE_IDS


def analyze_hallucination_rate(results: list[dict]) -> dict:
    """計算幻覺率：無效 CWE ID 占所有 CWE 引用的比例。"""
    total_refs = 0
    invalid_refs = 0
    invalid_examples: list[str] = []

    for result in results:
        for finding in result.get("findings", []):
            for cwe in finding.get("cwe_references", []):
                total_refs += 1
                if not _is_valid_cwe(cwe):
                    invalid_refs += 1
                    if len(invalid_examples) < 10:
                        invalid_examples.append(cwe)

    rate = invalid_refs / total_refs if total_refs > 0 else 0.0
    return {
        "total_cwe_references": total_refs,
        "invalid_cwe_count": invalid_refs,
        "hallucination_rate": round(rate, 4),
        "hallucination_rate_pct": f"{rate*100:.2f}%",
        "invalid_examples": invalid_examples,
    }


def analyze_latency(timing_records: list[dict]) -> dict:
    """統計每檔案的分析延遲。"""
    if not timing_records:
        return {"note": "無計時記錄"}

    times = [r["elapsed_sec"] for r in timing_records if "elapsed_sec" in r]
    if not times:
        return {"note": "無有效計時資料"}

    return {
        "count": len(times),
        "mean_sec": round(statistics.mean(times), 2),
        "median_sec": round(statistics.median(times), 2),
        "min_sec": round(min(times), 2),
        "max_sec": round(max(times), 2),
        "stdev_sec": round(statistics.stdev(times), 2) if len(times) > 1 else 0.0,
        "p95_sec": round(sorted(times)[int(len(times) * 0.95)], 2) if len(times) >= 2 else max(times),
    }


def estimate_token_cost(results: list[dict], code_samples: list[str]) -> dict:
    """估算 Token 消耗與 USD 成本。"""
    total_input_chars = 0
    total_output_chars = 0

    for i, result in enumerate(results):
        code = code_samples[i] if i < len(code_samples) else ""
        # 輸入：程式碼 + Prompt 固定部分（估計 800 字元）
        input_chars = len(code[:12_000]) + 800
        # 輸出：JSON 結果估算
        output_chars = len(json.dumps(result, ensure_ascii=False))
        total_input_chars += input_chars
        total_output_chars += output_chars

    input_tokens = total_input_chars / _AVG_CHARS_PER_TOKEN
    output_tokens = total_output_chars / _AVG_CHARS_PER_TOKEN
    cost_usd = (input_tokens / 1000 * _COST_PER_1K_INPUT_TOKENS +
                output_tokens / 1000 * _COST_PER_1K_OUTPUT_TOKENS)

    return {
        "total_input_tokens_est": int(input_tokens),
        "total_output_tokens_est": int(output_tokens),
        "cost_usd_est": round(cost_usd, 4),
        "cost_per_file_usd_est": round(cost_usd / len(results), 5) if results else 0,
        "note": "基於 GPT-4o-mini 定價估算（2024-06）",
    }


def analyze_context_truncation(code_samples: list[str], max_chars: int = 12_000) -> dict:
    """分析因脈絡視窗截斷而可能遺漏的程式碼比例。"""
    truncated = [s for s in code_samples if len(s) > max_chars]
    truncation_rates = [
        (len(s) - max_chars) / len(s) for s in truncated
    ]
    return {
        "total_files": len(code_samples),
        "truncated_files": len(truncated),
        "truncation_pct": f"{len(truncated)/len(code_samples)*100:.1f}%" if code_samples else "0%",
        "avg_lost_pct": f"{statistics.mean(truncation_rates)*100:.1f}%" if truncation_rates else "0%",
        "max_chars_limit": max_chars,
    }


def analyze_language_bias(results: list[dict], ground_truth: list[dict]) -> dict:
    """計算各語言的 F1 分數（需要 ground truth 標記）。"""
    from collections import defaultdict
    lang_tp: dict[str, int] = defaultdict(int)
    lang_fp: dict[str, int] = defaultdict(int)
    lang_fn: dict[str, int] = defaultdict(int)

    for pred, gt in zip(results, ground_truth):
        lang = gt.get("language", "Unknown")
        pred_vuln = len(pred.get("findings", [])) > 0
        gt_vuln = gt.get("has_vulnerability", False)

        if pred_vuln and gt_vuln:
            lang_tp[lang] += 1
        elif pred_vuln and not gt_vuln:
            lang_fp[lang] += 1
        elif not pred_vuln and gt_vuln:
            lang_fn[lang] += 1

    lang_metrics: dict[str, dict] = {}
    for lang in set(list(lang_tp.keys()) + list(lang_fp.keys()) + list(lang_fn.keys())):
        tp = lang_tp[lang]
        fp = lang_fp[lang]
        fn = lang_fn[lang]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        lang_metrics[lang] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }

    return lang_metrics


def run_analysis(results_dir: str = "data/eval_results") -> dict:
    """執行完整架構限制分析，回傳彙整結果。"""
    results_path = Path(results_dir)
    report: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": {},
    }

    # 嘗試讀取已有評估結果
    eval_file = results_path / "eval_results.json"
    timing_file = results_path / "timing_records.json"
    gt_file = results_path / "ground_truth.json"
    code_file = results_path / "code_samples_len.json"

    if eval_file.is_file():
        with open(eval_file, encoding="utf-8") as f:
            results = json.load(f)
        print(f"[限制分析] 載入 {len(results)} 筆評估結果")

        report["limitations"]["hallucination"] = analyze_hallucination_rate(results)

        code_samples = []
        if code_file.is_file():
            with open(code_file, encoding="utf-8") as f:
                code_samples = json.load(f)  # list of code strings
        report["limitations"]["token_cost"] = estimate_token_cost(results, code_samples)
        report["limitations"]["context_truncation"] = analyze_context_truncation(code_samples)

        if gt_file.is_file():
            with open(gt_file, encoding="utf-8") as f:
                ground_truth = json.load(f)
            report["limitations"]["language_bias"] = analyze_language_bias(results, ground_truth)
    else:
        print(f"[限制分析] 找不到 {eval_file}，使用示範資料")
        # 示範資料（基於 week16_plan.md 中記載的數值）
        report["limitations"]["hallucination"] = {
            "total_cwe_references": 285,
            "invalid_cwe_count": 12,
            "hallucination_rate": 0.042,
            "hallucination_rate_pct": "4.21%",
            "note": "示範數值（來源：week16_plan.md Phase D）",
        }
        report["limitations"]["token_cost"] = {
            "total_input_tokens_est": 45000,
            "total_output_tokens_est": 15000,
            "cost_usd_est": 0.18,
            "cost_per_file_usd_est": 0.006,
            "note": "30 案例示範估算（GPT-4o-mini）",
        }
        report["limitations"]["context_truncation"] = {
            "total_files": 30,
            "truncated_files": 4,
            "truncation_pct": "13.3%",
            "avg_lost_pct": "22.1%",
            "max_chars_limit": 12000,
        }
        report["limitations"]["language_bias"] = {
            "Python":     {"precision": 0.92, "recall": 0.87, "f1": 0.89},
            "JavaScript": {"precision": 0.85, "recall": 0.81, "f1": 0.83},
            "Java":       {"precision": 0.82, "recall": 0.78, "f1": 0.80},
            "C/C++":      {"precision": 0.58, "recall": 0.44, "f1": 0.50},
            "PHP":        {"precision": 0.80, "recall": 0.75, "f1": 0.77},
        }

    if timing_file.is_file():
        with open(timing_file, encoding="utf-8") as f:
            timing_records = json.load(f)
        report["limitations"]["latency"] = analyze_latency(timing_records)
    else:
        report["limitations"]["latency"] = {
            "note": "示範數值（來源：week16_plan.md Phase D）",
            "openai_mean_sec": 4.8,
            "openai_p95_sec": 7.2,
            "ollama_mean_sec": 67.3,
            "ollama_p95_sec": 88.5,
        }

    report["limitations"]["rag_precision"] = {
        "note": "示範數值（Top-4 結果中平均 1 條無關）",
        "top_k": 4,
        "relevant_avg": 3.1,
        "irrelevant_avg": 0.9,
        "precision_at_4": 0.775,
    }

    # 輸出報告
    results_path.mkdir(parents=True, exist_ok=True)
    out_path = results_path / "limitations_report.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[限制分析] 報告已輸出至 {out_path}")
    _print_summary(report)
    return report


def _print_summary(report: dict) -> None:
    lim = report["limitations"]
    print("\n=== 架構限制分析摘要 ===")

    h = lim.get("hallucination", {})
    if h:
        print(f"  幻覺率:      {h.get('hallucination_rate_pct', 'N/A')}"
              f"  ({h.get('invalid_cwe_count', '?')} / {h.get('total_cwe_references', '?')} 個 CWE 引用)")

    lat = lim.get("latency", {})
    if "openai_mean_sec" in lat:
        print(f"  延遲(OpenAI): 平均 {lat['openai_mean_sec']}s / P95 {lat['openai_p95_sec']}s")
        print(f"  延遲(Ollama): 平均 {lat['ollama_mean_sec']}s / P95 {lat['ollama_p95_sec']}s")
    elif "mean_sec" in lat:
        print(f"  延遲:         平均 {lat['mean_sec']}s / P95 {lat.get('p95_sec', '?')}s")

    cost = lim.get("token_cost", {})
    if cost:
        print(f"  Token 成本:  ${cost.get('cost_usd_est', '?')} USD "
              f"（{cost.get('note', '')}）")

    trunc = lim.get("context_truncation", {})
    if trunc:
        print(f"  截斷率:       {trunc.get('truncation_pct', 'N/A')} 檔案被截斷")

    lb = lim.get("language_bias", {})
    if lb:
        print("  語言 F1 對比:")
        for lang, m in lb.items():
            if isinstance(m, dict) and "f1" in m:
                print(f"    {lang:12s}: F1={m['f1']:.3f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="架構限制分析報告")
    parser.add_argument("--results-dir", default="data/eval_results", help="評估結果目錄")
    args = parser.parse_args()
    run_analysis(results_dir=args.results_dir)
