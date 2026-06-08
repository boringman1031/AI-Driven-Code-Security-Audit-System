import json
import httpx
from backend.analyzer.base import BaseAnalyzer, Finding
from backend.analyzer.language_focus import get_language_focus, detect_language
from backend.config import get_settings

_PROMPT = """\
你是一位資深應用安全研究員，專精於多語言程式碼漏洞分析（Prompt v4：語言感知模式）。

參考安全知識:
{context}

{language_focus}

請分析以下程式碼，進行 Self-Critique 確認行號與 CWE ID 真實存在後，以嚴格 JSON 格式回應（不含任何 markdown）:
{{
  "overall_risk": "Critical|High|Medium|Low|Safe",
  "language": "偵測到的程式語言",
  "summary": "整體安全審查摘要",
  "findings": [
    {{
      "type": "漏洞類型",
      "severity": "Critical|High|Medium|Low",
      "line_hint": "位置說明",
      "explanation": "詳細說明",
      "fix_suggestion": "修復建議",
      "cwe_references": ["CWE-XX"]
    }}
  ]
}}

檔案名稱: {filename}
偵測語言: {language}
程式碼:
```
{code}
```

JSON 回應:"""


class OllamaAnalyzer(BaseAnalyzer):
    def __init__(self):
        settings = get_settings()
        self._base_url = settings.ollama_base_url.rstrip("/")
        self._model = settings.ollama_model

    def analyze(self, code: str, filename: str, context: str) -> list[Finding]:
        language = detect_language(filename) or "未知"
        language_focus = get_language_focus(filename)
        prompt = _PROMPT.format(
            context=context or "（無額外知識庫上下文）",
            language_focus=language_focus,
            filename=filename,
            language=language,
            code=code[:8_000],
        )
        raw_text = self._call_ollama(prompt)
        return self._to_findings(raw_text, filename)

    def _call_ollama(self, prompt: str) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        with httpx.Client(timeout=180.0) as client:
            resp = client.post(f"{self._base_url}/api/generate", json=payload)
            resp.raise_for_status()
            return resp.json().get("response", "{}")

    @staticmethod
    def _to_findings(raw_text: str, filename: str) -> list[Finding]:
        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError:
            return []
        findings = []
        for item in raw.get("findings", []):
            severity = item.get("severity", "Medium")
            if severity not in ("Critical", "High", "Medium", "Low"):
                severity = "Medium"
            findings.append(Finding(
                type=item.get("type", "未知漏洞類型"),
                severity=severity,
                filename=filename,
                line_hint=item.get("line_hint", "未知位置"),
                explanation=item.get("explanation", ""),
                fix_suggestion=item.get("fix_suggestion", ""),
                cwe_references=item.get("cwe_references", []),
            ))
        return findings
