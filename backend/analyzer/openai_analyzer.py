from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from backend.analyzer.base import BaseAnalyzer, Finding
from backend.analyzer.language_focus import get_language_focus, detect_language
from backend.config import get_settings

_SYSTEM = """\
你是一位資深應用安全研究員，專精於多語言程式碼漏洞分析（Prompt v4：語言感知模式）。

請參考以下安全知識庫進行分析:
{context}

{language_focus}

分析步驟:
1. 識別程式語言與主要功能
2. 依據上方語言分析重點，逐段檢查對應的高風險模式
3. 對每個發現進行自我審查（Self-Critique）：確認行號是否真實存在、CWE ID 是否確為已知 CWE
4. 對照 CWE / OWASP 分類每個發現

回應必須是嚴格的 JSON，格式如下（不含 markdown code block）:
{{
  "overall_risk": "Critical|High|Medium|Low|Safe",
  "language": "偵測到的程式語言",
  "summary": "整體安全審查摘要（繁體中文）",
  "findings": [
    {{
      "type": "漏洞類型，例如 CWE-89 SQL Injection",
      "severity": "Critical|High|Medium|Low",
      "line_hint": "漏洞位置，例如「第 23 行」或「函數 login()」",
      "explanation": "漏洞詳細說明（繁體中文）",
      "fix_suggestion": "修復建議與修復後程式碼範例（繁體中文）",
      "cwe_references": ["CWE-89"]
    }}
  ]
}}

若無任何漏洞，findings 回傳空陣列，overall_risk 為 "Safe"。"""

_HUMAN = """\
請分析以下程式碼檔案:
檔案名稱: {filename}
偵測語言: {language}

```
{code}
```"""


class OpenAIAnalyzer(BaseAnalyzer):
    def __init__(self):
        settings = get_settings()
        llm = ChatOpenAI(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            temperature=0,
        )
        prompt = ChatPromptTemplate.from_messages([
            ("system", _SYSTEM),
            ("human", _HUMAN),
        ])
        self._chain = prompt | llm | JsonOutputParser()

    def analyze(self, code: str, filename: str, context: str) -> list[Finding]:
        language = detect_language(filename) or "未知"
        language_focus = get_language_focus(filename)
        raw: dict = self._chain.invoke({
            "context": context or "（無額外知識庫上下文）",
            "language_focus": language_focus,
            "filename": filename,
            "language": language,
            "code": code[:12_000],
        })
        return self._to_findings(raw, filename)

    @staticmethod
    def _to_findings(raw: dict, filename: str) -> list[Finding]:
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
