from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import Literal


@dataclass
class Finding:
    type: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    filename: str
    line_hint: str
    explanation: str
    fix_suggestion: str
    cwe_references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "filename": self.filename,
            "line_hint": self.line_hint,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "cwe_references": self.cwe_references,
        }


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, code: str, filename: str, context: str) -> list[Finding]:
        ...
