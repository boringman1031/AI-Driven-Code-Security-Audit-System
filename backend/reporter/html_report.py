import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from backend.analyzer.base import Finding
from backend.config import get_settings


def generate_report(
    findings: list[Finding],
    scan_metadata: dict,
    scan_id: str | None = None,
) -> tuple[str, str]:
    """
    生成 HTML 報告，回傳 (scan_id, report_file_path)。
    """
    if not scan_id:
        scan_id = str(uuid.uuid4())

    settings = get_settings()
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    counts = Counter(f.severity for f in findings)
    overall_risk = _overall_risk(counts)

    env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    template = env.get_template("report.html")

    html = template.render(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        findings=[f.to_dict() for f in findings],
        metadata=scan_metadata,
        counts=dict(counts),
        overall_risk=overall_risk,
        total=len(findings),
    )

    report_path = reports_dir / f"{scan_id}.html"
    report_path.write_text(html, encoding="utf-8")
    return scan_id, str(report_path)


def _overall_risk(counts: Counter) -> str:
    for level in ("Critical", "High", "Medium", "Low"):
        if counts.get(level, 0) > 0:
            return level
    return "Safe"
