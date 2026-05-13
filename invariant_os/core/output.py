"""Output writers for audit artifacts."""

import json
from pathlib import Path

from invariant_os.core.models import AuditResult
from invariant_os.report.markdown import render_research_brief


def write_audit_outputs(result: AuditResult, output_dir: Path) -> tuple[Path, Path]:
    """Write stable JSON and Markdown audit artifacts."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    json_path = target_dir / "audit_result.json"
    markdown_path = target_dir / "research_brief.md"

    json_payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    json_path.write_text(f"{json_payload}\n", encoding="utf-8")
    markdown_path.write_text(render_research_brief(result), encoding="utf-8")

    return json_path, markdown_path
