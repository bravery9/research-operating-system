"""Output writers for audit artifacts."""

from dataclasses import dataclass
import json
from pathlib import Path

from invariant_os.core.models import AuditResult
from invariant_os.report.html import render_evidence_viewer
from invariant_os.report.markdown import render_research_brief
from invariant_os.report.review_queue import render_review_queue_jsonl
from invariant_os.report.sarif import render_sarif


@dataclass(frozen=True)
class AuditOutputPaths:
    json: Path
    markdown: Path
    graph: Path
    html: Path
    sarif: Path
    review_queue: Path


def write_audit_outputs(result: AuditResult, output_dir: Path) -> AuditOutputPaths:
    """Write stable audit artifacts."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    json_path = target_dir / "audit_result.json"
    markdown_path = target_dir / "research_brief.md"
    graph_path = target_dir / "evidence_graph.json"
    html_path = target_dir / "evidence_viewer.html"
    sarif_path = target_dir / "audit_result.sarif.json"
    review_queue_path = target_dir / "audit_review_queue.jsonl"

    json_payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    graph_payload = json.dumps(result.evidence_graph.model_dump(mode="json"), indent=2, sort_keys=True)
    sarif_payload = json.dumps(render_sarif(result), indent=2, sort_keys=True)
    json_path.write_text(f"{json_payload}\n", encoding="utf-8")
    markdown_path.write_text(render_research_brief(result), encoding="utf-8")
    graph_path.write_text(f"{graph_payload}\n", encoding="utf-8")
    html_path.write_text(render_evidence_viewer(result), encoding="utf-8")
    sarif_path.write_text(f"{sarif_payload}\n", encoding="utf-8")
    review_queue_path.write_text(render_review_queue_jsonl(result), encoding="utf-8")

    return AuditOutputPaths(
        json=json_path,
        markdown=markdown_path,
        graph=graph_path,
        html=html_path,
        sarif=sarif_path,
        review_queue=review_queue_path,
    )
