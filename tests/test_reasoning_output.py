from invariant_os.core.models import (
    Confidence,
    Project,
    ReasoningCategory,
    ReasoningItem,
    ReasoningResult,
    ReasoningSummary,
)
from invariant_os.reasoning.output import write_reasoning_outputs


def _reasoning_result() -> ReasoningResult:
    return ReasoningResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/tmp/audit_result.json",
        items=[
            ReasoningItem(
                id="reason_surface_0001",
                category=ReasoningCategory.HIGH_VALUE_SURFACE,
                title="Candidate high-value surface",
                summary="Candidate review surface from static audit evidence.",
                confidence=Confidence.HIGH,
                related_ids=["flow_0001"],
                evidence_ids=["ev_0001"],
            )
        ],
        summary=ReasoningSummary(
            high_value_surfaces=1,
            invariant_hypotheses=0,
            primitive_triage_items=0,
            missing_evidence_items=0,
            safe_next_steps=0,
        ),
    )


def test_write_reasoning_outputs_writes_json_and_markdown(tmp_path):
    json_path, markdown_path = write_reasoning_outputs(_reasoning_result(), tmp_path)

    assert json_path == tmp_path / "reason_result.json"
    assert markdown_path == tmp_path / "reasoning_brief.md"
    assert json_path.exists()
    assert markdown_path.exists()
    assert '"schema_version": "0.6"' in json_path.read_text(encoding="utf-8")
    assert json_path.read_text(encoding="utf-8").endswith("\n")
    assert "# InvariantOS Reasoning Brief" in markdown_path.read_text(encoding="utf-8")
