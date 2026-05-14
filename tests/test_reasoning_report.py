from invariant_os.core.models import (
    Confidence,
    Project,
    ReasoningCategory,
    ReasoningItem,
    ReasoningResult,
    ReasoningSummary,
)
from invariant_os.report.reasoning_markdown import render_reasoning_brief


REQUIRED_SECTIONS = [
    "# InvariantOS Reasoning Brief",
    "## Scope and Safety",
    "## Source Audit",
    "## Summary",
    "## High-Value Surfaces",
    "## Security Invariant Hypotheses",
    "## Primitive Triage",
    "## Missing Evidence",
    "## Safe Next Steps",
    "## Appendix: Reasoning Items",
]


def _reasoning_result() -> ReasoningResult:
    items = [
        ReasoningItem(
            id="reason_surface_0001",
            category=ReasoningCategory.HIGH_VALUE_SURFACE,
            title="Candidate high-value surface",
            summary="Candidate review surface from static audit evidence.",
            confidence=Confidence.HIGH,
            related_ids=["flow_0001", "ep_0001", "cons_0001"],
            evidence_ids=["ev_0001"],
            missing_evidence=["confirm whether request-controlled data reaches the operation"],
        ),
        ReasoningItem(
            id="reason_invariant_0001",
            category=ReasoningCategory.SECURITY_INVARIANT_HYPOTHESIS,
            title="Invariant hypothesis for data_to_database",
            summary="Hypothesis: database boundaries should preserve query construction invariants.",
            confidence=Confidence.MEDIUM,
            related_ids=["boundary_0001"],
            evidence_ids=["ev_0001"],
        ),
        ReasoningItem(
            id="reason_primitive_0001",
            category=ReasoningCategory.PRIMITIVE_TRIAGE,
            title="Primitive hypothesis triage primitive_0001",
            summary="Review primitive hypothesis using linked evidence.",
            confidence=Confidence.MEDIUM,
            related_ids=["primitive_0001"],
            evidence_ids=["ev_0001"],
        ),
        ReasoningItem(
            id="reason_step_0001",
            category=ReasoningCategory.SAFE_NEXT_STEP,
            title="Safe review step for primitive_0001",
            summary="Use benign local review to evaluate this candidate hypothesis.",
            confidence=Confidence.LOW,
            related_ids=["primitive_0001"],
            safe_next_steps=["Trace a benign sample through the candidate operation."],
        ),
    ]
    return ReasoningResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/tmp/audit_result.json",
        items=items,
        summary=ReasoningSummary(
            high_value_surfaces=1,
            invariant_hypotheses=1,
            primitive_triage_items=1,
            missing_evidence_items=0,
            safe_next_steps=1,
        ),
    )


def test_reasoning_brief_contains_required_sections_and_safety_statement():
    brief = render_reasoning_brief(_reasoning_result())

    for section in REQUIRED_SECTIONS:
        assert section in brief
    assert "authorized local repository analysis" in brief
    assert "does not prove exploitability" in brief


def test_reasoning_brief_renders_evidence_related_ids_and_missing_evidence():
    brief = render_reasoning_brief(_reasoning_result())

    assert "ev_0001" in brief
    assert "primitive_0001" in brief
    assert "confirm whether request-controlled data reaches the operation" in brief


def test_reasoning_brief_renders_source_and_summary_metadata():
    brief = render_reasoning_brief(_reasoning_result())

    assert "example" in brief
    assert "/repo" in brief
    assert "/tmp/audit_result.json" in brief
    assert "Source schema version: `0.5`" in brief
    assert "High-value surfaces: 1" in brief


def test_reasoning_brief_uses_conservative_language():
    brief = render_reasoning_brief(_reasoning_result()).lower()

    assert "candidate" in brief or "hypothesis" in brief
    assert "confirmed vulnerable" not in brief
    assert "confirmed exploitable" not in brief
    assert "exploitability proved" not in brief
    assert "payload to exploit" not in brief
