from invariant_os.core.models import (
    Confidence,
    Project,
    ReasoningCategory,
    ReasoningItem,
    ReasoningResult,
    ReasoningSummary,
)


def test_reasoning_category_wire_values_are_stable():
    assert [item.value for item in ReasoningCategory] == [
        "high_value_surface",
        "security_invariant_hypothesis",
        "primitive_triage",
        "missing_evidence",
        "safe_next_step",
    ]


def test_reasoning_result_defaults_to_schema_06_and_safety_metadata():
    result = ReasoningResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/tmp/audit_result.json",
        items=[],
        summary=ReasoningSummary(
            high_value_surfaces=0,
            invariant_hypotheses=0,
            primitive_triage_items=0,
            missing_evidence_items=0,
            safe_next_steps=0,
        ),
    )

    dumped = result.model_dump(mode="json")

    assert dumped["schema_version"] == "0.6"
    assert dumped["tool"] == "invariant-os"
    assert dumped["source_schema_version"] == "0.5"
    assert dumped["source_project"] == {"name": "example", "root": "/repo"}
    assert dumped["safety"]["principle"] == "LLM proposes. Tools prove. Human approves."


def test_reasoning_item_serializes_evidence_and_review_fields():
    item = ReasoningItem(
        id="reason_surface_0001",
        category=ReasoningCategory.HIGH_VALUE_SURFACE,
        title="Candidate high-value surface",
        summary="Candidate review surface because static evidence links an entrypoint to a consumer.",
        confidence=Confidence.MEDIUM,
        related_ids=["ep_0001", "cons_0001"],
        evidence_ids=["ev_0001"],
        missing_evidence=["confirm runtime dispatch"],
        safe_next_steps=["Review the candidate with benign inputs only."],
    )

    assert item.model_dump(mode="json") == {
        "id": "reason_surface_0001",
        "category": "high_value_surface",
        "title": "Candidate high-value surface",
        "summary": "Candidate review surface because static evidence links an entrypoint to a consumer.",
        "confidence": "medium",
        "related_ids": ["ep_0001", "cons_0001"],
        "evidence_ids": ["ev_0001"],
        "missing_evidence": ["confirm runtime dispatch"],
        "safe_next_steps": ["Review the candidate with benign inputs only."],
    }
