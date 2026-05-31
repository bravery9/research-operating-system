import json

from invariant_os.core.models import (
    REVIEW_QUEUE_SCHEMA_VERSION,
    AuditResult,
    AuditSummary,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Evidence,
    EvidenceType,
    PrimitiveCandidate,
    PrimitiveType,
    Project,
    SafetyMetadata,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
)
from invariant_os.report.review_queue import render_review_queue_jsonl


def _empty_result() -> AuditResult:
    return AuditResult(
        project=Project(name="empty", root="/tmp/empty"),
        summary=AuditSummary(
            files=0,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
            static_flow_candidates=0,
        ),
        safety=SafetyMetadata(),
    )


def _evidence(evidence_id: str = "ev_queue_0001") -> Evidence:
    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=12,
        pattern="open(",
        snippet="open(user_path, 'w')",
        message="Candidate file operation evidence",
    )


def _rows(result: AuditResult) -> list[dict[str, object]]:
    payload = render_review_queue_jsonl(result)
    return [json.loads(line) for line in payload.splitlines()]


def test_review_queue_empty_audit_renders_empty_jsonl():
    assert render_review_queue_jsonl(_empty_result()) == ""


def test_review_queue_renders_primitive_candidate_row():
    evidence = _evidence()
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[evidence],
        missing_evidence=["confirm whether request data controls the path"],
        safe_next_steps=["Trace a benign sample path through the write call."],
    )
    result = _empty_result().model_copy(update={"primitive_candidates": [primitive]})

    rows = _rows(result)

    assert len(rows) == 1
    row = rows[0]
    assert row["schema_version"] == REVIEW_QUEUE_SCHEMA_VERSION
    assert row["queue_type"] == "manual_review_candidate"
    assert row["category"] == "primitive"
    assert row["candidate_id"] == "primitive_0001"
    assert row["kind"] == "file_write"
    assert row["confidence"] == "high"
    assert row["primary_file"] == "app.py"
    assert row["primary_line"] == 12
    assert row["evidence_ids"] == ["ev_queue_0001"]
    assert row["evidence_locations"] == [
        {"file": "app.py", "id": "ev_queue_0001", "line": 12, "type": "pattern_match"}
    ]
    assert row["missing_evidence"] == ["confirm whether request data controls the path"]
    assert row["safe_review_notes"] == [
        "Review the referenced static evidence and document missing runtime context before drawing conclusions.",
        "Trace a benign sample path through the write call.",
    ]
    assert row["properties"] == {
        "primitive": "file_write",
        "safe_next_steps": ["Trace a benign sample path through the write call."],
    }
    assert "Manual review candidate" in row["summary"]
    assert "does not confirm" in row["summary"]


def test_review_queue_renders_boundary_with_evidence_and_skips_boundary_without_evidence():
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where data reaches file-system operations.",
        evidence=[_evidence("ev_boundary_0001")],
    )
    boundary_without_evidence = BoundaryCandidate(
        id="boundary_0002",
        type=BoundaryType.DATA_TO_URL,
        confidence=Confidence.LOW,
        reason="Candidate boundary without direct evidence.",
    )
    result = _empty_result().model_copy(
        update={"boundaries": [boundary_without_evidence, boundary]}
    )

    rows = _rows(result)

    assert len(rows) == 1
    row = rows[0]
    assert row["category"] == "boundary"
    assert row["candidate_id"] == "boundary_0001"
    assert row["kind"] == "data_to_file"
    assert row["confidence"] == "medium"
    assert row["evidence_ids"] == ["ev_boundary_0001"]
    assert row["properties"] == {
        "boundary_type": "data_to_file",
        "reason": "Candidate boundary where data reaches file-system operations.",
    }
    assert "manual review" in row["summary"].lower()


def test_review_queue_renders_static_flow_candidate_row():
    flow_evidence = Evidence(
        id="ev_flow_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="routes.xml",
        line=4,
        pattern="product_api_xml",
        snippet="SERVLET_CLASS_NAME=com.example.ReportServlet",
    )
    flow = StaticFlowCandidate(
        id="flow_0001",
        source_entrypoint_id="ep_0001",
        target_ref_id="cons_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.HIGH,
        score=110,
        summary="Candidate static flow from `ep_0001` to `cons_0001` based on handler overlap.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.HANDLER_CLASS,
                term="ReportServlet",
                score=60,
                evidence_ids=["ev_flow_0001"],
            )
        ],
        evidence=[flow_evidence],
        missing_evidence=["confirm runtime dispatch"],
    )
    result = _empty_result().model_copy(update={"static_flow_candidates": [flow]})

    rows = _rows(result)

    assert len(rows) == 1
    row = rows[0]
    assert row["category"] == "static_flow"
    assert row["candidate_id"] == "flow_0001"
    assert row["kind"] == "consumer"
    assert row["primary_file"] == "routes.xml"
    assert row["primary_line"] == 4
    assert row["missing_evidence"] == ["confirm runtime dispatch"]
    assert row["properties"] == {
        "flow_summary": "Candidate static flow from `ep_0001` to `cons_0001` based on handler overlap.",
        "score": 110,
        "signals": [
            {
                "evidence_ids": ["ev_flow_0001"],
                "score": 60,
                "term": "ReportServlet",
                "type": "handler_class",
            }
        ],
        "source_entrypoint_id": "ep_0001",
        "target_ref_id": "cons_0001",
        "target_type": "consumer",
    }


def test_review_queue_rows_include_focus_metadata():
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[_evidence("ev_primitive_0001")],
    )
    result = _empty_result().model_copy(
        update={
            "focus": {
                "mode": "import-upload",
                "label": "Import / Upload",
                "description": "Prioritizes import and upload surfaces.",
                "boundary_matches": 0,
                "primitive_matches": 1,
                "static_flow_matches": 0,
                "total_matches": 1,
            },
            "primitive_candidates": [primitive],
        }
    )

    row = _rows(result)[0]

    assert row["focus_mode"] == "import-upload"
    assert row["focus_match"] is True
    assert row["focus_score"] >= 50
    assert "primitive:file_write" in row["focus_reasons"]


def test_review_queue_sorts_focus_matches_before_non_matches():
    url_primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.URL_CONTROL,
        confidence=Confidence.MEDIUM,
        evidence=[_evidence("ev_url_0001")],
    )
    file_primitive = PrimitiveCandidate(
        id="primitive_0002",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[_evidence("ev_file_0001")],
    )
    result = _empty_result().model_copy(
        update={
            "focus": {
                "mode": "import-upload",
                "label": "Import / Upload",
                "description": "Prioritizes import and upload surfaces.",
                "boundary_matches": 0,
                "primitive_matches": 1,
                "static_flow_matches": 0,
                "total_matches": 1,
            },
            "primitive_candidates": [url_primitive, file_primitive],
        }
    )

    rows = _rows(result)

    assert [row["candidate_id"] for row in rows] == ["primitive_0002", "primitive_0001"]
    assert rows[0]["focus_match"] is True
    assert rows[1]["focus_match"] is False


def test_review_queue_rows_are_sorted_deterministically():
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where data reaches file-system operations.",
        evidence=[_evidence("ev_boundary_0001")],
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[_evidence("ev_primitive_0001")],
    )
    flow = StaticFlowCandidate(
        id="flow_0001",
        source_entrypoint_id="ep_0001",
        target_ref_id="worker_0001",
        target_type=StaticFlowTargetType.WORKER,
        confidence=Confidence.MEDIUM,
        score=80,
        summary="Candidate static flow from entrypoint to worker.",
        evidence=[_evidence("ev_flow_0001")],
    )
    result = _empty_result().model_copy(
        update={
            "static_flow_candidates": [flow],
            "primitive_candidates": [primitive],
            "boundaries": [boundary],
        }
    )

    rows = _rows(result)

    assert [(row["category"], row["kind"], row["candidate_id"]) for row in rows] == [
        ("boundary", "data_to_file", "boundary_0001"),
        ("primitive", "file_write", "primitive_0001"),
        ("static_flow", "worker", "flow_0001"),
    ]
    assert render_review_queue_jsonl(result) == render_review_queue_jsonl(result)


def test_review_queue_uses_safe_language():
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.PATH_CONTROL,
        confidence=Confidence.MEDIUM,
        evidence=[_evidence()],
    )
    result = _empty_result().model_copy(update={"primitive_candidates": [primitive]})

    rendered = render_review_queue_jsonl(result).lower()

    assert "candidate" in rendered or "manual review" in rendered
    assert "confirmed vulnerable" not in rendered
    assert "confirmed exploitable" not in rendered
    assert "confirmed exploitability" not in rendered
    assert "exploitability proved" not in rendered
    assert "exploit payload" not in rendered
    assert "payload to exploit" not in rendered
    assert "exploit steps" not in rendered
    assert "auto-fix" not in rendered
