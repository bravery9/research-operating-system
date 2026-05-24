from invariant_os.core.models import (
    AUDIT_SCHEMA_VERSION,
    AuditResult,
    AuditSummary,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Consumer,
    ConsumerType,
    Entrypoint,
    EntrypointType,
    Evidence,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphEdgeType,
    EvidenceGraphNode,
    EvidenceGraphNodeType,
    EvidenceType,
    PrimitiveCandidate,
    PrimitiveType,
    Project,
    ReasoningCategory,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
)
from invariant_os.reasoning.engine import build_reasoning_result


FORBIDDEN_PHRASES = [
    "confirmed vulnerable",
    "confirmed exploitable",
    "exploitability proved",
    "payload to exploit",
]


def _evidence(evidence_id: str, file: str = "app.py", line: int = 12) -> Evidence:
    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file=file,
        line=line,
        pattern="test_pattern",
        snippet="candidate code reference",
    )


def _audit_with_boundary_primitive_and_flow() -> AuditResult:
    ev_entry = _evidence("ev_entry_0001", "routes.py", 5)
    ev_consumer = _evidence("ev_cons_0001", "repo.py", 20)
    ev_primitive = _evidence("ev_primitive_0001", "repo.py", 20)
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="routes.py",
        line=5,
        method="POST",
        route_path="/reports/export",
        handler="ReportController#export",
        evidence=[ev_entry],
    )
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.DATABASE_OPERATION,
        file="repo.py",
        line=20,
        symbol="executeQuery",
        pattern="database_operation",
        evidence=[ev_consumer],
    )
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_DATABASE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where request-shaped data reaches database operations.",
        evidence=[ev_entry, ev_consumer],
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.QUERY_CONTROL,
        confidence=Confidence.MEDIUM,
        evidence=[ev_primitive],
        missing_evidence=["confirm whether request-controlled data reaches query construction"],
        safe_next_steps=["Trace a benign query parameter through the candidate database path."],
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
                term="ReportController",
                score=60,
                evidence_ids=["ev_entry_0001"],
            )
        ],
        evidence=[ev_entry, ev_consumer],
        missing_evidence=["confirm runtime dispatch"],
    )
    graph = EvidenceGraph(
        nodes=[
            EvidenceGraphNode(
                id="node_flow_0001",
                type=EvidenceGraphNodeType.STATIC_FLOW,
                label="flow_0001",
                ref_id="flow_0001",
            ),
            EvidenceGraphNode(
                id="node_entrypoint_0001",
                type=EvidenceGraphNodeType.ENTRYPOINT,
                label="POST /reports/export",
                ref_id="ep_0001",
            ),
        ],
        edges=[
            EvidenceGraphEdge(
                id="edge_0001",
                type=EvidenceGraphEdgeType.STATIC_FLOW_SOURCE,
                source="node_flow_0001",
                target="node_entrypoint_0001",
                confidence=Confidence.HIGH,
                evidence_ids=["ev_entry_0001"],
                reason="Candidate static flow source link.",
                missing_evidence=["confirm runtime dispatch"],
            )
        ],
    )
    return AuditResult(
        project=Project(name="example", root="/repo"),
        entrypoints=[entrypoint],
        consumers=[consumer],
        boundaries=[boundary],
        primitive_candidates=[primitive],
        static_flow_candidates=[flow],
        evidence_graph=graph,
        summary=AuditSummary(
            files=2,
            entrypoints=1,
            consumers=1,
            workers=0,
            boundaries=1,
            primitive_candidates=1,
            static_flow_candidates=1,
        ),
    )


def _audit_evidence_ids(audit: AuditResult) -> set[str]:
    groups = [
        *[item.evidence for item in audit.entrypoints],
        *[item.evidence for item in audit.consumers],
        *[item.evidence for item in audit.workers],
        *[item.evidence for item in audit.boundaries],
        *[item.evidence for item in audit.primitive_candidates],
        *[item.evidence for item in audit.static_flow_candidates],
    ]
    return {evidence.id for group in groups for evidence in group}


def test_reasoning_engine_builds_expected_categories_from_audit_result():
    audit = _audit_with_boundary_primitive_and_flow()

    result = build_reasoning_result(audit, "/tmp/audit_result.json")

    categories = {item.category for item in result.items}
    assert ReasoningCategory.HIGH_VALUE_SURFACE in categories
    assert ReasoningCategory.SECURITY_INVARIANT_HYPOTHESIS in categories
    assert ReasoningCategory.PRIMITIVE_TRIAGE in categories
    assert ReasoningCategory.MISSING_EVIDENCE in categories
    assert ReasoningCategory.SAFE_NEXT_STEP in categories
    assert result.schema_version == "0.6"
    assert result.source_schema_version == AUDIT_SCHEMA_VERSION
    assert result.source_project == audit.project
    assert result.summary.high_value_surfaces > 0
    assert result.summary.invariant_hypotheses > 0
    assert result.summary.primitive_triage_items > 0
    assert result.summary.missing_evidence_items > 0
    assert result.summary.safe_next_steps > 0


def test_reasoning_items_reference_existing_evidence_ids_only():
    audit = _audit_with_boundary_primitive_and_flow()

    result = build_reasoning_result(audit, "/tmp/audit_result.json")

    audit_evidence_ids = _audit_evidence_ids(audit)
    assert audit_evidence_ids
    for item in result.items:
        assert item.evidence_ids or item.related_ids or item.missing_evidence or item.safe_next_steps
        assert set(item.evidence_ids) <= audit_evidence_ids


def test_reasoning_engine_uses_conservative_language():
    audit = _audit_with_boundary_primitive_and_flow()

    result = build_reasoning_result(audit, "/tmp/audit_result.json")
    text = " ".join(
        " ".join(
            [
                item.title,
                item.summary,
                " ".join(item.missing_evidence),
                " ".join(item.safe_next_steps),
            ]
        )
        for item in result.items
    ).lower()

    assert "candidate" in text or "hypothesis" in text
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in text


def test_reasoning_engine_handles_empty_audit_result_without_crashing():
    audit = AuditResult(
        project=Project(name="empty", root="/repo"),
        summary=AuditSummary(
            files=0,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
            static_flow_candidates=0,
        ),
    )

    result = build_reasoning_result(audit, "/tmp/audit_result.json")

    assert result.items == []
    assert result.summary.high_value_surfaces == 0
    assert result.summary.invariant_hypotheses == 0
    assert result.summary.primitive_triage_items == 0
    assert result.summary.missing_evidence_items == 0
    assert result.summary.safe_next_steps == 0
