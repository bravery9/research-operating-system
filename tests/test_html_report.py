from invariant_os.core.models import (
    AuditResult,
    AuditSummary,
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
    SafetyMetadata,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
)
from invariant_os.report.html import render_evidence_viewer


REQUIRED_SECTIONS = [
    "InvariantOS Static Evidence Workspace",
    "Summary",
    "Scope and Safety",
    "Entrypoints",
    "Worker and Background Job Candidates",
    "Dangerous Consumer Inventory",
    "Trust Boundary Candidates",
    "Primitive Candidates",
    "Static Flow/Dataflow Candidates",
    "Evidence Graph Preview",
    "Missing Evidence",
    "Safe Manual Review Steps",
    "Evidence Index",
]


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


def _evidence(evidence_id: str = "ev_flow_0001") -> Evidence:
    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file="routes.xml",
        line=4,
        pattern="product_api_xml",
        snippet="SERVLET_CLASS_NAME=com.example.ReportServlet",
        message="Candidate route metadata for ReportServlet",
    )


def test_evidence_viewer_contains_required_sections_and_safety_banner():
    html = render_evidence_viewer(_empty_result())

    for section in REQUIRED_SECTIONS:
        assert section in html
    assert "authorized local analysis" in html
    assert "does not prove exploitability" in html
    assert "No target code execution" in html
    assert "No network or public target scanning" in html
    assert "No exploit payload generation" in html


def test_evidence_viewer_renders_static_flow_graph_and_evidence_links():
    evidence = _evidence()
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="routes.xml",
        line=4,
        method="POST",
        route_path="/reports/export",
        handler="com.example.ReportServlet",
        evidence=[evidence],
    )
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.DATABASE_OPERATION,
        file="ReportServlet.java",
        line=20,
        symbol="executeQuery",
        pattern="database_operation",
        evidence=[evidence],
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
        evidence=[evidence],
        missing_evidence=["confirm runtime dispatch"],
    )
    result = _empty_result().model_copy(
        update={
            "entrypoints": [entrypoint],
            "consumers": [consumer],
            "static_flow_candidates": [flow],
            "evidence_graph": EvidenceGraph(
                nodes=[
                    EvidenceGraphNode(
                        id="node_entrypoint_0001",
                        type=EvidenceGraphNodeType.ENTRYPOINT,
                        label="POST /reports/export",
                        ref_id="ep_0001",
                        file="routes.xml",
                        line=4,
                    ),
                    EvidenceGraphNode(
                        id="node_static_flow_0001",
                        type=EvidenceGraphNodeType.STATIC_FLOW,
                        label="flow_0001",
                        ref_id="flow_0001",
                    ),
                ],
                edges=[
                    EvidenceGraphEdge(
                        id="edge_0001",
                        type=EvidenceGraphEdgeType.STATIC_FLOW_SOURCE,
                        source="node_static_flow_0001",
                        target="node_entrypoint_0001",
                        confidence=Confidence.HIGH,
                        evidence_ids=["ev_flow_0001"],
                        reason="Candidate static flow source link.",
                        missing_evidence=["confirm runtime dispatch"],
                    )
                ],
            ),
            "summary": AuditSummary(
                files=2,
                entrypoints=1,
                consumers=1,
                workers=0,
                boundaries=0,
                primitive_candidates=0,
                static_flow_candidates=1,
            ),
        }
    )

    html = render_evidence_viewer(result)

    assert "ep_0001" in html
    assert "cons_0001" in html
    assert "flow_0001" in html
    assert "edge_0001" in html
    assert 'id="evidence-ev_flow_0001"' in html
    assert 'href="#evidence-ev_flow_0001"' in html
    assert "handler_class" in html
    assert "ReportServlet" in html
    assert "110" in html
    assert "Candidate static flow" in html
    assert "confirm runtime dispatch" in html


def test_evidence_viewer_escapes_dynamic_content():
    evidence = Evidence(
        id="ev_script_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="routes.xml",
        line=4,
        pattern="route",
        snippet='<script>alert(1)</script>',
        message='<script>alert(1)</script>',
    )
    result = _empty_result().model_copy(
        update={
            "entrypoints": [
                Entrypoint(
                    id="ep_script_0001",
                    type=EntrypointType.HTTP_ROUTE,
                    file="routes.xml",
                    line=4,
                    route_path='/unsafe/<script>alert(1)</script>',
                    evidence=[evidence],
                )
            ],
            "summary": AuditSummary(
                files=1,
                entrypoints=1,
                consumers=0,
                workers=0,
                boundaries=0,
                primitive_candidates=0,
                static_flow_candidates=0,
            ),
        }
    )

    html = render_evidence_viewer(result)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_evidence_viewer_is_self_contained_local_artifact():
    result = _empty_result().model_copy(
        update={
            "entrypoints": [
                Entrypoint(
                    id="ep_url_0001",
                    type=EntrypointType.HTTP_ROUTE,
                    file="routes.xml",
                    line=4,
                    route_path="https://example.com/callback",
                    evidence=[
                        Evidence(
                            id="ev_url_0001",
                            type=EvidenceType.PATTERN_MATCH,
                            file="routes.xml",
                            line=4,
                            pattern="route",
                            snippet="http://example.com/internal",
                        )
                    ],
                )
            ],
            "summary": AuditSummary(
                files=1,
                entrypoints=1,
                consumers=0,
                workers=0,
                boundaries=0,
                primitive_candidates=0,
                static_flow_candidates=0,
            ),
        }
    )

    html = render_evidence_viewer(result)

    assert "http://" not in html
    assert "https://" not in html
    assert "hxxps://example.com/callback" in html
    assert "hxxp://example.com/internal" in html
    assert "src=" not in html
    assert 'href="#' in html or "href=\"#" not in html


def test_evidence_viewer_uses_conservative_wording():
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.PATH_CONTROL,
        confidence=Confidence.MEDIUM,
        evidence=[_evidence("ev_primitive_0001")],
        missing_evidence=["confirm whether request-controlled data reaches the path operation"],
        safe_next_steps=["Trace a benign sample path through the candidate operation."],
    )
    result = _empty_result().model_copy(
        update={
            "primitive_candidates": [primitive],
            "summary": AuditSummary(
                files=1,
                entrypoints=0,
                consumers=0,
                workers=0,
                boundaries=0,
                primitive_candidates=1,
                static_flow_candidates=0,
            ),
        }
    )

    html = render_evidence_viewer(result).lower()

    assert "candidate" in html or "hypothesis" in html
    assert "confirmed vulnerable" not in html
    assert "confirmed exploitable" not in html
    assert "exploitability proved" not in html
    assert "payload to exploit" not in html
