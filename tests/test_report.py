from invariant_os.core.models import (
    AuditResult,
    AuditSummary,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
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
from invariant_os.report.markdown import render_research_brief


REQUIRED_SECTIONS = [
    "# InvariantOS Research Brief",
    "## Scope and Safety",
    "## Summary",
    "## Repository Profile",
    "## Entrypoints",
    "## Worker and Background Job Candidates",
    "## Dangerous Consumer Inventory",
    "## Trust Boundary Candidates",
    "## Primitive Candidates To Investigate",
    "## Static Flow/Dataflow Candidates",
    "## Evidence Graph Summary",
    "## Suggested Security Invariants",
    "## Missing Evidence",
    "## Safe Manual Review Plan",
    "## Appendix: Evidence Index",
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


def test_research_brief_contains_required_sections_and_safety_statement():
    markdown = render_research_brief(_empty_result())

    for section in REQUIRED_SECTIONS:
        assert section in markdown
    assert "authorized local repository analysis" in markdown
    assert "does not prove exploitability" in markdown


def test_research_brief_references_evidence_ids_and_missing_evidence():
    evidence = Evidence(
        id="ev_test_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=12,
        pattern="open(",
        snippet="open(user_path, 'w')",
    )
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where data reaches file-system operations.",
        evidence=[evidence],
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.MEDIUM,
        evidence=[evidence],
        missing_evidence=["confirm whether the file path is data-influenced"],
        safe_next_steps=["Trace a benign sample path through the write call."],
    )
    result = _empty_result().model_copy(
        update={
            "boundaries": [boundary],
            "primitive_candidates": [primitive],
            "summary": AuditSummary(
                files=1,
                entrypoints=0,
                consumers=0,
                workers=0,
                boundaries=1,
                primitive_candidates=1,
                static_flow_candidates=0,
            ),
        }
    )

    markdown = render_research_brief(result)

    assert "ev_test_0001" in markdown
    assert "confirm whether the file path is data-influenced" in markdown
    assert "boundary_0001" in markdown
    assert "primitive_0001" in markdown


def test_research_brief_renders_static_flow_candidates_with_evidence_and_missing_evidence():
    evidence = Evidence(
        id="ev_flow_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="routes.xml",
        line=4,
        pattern="product_api_xml",
        snippet="SERVLET_CLASS_NAME=com.example.ReportServlet",
    )
    candidate = StaticFlowCandidate(
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
            "static_flow_candidates": [candidate],
            "summary": AuditSummary(
                files=1,
                entrypoints=1,
                consumers=1,
                workers=0,
                boundaries=0,
                primitive_candidates=0,
                static_flow_candidates=1,
            ),
        }
    )

    markdown = render_research_brief(result)

    assert "## Static Flow/Dataflow Candidates" in markdown
    assert "flow_0001" in markdown
    assert "ep_0001" in markdown
    assert "cons_0001" in markdown
    assert "consumer" in markdown
    assert "high" in markdown
    assert "110" in markdown
    assert "handler_class" in markdown
    assert "ReportServlet" in markdown
    assert "ev_flow_0001" in markdown
    assert "confirm runtime dispatch" in markdown
    assert "confirmed vulnerable" not in markdown.lower()
    assert "exploitability proved" not in markdown.lower()
    assert "exploit payload" not in markdown.lower()


def test_research_brief_summarizes_evidence_graph_edges():
    result = _empty_result().model_copy(
        update={
            "evidence_graph": EvidenceGraph(
                nodes=[
                    EvidenceGraphNode(
                        id="node_entrypoint_0001",
                        type=EvidenceGraphNodeType.ENTRYPOINT,
                        label="POST /import",
                        ref_id="ep_0001",
                        file="app.js",
                        line=3,
                    ),
                    EvidenceGraphNode(
                        id="node_consumer_0001",
                        type=EvidenceGraphNodeType.CONSUMER,
                        label="file_operation",
                        ref_id="cons_0001",
                        file="app.js",
                        line=9,
                    ),
                ],
                edges=[
                    EvidenceGraphEdge(
                        id="edge_0001",
                        type=EvidenceGraphEdgeType.SAME_FILE_CORRELATION,
                        source="node_entrypoint_0001",
                        target="node_consumer_0001",
                        confidence=Confidence.MEDIUM,
                        evidence_ids=["ev_ep_0001", "ev_cons_0001"],
                        reason="Candidate correlation because both detections are in app.js.",
                        missing_evidence=["same-file correlation does not prove dataflow"],
                    )
                ],
            )
        }
    )

    markdown = render_research_brief(result)

    assert "Evidence Graph Summary" in markdown
    assert "same_file_correlation" in markdown
    assert "same-file correlation does not prove dataflow" in markdown


def test_research_brief_prioritizes_candidate_graph_edges_over_defined_in_preview():
    defined_edges = [
        EvidenceGraphEdge(
            id=f"edge_{index:04d}",
            type=EvidenceGraphEdgeType.DEFINED_IN,
            source=f"node_entrypoint_{index:04d}",
            target="node_file_0001",
            confidence=Confidence.HIGH,
            evidence_ids=[f"ev_{index:04d}"],
            reason=f"Candidate {index} is defined in `app.js`.",
            missing_evidence=[],
        )
        for index in range(1, 22)
    ]
    route_edge = EvidenceGraphEdge(
        id="edge_9999",
        type=EvidenceGraphEdgeType.ROUTE_TO_WORKER_CANDIDATE,
        source="node_entrypoint_0001",
        target="node_worker_0001",
        confidence=Confidence.HIGH,
        evidence_ids=["ev_ep_0001", "ev_worker_0001"],
        reason="Candidate enterprise route-to-worker link from handler evidence.",
        missing_evidence=["confirm runtime dispatch"],
    )
    result = _empty_result().model_copy(
        update={
            "evidence_graph": EvidenceGraph(
                nodes=[
                    EvidenceGraphNode(
                        id="node_file_0001",
                        type=EvidenceGraphNodeType.FILE,
                        label="app.js",
                        file="app.js",
                    )
                ],
                edges=[*defined_edges, route_edge],
            )
        }
    )

    markdown = render_research_brief(result)

    graph_lines = [line for line in markdown.splitlines() if line.startswith("- `edge_")]
    assert len(graph_lines) == 20
    assert "route_to_worker_candidate" in "\n".join(graph_lines)
    assert "Additional graph edges are available in `evidence_graph.json`." in markdown


def test_research_brief_uses_candidate_language_without_confirmed_exploitability_claims():
    markdown = render_research_brief(_empty_result()).lower()

    assert "candidate" in markdown or "hypothesis" in markdown
    assert "confirmed exploitability" not in markdown
    assert "confirmed exploitable" not in markdown
    assert "exploit payload" not in markdown
