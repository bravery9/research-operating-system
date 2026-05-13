from pathlib import Path

from invariant_os.core.evidence import build_pattern_evidence, make_evidence_id
from invariant_os.core.models import (
    AuditResult,
    AuditSummary,
    BoundaryType,
    Confidence,
    ConsumerType,
    EntrypointType,
    Evidence,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphEdgeType,
    EvidenceGraphNode,
    EvidenceGraphNodeType,
    EvidenceType,
    FileRecord,
    PrimitiveType,
    Project,
    SafetyMetadata,
    WorkerType,
)


def test_audit_result_json_dump_includes_schema_tool_and_safety_principle():
    result = AuditResult(
        project=Project(name="example", root="/repo"),
        files=[
            FileRecord(
                path="app.py",
                language="python",
                size_bytes=123,
                sha256="abc123",
            )
        ],
        entrypoints=[],
        consumers=[],
        workers=[],
        boundaries=[],
        primitive_candidates=[],
        summary=AuditSummary(
            files=1,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
        ),
        safety=SafetyMetadata(),
    )

    dumped = result.model_dump(mode="json")

    assert dumped["schema_version"] == "0.3"
    assert dumped["tool"] == "invariant-os"
    assert dumped["safety"]["principle"] == "LLM proposes. Tools prove. Human approves."


def test_enum_values_are_expected_wire_values():
    assert [item.value for item in EntrypointType] == [
        "http_route",
        "cli_command",
        "webhook",
        "graphql_resolver",
        "rpc_handler",
        "generic",
    ]
    assert [item.value for item in ConsumerType] == [
        "file_operation",
        "network_operation",
        "process_operation",
        "template_operation",
        "deserialization",
        "config_operation",
        "queue_operation",
        "archive_operation",
        "parser_operation",
        "database_operation",
        "directory_operation",
    ]
    assert [item.value for item in WorkerType] == [
        "queue_worker",
        "cron_job",
        "background_task",
        "event_consumer",
    ]
    assert [item.value for item in EvidenceType] == [
        "code_reference",
        "pattern_match",
        "boundary_rule",
        "llm_hypothesis",
        "static_analysis_hit",
        "manual_note",
        "test_result",
    ]
    assert [item.value for item in Confidence] == ["low", "medium", "high"]
    assert [item.value for item in BoundaryType] == [
        "request_to_worker",
        "data_to_file",
        "data_to_url",
        "data_to_template",
        "data_to_config",
        "data_to_job",
        "external_to_internal",
        "low_priv_to_privileged_consumer",
        "parser_to_consumer",
        "data_to_database",
        "data_to_directory",
    ]
    assert [item.value for item in PrimitiveType] == [
        "path_control",
        "file_write",
        "file_read",
        "url_control",
        "internal_request_trigger",
        "template_control",
        "type_control",
        "job_control",
        "config_control",
        "cache_poisoning",
        "auth_context_confusion",
        "tenant_confusion",
        "parser_differential",
        "query_control",
        "directory_query_control",
    ]


def test_evidence_graph_models_have_expected_wire_values():
    assert [item.value for item in EvidenceGraphNodeType] == [
        "file",
        "entrypoint",
        "consumer",
        "worker",
        "boundary",
        "primitive",
    ]
    assert [item.value for item in EvidenceGraphEdgeType] == [
        "defined_in",
        "same_file_correlation",
        "handler_name_correlation",
        "route_to_worker_candidate",
        "route_to_consumer_candidate",
        "boundary_evidence",
        "primitive_evidence",
    ]


def test_audit_result_defaults_to_empty_evidence_graph_and_schema_03():
    result = AuditResult(
        project=Project(name="example", root="/repo"),
        summary=AuditSummary(
            files=0,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
        ),
    )

    dumped = result.model_dump(mode="json")

    assert dumped["schema_version"] == "0.3"
    assert dumped["evidence_graph"] == {"nodes": [], "edges": []}


def test_evidence_graph_edge_stores_candidate_reason_and_evidence_ids():
    graph = EvidenceGraph(
        nodes=[
            EvidenceGraphNode(
                id="node_entrypoint_0001",
                type=EvidenceGraphNodeType.ENTRYPOINT,
                label="POST /import",
                ref_id="ep_0001",
                file="app.js",
                line=12,
            ),
            EvidenceGraphNode(
                id="node_consumer_0001",
                type=EvidenceGraphNodeType.CONSUMER,
                label="file_operation",
                ref_id="cons_0001",
                file="app.js",
                line=20,
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
                missing_evidence=["confirm whether request data reaches this consumer"],
            )
        ],
    )

    assert graph.edges[0].reason.startswith("Candidate correlation")
    assert graph.edges[0].missing_evidence == ["confirm whether request data reaches this consumer"]


def test_evidence_stores_file_and_line():
    evidence = Evidence(
        id="ev_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=10,
        pattern="@app.post",
        snippet='@app.post("/upload")',
    )

    assert evidence.file == "app.py"
    assert evidence.line == 10


def test_make_evidence_id_formats_zero_padded_identifier():
    assert make_evidence_id(42) == "ev_0042"


def test_build_pattern_evidence_uses_explicit_id_and_normalizes_fields():
    evidence = build_pattern_evidence(
        evidence_id="ev_0042",
        repo_root=Path("/repo"),
        file_path=Path("/repo/app/routes.py"),
        line=27,
        pattern="@app.post",
        snippet='  @app.post("/upload")  \n',
    )

    assert evidence.id == "ev_0042"
    assert evidence.type == EvidenceType.PATTERN_MATCH
    assert evidence.file == "app/routes.py"
    assert evidence.line == 27
    assert evidence.pattern == "@app.post"
    assert evidence.snippet == '@app.post("/upload")'
    assert evidence.message is None


def test_build_pattern_evidence_includes_optional_message():
    evidence = build_pattern_evidence(
        evidence_id="ev_0043",
        repo_root=Path("/repo"),
        file_path=Path("/repo/app/routes.py"),
        line=28,
        pattern="open(",
        snippet="  open(user_path)  ",
        message="Potential user-controlled file operation",
    )

    assert evidence.id == "ev_0043"
    assert evidence.message == "Potential user-controlled file operation"
