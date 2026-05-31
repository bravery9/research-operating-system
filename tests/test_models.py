from pathlib import Path

from invariant_os.core.evidence import build_pattern_evidence, make_evidence_id
from invariant_os.core.models import (
    AUDIT_SCHEMA_VERSION,
    REVIEW_QUEUE_SCHEMA_VERSION,
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
    FocusMetadata,
    PatchChangedFile,
    PatchChangeType,
    PatchCorrelation,
    PatchCorrelationType,
    PatchDiffInputType,
    PatchDiffResult,
    PatchDiffSummary,
    PatchHunk,
    PatchVariantCandidate,
    PatchVariantSourceType,
    PrimitiveType,
    Project,
    SafetyMetadata,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
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
            static_flow_candidates=0,
        ),
        safety=SafetyMetadata(),
    )

    dumped = result.model_dump(mode="json")

    assert dumped["schema_version"] == AUDIT_SCHEMA_VERSION
    assert dumped["tool"] == "invariant-os"
    assert dumped["static_flow_candidates"] == []
    assert dumped["summary"]["static_flow_candidates"] == 0
    assert dumped["safety"]["principle"] == "LLM proposes. Tools prove. Human approves."


def test_default_safety_metadata_includes_static_workspace_limitations():
    limitations = " ".join(SafetyMetadata().limitations).lower()

    assert "target code execution" in limitations
    assert "network" in limitations
    assert "public target scanning" in limitations
    assert "exploit payload" in limitations
    assert "static candidates" in limitations
    assert "human review" in limitations


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
    assert [item.value for item in StaticFlowTargetType] == ["consumer", "worker"]
    assert [item.value for item in StaticFlowSignalType] == [
        "handler_exact",
        "handler_class",
        "handler_method",
        "declared_parameter",
        "request_parameter",
        "route_token",
        "same_file_proximity",
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
    assert [item.value for item in PatchDiffInputType] == ["patch_file", "git_diff"]
    assert [item.value for item in PatchChangeType] == [
        "added",
        "modified",
        "deleted",
        "renamed",
    ]
    assert [item.value for item in PatchCorrelationType] == [
        "line_overlap",
        "line_proximity",
        "same_file",
    ]
    assert [item.value for item in PatchVariantSourceType] == [
        "evidence",
        "boundary",
        "primitive",
        "static_flow",
    ]


def test_evidence_graph_models_have_expected_wire_values():
    assert [item.value for item in EvidenceGraphNodeType] == [
        "file",
        "entrypoint",
        "consumer",
        "worker",
        "boundary",
        "primitive",
        "static_flow",
    ]
    assert [item.value for item in EvidenceGraphEdgeType] == [
        "defined_in",
        "same_file_correlation",
        "handler_name_correlation",
        "route_to_worker_candidate",
        "route_to_consumer_candidate",
        "boundary_evidence",
        "primitive_evidence",
        "static_flow_source",
        "static_flow_target",
    ]


def test_audit_result_defaults_to_empty_evidence_graph_and_schema_010():
    result = AuditResult(
        project=Project(name="example", root="/repo"),
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

    assert result.schema_version == "0.10"
    assert result.schema_version == AUDIT_SCHEMA_VERSION
    assert result.evidence_graph.nodes == []
    assert result.evidence_graph.edges == []


def test_audit_result_defaults_to_all_focus_metadata():
    result = AuditResult(
        project=Project(name="example", root="/repo"),
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

    assert result.focus == FocusMetadata(
        mode="all",
        label="All Evidence",
        description="Default lens over all deterministic audit evidence.",
        boundary_matches=0,
        primitive_matches=0,
        static_flow_matches=0,
        total_matches=0,
    )


def test_schema_version_constants_are_aligned_for_v010_release():
    assert AUDIT_SCHEMA_VERSION == "0.10"
    assert REVIEW_QUEUE_SCHEMA_VERSION == "0.10"


def test_patch_diff_result_defaults_to_schema_07_and_safe_metadata():
    result = PatchDiffResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/repo/audit_result.json",
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
        changed_files=[
            PatchChangedFile(
                id="patch_file_0001",
                old_path="app.py",
                new_path="app.py",
                change_type=PatchChangeType.MODIFIED,
                hunks=[
                    PatchHunk(
                        id="patch_hunk_0001_0001",
                        old_start=10,
                        old_count=3,
                        new_start=10,
                        new_count=4,
                        added_lines=[12],
                        removed_lines=[11],
                        context="handler",
                    )
                ],
            )
        ],
        correlations=[
            PatchCorrelation(
                id="patch_corr_0001",
                type=PatchCorrelationType.LINE_OVERLAP,
                changed_file_id="patch_file_0001",
                hunk_id="patch_hunk_0001_0001",
                related_id="primitive_0001",
                related_type=PatchVariantSourceType.PRIMITIVE,
                file="app.py",
                line=12,
                confidence=Confidence.MEDIUM,
                reason="Candidate correlation because changed lines overlap existing audit evidence.",
                evidence_ids=["ev_0001"],
                missing_evidence=[
                    "confirm whether the changed code affects the audited path before drawing conclusions"
                ],
            )
        ],
        variant_candidates=[
            PatchVariantCandidate(
                id="patch_variant_0001",
                source_type=PatchVariantSourceType.PRIMITIVE,
                source_id="primitive_0001",
                changed_file_id="patch_file_0001",
                hunk_id="patch_hunk_0001_0001",
                confidence=Confidence.MEDIUM,
                title="Patch-adjacent primitive hypothesis primitive_0001",
                summary="Candidate variant review item only.",
                related_ids=["primitive_0001"],
                evidence_ids=["ev_0001"],
                missing_evidence=[
                    "confirm data origin, validation, authorization, and sink semantics with benign local review"
                ],
                safe_next_steps=[
                    "Review the changed lines and linked audit evidence locally without executing target code."
                ],
            )
        ],
        summary=PatchDiffSummary(
            changed_files=1,
            hunks=1,
            correlations=1,
            variant_candidates=1,
            files_with_audit_context=1,
        ),
    )

    dumped = result.model_dump(mode="json")

    assert dumped["schema_version"] == "0.7"
    assert dumped["tool"] == "invariant-os"
    assert dumped["input_type"] == "patch_file"
    assert dumped["changed_files"][0]["change_type"] == "modified"
    assert dumped["correlations"][0]["type"] == "line_overlap"
    assert dumped["variant_candidates"][0]["source_type"] == "primitive"
    assert dumped["safety"]["principle"] == "LLM proposes. Tools prove. Human approves."



def test_static_flow_candidate_serializes_evidence_and_signals():
    evidence = Evidence(
        id="ev_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="WEB-INF/web.xml",
        line=10,
        pattern="servlet-class",
        snippet="com.example.ReportServlet",
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
                type=StaticFlowSignalType.HANDLER_EXACT,
                term="com.example.ReportServlet",
                score=90,
                evidence_ids=["ev_0001"],
            )
        ],
        evidence=[evidence],
        missing_evidence=["confirm runtime dispatch"],
    )

    dumped = candidate.model_dump(mode="json")

    assert dumped == {
        "id": "flow_0001",
        "source_entrypoint_id": "ep_0001",
        "target_ref_id": "cons_0001",
        "target_type": "consumer",
        "confidence": "high",
        "score": 110,
        "summary": "Candidate static flow from `ep_0001` to `cons_0001` based on handler overlap.",
        "signals": [
            {
                "type": "handler_exact",
                "term": "com.example.ReportServlet",
                "score": 90,
                "evidence_ids": ["ev_0001"],
            }
        ],
        "evidence": [evidence.model_dump(mode="json")],
        "missing_evidence": ["confirm runtime dispatch"],
    }


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
