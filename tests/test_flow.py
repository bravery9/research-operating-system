from pathlib import Path

from invariant_os.analysis.flow import (
    MAX_STATIC_FLOW_CANDIDATES_PER_ENTRYPOINT,
    enrich_static_flows,
)
from invariant_os.core.models import (
    Confidence,
    Consumer,
    ConsumerType,
    Entrypoint,
    EntrypointType,
    Evidence,
    EvidenceType,
    StaticFlowSignalType,
    StaticFlowTargetType,
    Worker,
    WorkerType,
)


def _evidence(evidence_id: str, file: str, line: int, pattern: str, text: str) -> Evidence:
    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file=file,
        line=line,
        pattern=pattern,
        snippet=text,
        message=text,
        symbol=text,
    )


def _entrypoint(
    *,
    entrypoint_id: str = "ep_0001",
    file: str = "conf/adap/rest-api.xml",
    line: int = 4,
    route_path: str = "/reports/export",
    handler: str | None = "com.example.ReportController#exportReport",
    framework_hint: str | None = "adap-rest-api",
    evidence_text: str = "ACCESS_ID=REPORT_EXPORT param=reportId",
) -> Entrypoint:
    return Entrypoint(
        id=entrypoint_id,
        type=EntrypointType.HTTP_ROUTE,
        file=file,
        line=line,
        route_path=route_path,
        handler=handler,
        framework_hint=framework_hint,
        evidence=[_evidence(f"ev_{entrypoint_id}", file, line, "entrypoint", evidence_text)],
    )


def _consumer(
    *,
    consumer_id: str = "cons_0001",
    file: str = "src/com/example/ReportServlet.java",
    line: int = 12,
    text: str = "class ReportServlet { executeQuery(reportId); }",
) -> Consumer:
    return Consumer(
        id=consumer_id,
        type=ConsumerType.DATABASE_OPERATION,
        file=file,
        line=line,
        symbol="executeQuery",
        pattern="database_operation",
        evidence=[_evidence(f"ev_{consumer_id}", file, line, "database_operation", text)],
    )


def _worker(
    *,
    worker_id: str = "worker_0001",
    text: str = '<TaskEngine_Task task_name="exportReport" class_name="com.example.ReportController" />',
) -> Worker:
    return Worker(
        id=worker_id,
        type=WorkerType.BACKGROUND_TASK,
        file="conf/adap/taskflow.xml",
        line=8,
        framework_hint="taskengine",
        pattern="taskengine_task",
        evidence=[_evidence(f"ev_{worker_id}", "conf/adap/taskflow.xml", 8, "taskengine_task", text)],
    )


def _signal_types(candidate) -> set[StaticFlowSignalType]:
    return {signal.type for signal in candidate.signals}


def test_static_flow_links_exact_handler_to_taskengine_worker(tmp_path: Path):
    entrypoint = _entrypoint()
    worker = _worker()

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=[],
        workers=[worker],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.source_entrypoint_id == "ep_0001"
    assert candidate.target_ref_id == "worker_0001"
    assert candidate.target_type == StaticFlowTargetType.WORKER
    assert candidate.confidence == Confidence.HIGH
    assert StaticFlowSignalType.HANDLER_EXACT in _signal_types(candidate)
    assert [evidence.id for evidence in candidate.evidence] == ["ev_ep_0001", "ev_worker_0001"]
    assert "runtime dispatch" in candidate.missing_evidence[0]
    assert "Candidate static flow" in candidate.summary


def test_static_flow_links_product_api_handler_and_declared_parameter_to_database_consumer(tmp_path: Path):
    entrypoint = _entrypoint(
        handler="com.example.ReportServlet",
        framework_hint="product-api-xml",
        evidence_text="API_URL=/reports/export param=reportId SERVLET_CLASS_NAME=com.example.ReportServlet",
    )
    consumer = _consumer(text="class ReportServlet { executeQuery(reportId); }")

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.target_type == StaticFlowTargetType.CONSUMER
    assert candidate.target_ref_id == "cons_0001"
    assert StaticFlowSignalType.HANDLER_CLASS in _signal_types(candidate)
    assert StaticFlowSignalType.DECLARED_PARAMETER in _signal_types(candidate)


def test_static_flow_extracts_same_file_request_parameter_near_entrypoint(tmp_path: Path):
    source = tmp_path / "src" / "ReportServlet.java"
    source.parent.mkdir()
    source.write_text(
        "class ReportServlet {\n"
        "  void doGet(HttpServletRequest request) {\n"
        "    String reportId = request.getParameter(\"reportId\");\n"
        "    executeQuery(reportId);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    entrypoint = _entrypoint(
        file="src/ReportServlet.java",
        line=2,
        handler=None,
        route_path="/reports/export",
        evidence_text="servlet mapping /reports/export",
    )
    consumer = _consumer(
        file="src/ReportServlet.java",
        line=4,
        text="executeQuery(reportId)",
    )

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
    )

    assert len(candidates) == 1
    request_parameter_signals = [
        signal for signal in candidates[0].signals if signal.type == StaticFlowSignalType.REQUEST_PARAMETER
    ]
    assert [signal.term for signal in request_parameter_signals] == ["reportId"]


def test_static_flow_applies_deterministic_per_entrypoint_cap(tmp_path: Path):
    entrypoint = _entrypoint(handler="com.example.ReportServlet", framework_hint="product-api-xml")
    consumers = [
        _consumer(
            consumer_id=f"cons_{index:04d}",
            text="com.example.ReportServlet executeQuery reportId",
            file=f"src/com/example/ReportServlet{index}.java",
        )
        for index in range(1, MAX_STATIC_FLOW_CANDIDATES_PER_ENTRYPOINT + 4)
    ]

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=consumers,
        workers=[],
    )

    assert len(candidates) == MAX_STATIC_FLOW_CANDIDATES_PER_ENTRYPOINT
    assert [candidate.target_ref_id for candidate in candidates] == [
        f"cons_{index:04d}" for index in range(1, MAX_STATIC_FLOW_CANDIDATES_PER_ENTRYPOINT + 1)
    ]


def test_static_flow_treats_simple_metadata_class_as_class_signal(tmp_path: Path):
    entrypoint = _entrypoint(
        handler=None,
        framework_hint="product-api-xml",
        evidence_text="CLASS_NAME=com.example.ReportServlet",
    )
    consumer = _consumer(text="class ReportServlet { executeQuery(reportId); }")

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
    )

    assert len(candidates) == 1
    assert candidates[0].confidence == Confidence.MEDIUM
    assert StaticFlowSignalType.HANDLER_CLASS in _signal_types(candidates[0])
    assert StaticFlowSignalType.HANDLER_EXACT not in _signal_types(candidates[0])


def test_static_flow_request_parameter_summary_does_not_claim_same_file_without_proximity(
    tmp_path: Path,
):
    source = tmp_path / "src" / "RouteServlet.java"
    source.parent.mkdir()
    source.write_text(
        "class RouteServlet {\n"
        "  void doGet(HttpServletRequest request) {\n"
        "    String reportId = request.getParameter(\"reportId\");\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    entrypoint = _entrypoint(
        file="src/RouteServlet.java",
        line=2,
        handler=None,
        route_path="/reports/export",
        evidence_text="param=reportId",
    )
    consumer = _consumer(
        file="src/ReportDao.java",
        line=20,
        text="executeQuery(reportId, report, export)",
    )

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
    )

    assert len(candidates) == 1
    assert StaticFlowSignalType.REQUEST_PARAMETER in _signal_types(candidates[0])
    assert StaticFlowSignalType.SAME_FILE_PROXIMITY not in _signal_types(candidates[0])
    assert "same-file" not in candidates[0].summary
    assert "request parameter" in candidates[0].summary


def test_static_flow_same_file_proximity_alone_does_not_emit(tmp_path: Path):
    entrypoint = _entrypoint(
        file="src/UnrelatedServlet.java",
        line=10,
        handler=None,
        route_path="/alpha",
        evidence_text="servlet mapping /alpha",
    )
    consumer = _consumer(
        file="src/UnrelatedServlet.java",
        line=12,
        text="executeQuery(unrelatedValue)",
    )

    candidates = enrich_static_flows(
        repo_root=tmp_path,
        files=[],
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
    )

    assert candidates == []
