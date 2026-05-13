from invariant_os.analysis.enterprise_resolver import resolve_enterprise_graph_edges
from invariant_os.core.models import (
    Confidence,
    Consumer,
    ConsumerType,
    Entrypoint,
    EntrypointType,
    Evidence,
    EvidenceGraphEdgeType,
    EvidenceType,
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
    route_path: str = "/reports/export",
    handler: str | None = "com.example.ReportController#exportReport",
    framework_hint: str | None = "adap-rest-api",
    evidence_text: str = "ACCESS_ID=REPORT_EXPORT ACCESS_TYPE=write TAB_NAME=Reports",
) -> Entrypoint:
    return Entrypoint(
        id=entrypoint_id,
        type=EntrypointType.HTTP_ROUTE,
        file="conf/adap/rest-api.xml",
        line=4,
        route_path=route_path,
        handler=handler,
        framework_hint=framework_hint,
        evidence=[_evidence(f"ev_{entrypoint_id}", "conf/adap/rest-api.xml", 4, "adap_rest_api_mapping", evidence_text)],
    )


def _consumer(
    *,
    consumer_id: str = "cons_0001",
    text: str = "class ReportServlet { reportConnection.executeQuery(sql); }",
    file: str = "src/com/example/ReportServlet.java",
) -> Consumer:
    return Consumer(
        id=consumer_id,
        type=ConsumerType.DATABASE_OPERATION,
        file=file,
        line=12,
        symbol="executeQuery",
        pattern="database_operation",
        evidence=[_evidence(f"ev_{consumer_id}", file, 12, "database_operation", text)],
    )


def _worker(
    *,
    worker_id: str = "worker_0001",
    text: str = '<TaskEngine_Task task_name="exportReport" class_name="com.example.ReportController" />',
) -> Worker:
    return Worker(
        id=worker_id,
        type=WorkerType.BACKGROUND_TASK,
        file="conf/TaskEngine.xml",
        line=8,
        framework_hint="taskengine",
        pattern="taskengine_task",
        evidence=[_evidence(f"ev_{worker_id}", "conf/TaskEngine.xml", 8, "taskengine_task", text)],
    )


def test_resolver_links_exact_handler_to_taskengine_worker():
    entrypoint = _entrypoint()
    worker = _worker()

    edges = resolve_enterprise_graph_edges(entrypoints=[entrypoint], consumers=[], workers=[worker])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.edge_type == EvidenceGraphEdgeType.ROUTE_TO_WORKER_CANDIDATE
    assert edge.source_ref == "ep_0001"
    assert edge.target_ref == "worker_0001"
    assert edge.confidence == Confidence.HIGH
    assert edge.evidence_ids == ["ev_ep_0001", "ev_worker_0001"]
    assert "Candidate" in edge.reason
    assert "runtime dispatch" in edge.missing_evidence[0]
    assert "data reaches" in edge.missing_evidence[0]


def test_resolver_links_product_api_servlet_handler_to_consumer():
    entrypoint = _entrypoint(
        handler="com.example.ReportServlet",
        framework_hint="product-api-xml",
        evidence_text="API_URL=/api/reports/export SERVLET_CLASS_NAME=com.example.ReportServlet IS_HS_REQUIRED=true",
    )
    consumer = _consumer(text="com.example.ReportServlet writes report rows with executeQuery")

    edges = resolve_enterprise_graph_edges(entrypoints=[entrypoint], consumers=[consumer], workers=[])

    assert len(edges) == 1
    edge = edges[0]
    assert edge.edge_type == EvidenceGraphEdgeType.ROUTE_TO_CONSUMER_CANDIDATE
    assert edge.source_ref == "ep_0001"
    assert edge.target_ref == "cons_0001"
    assert edge.confidence in {Confidence.MEDIUM, Confidence.HIGH}
    assert edge.evidence_ids == ["ev_ep_0001", "ev_cons_0001"]
    assert "Candidate" in edge.reason


def test_resolver_ignores_generic_stop_word_overlap():
    entrypoint = _entrypoint(
        route_path="/api/get/list",
        handler=None,
        framework_hint="javascript-url-config",
        evidence_text="api get list action method service",
    )
    consumer = _consumer(text="api get list action method service")
    worker = _worker(text="api get list action method service")

    edges = resolve_enterprise_graph_edges(entrypoints=[entrypoint], consumers=[consumer], workers=[worker])

    assert edges == []


def test_resolver_applies_deterministic_per_entrypoint_cap():
    entrypoint = _entrypoint(handler="com.example.ReportServlet", framework_hint="product-api-xml")
    consumers = [
        _consumer(
            consumer_id=f"cons_{index:04d}",
            text="com.example.ReportServlet executeQuery report export",
            file=f"src/com/example/ReportServlet{index}.java",
        )
        for index in range(1, 7)
    ]

    edges = resolve_enterprise_graph_edges(
        entrypoints=[entrypoint],
        consumers=consumers,
        workers=[],
        max_edges_per_entrypoint=3,
    )

    assert [edge.target_ref for edge in edges] == ["cons_0001", "cons_0002", "cons_0003"]
    assert len(edges) == 3
    assert all(edge.score == edges[0].score for edge in edges)
