import invariant_os.analysis.graph as graph_module
from invariant_os.analysis.graph import build_evidence_graph
from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Consumer,
    ConsumerType,
    Entrypoint,
    EntrypointType,
    Evidence,
    EvidenceGraphEdgeType,
    EvidenceGraphNodeType,
    EvidenceType,
    FileRecord,
    PrimitiveCandidate,
    PrimitiveType,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
    Worker,
    WorkerType,
)


def _evidence(evidence_id: str, file: str, line: int, pattern: str) -> Evidence:
    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file=file,
        line=line,
        pattern=pattern,
        snippet=pattern,
    )


def test_build_evidence_graph_adds_file_detection_nodes_and_defined_in_edges():
    files = [FileRecord(path="app.js", language="javascript", size_bytes=10, sha256="abc")]
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="app.js",
        line=3,
        method="post",
        route_path="/import",
        framework_hint="express",
        evidence=[_evidence("ev_ep_0001", "app.js", 3, "express_route")],
    )
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.FILE_OPERATION,
        file="app.js",
        line=9,
        pattern="file_operation",
        evidence=[_evidence("ev_cons_0001", "app.js", 9, "file_operation")],
    )

    graph = build_evidence_graph(
        files=files,
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    node_types = {node.type for node in graph.nodes}
    assert EvidenceGraphNodeType.FILE in node_types
    assert EvidenceGraphNodeType.ENTRYPOINT in node_types
    assert EvidenceGraphNodeType.CONSUMER in node_types
    defined_edges = [edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.DEFINED_IN]
    assert len(defined_edges) == 2
    assert all(edge.confidence == Confidence.HIGH for edge in defined_edges)


def test_build_evidence_graph_correlates_same_file_entrypoint_to_consumer():
    files = [FileRecord(path="app.js", language="javascript", size_bytes=10, sha256="abc")]
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="app.js",
        line=3,
        method="post",
        route_path="/import",
        evidence=[_evidence("ev_ep_0001", "app.js", 3, "express_route")],
    )
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.FILE_OPERATION,
        file="app.js",
        line=9,
        pattern="file_operation",
        evidence=[_evidence("ev_cons_0001", "app.js", 9, "file_operation")],
    )

    graph = build_evidence_graph(
        files=files,
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    edge = next(edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.SAME_FILE_CORRELATION)
    assert edge.confidence == Confidence.MEDIUM
    assert edge.evidence_ids == ["ev_ep_0001", "ev_cons_0001"]
    assert "does not prove dataflow" in edge.missing_evidence[0]


def test_build_evidence_graph_correlates_handler_name_to_worker_snippet():
    files = [
        FileRecord(path="conf/adap/rest-api.xml", language="xml", size_bytes=10, sha256="abc"),
        FileRecord(path="conf/adap/taskflow.xml", language="xml", size_bytes=10, sha256="def"),
    ]
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="conf/adap/rest-api.xml",
        line=4,
        route_path="/report/data",
        handler="com.example.ReportHandler#getData",
        framework_hint="adap-rest-api",
        evidence=[_evidence("ev_ep_0001", "conf/adap/rest-api.xml", 4, "adap_rest_api_mapping")],
    )
    worker = Worker(
        id="worker_0001",
        type=WorkerType.BACKGROUND_TASK,
        file="conf/adap/taskflow.xml",
        line=8,
        framework_hint="taskengine",
        pattern="taskengine_task",
        evidence=[
            Evidence(
                id="ev_worker_0001",
                type=EvidenceType.PATTERN_MATCH,
                file="conf/adap/taskflow.xml",
                line=8,
                pattern="taskengine_task",
                snippet='<TaskEngine_Task class_name="com.example.ReportHandler" />',
            )
        ],
    )

    graph = build_evidence_graph(
        files=files,
        entrypoints=[entrypoint],
        consumers=[],
        workers=[worker],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    edge = next(edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION)
    assert edge.confidence == Confidence.MEDIUM
    assert edge.evidence_ids == ["ev_ep_0001", "ev_worker_0001"]


def test_build_evidence_graph_links_boundaries_and_primitives_to_detection_evidence():
    evidence = _evidence("ev_cons_0001", "app.js", 9, "file_operation")
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.FILE_OPERATION,
        file="app.js",
        line=9,
        pattern="file_operation",
        evidence=[evidence],
    )
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where application data reaches file-system operations.",
        evidence=[evidence],
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.MEDIUM,
        evidence=[evidence],
        missing_evidence=["confirm data influence"],
        safe_next_steps=["Trace benign sample data."],
    )

    graph = build_evidence_graph(
        files=[FileRecord(path="app.js", language="javascript", size_bytes=10, sha256="abc")],
        entrypoints=[],
        consumers=[consumer],
        workers=[],
        boundaries=[boundary],
        primitive_candidates=[primitive],
        static_flow_candidates=[],
    )

    assert any(node.type == EvidenceGraphNodeType.BOUNDARY and node.ref_id == "boundary_0001" for node in graph.nodes)
    assert any(node.type == EvidenceGraphNodeType.PRIMITIVE and node.ref_id == "primitive_0001" for node in graph.nodes)
    assert any(edge.type == EvidenceGraphEdgeType.BOUNDARY_EVIDENCE for edge in graph.edges)
    assert any(edge.type == EvidenceGraphEdgeType.PRIMITIVE_EVIDENCE for edge in graph.edges)


def test_build_evidence_graph_adds_enterprise_route_candidate_edges():
    files = [
        FileRecord(path="conf/adap/rest-api.xml", language="xml", size_bytes=10, sha256="abc"),
        FileRecord(path="conf/TaskEngine.xml", language="xml", size_bytes=10, sha256="def"),
        FileRecord(path="src/com/example/ReportServlet.java", language="java", size_bytes=10, sha256="ghi"),
    ]
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="conf/adap/rest-api.xml",
        line=4,
        route_path="/reports/export",
        handler="com.example.ReportServlet#exportReport",
        framework_hint="product-api-xml",
        evidence=[_evidence("ev_ep_0001", "conf/adap/rest-api.xml", 4, "product_api_xml")],
    )
    worker = Worker(
        id="worker_0001",
        type=WorkerType.BACKGROUND_TASK,
        file="conf/TaskEngine.xml",
        line=8,
        framework_hint="taskengine",
        pattern="taskengine_task",
        evidence=[
            _evidence(
                "ev_worker_0001",
                "conf/TaskEngine.xml",
                8,
                '<TaskEngine_Task class_name="com.example.ReportServlet" task_name="exportReport" />',
            )
        ],
    )
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.DATABASE_OPERATION,
        file="src/com/example/ReportServlet.java",
        line=12,
        pattern="database_operation",
        evidence=[
            _evidence(
                "ev_cons_0001",
                "src/com/example/ReportServlet.java",
                12,
                "com.example.ReportServlet executeQuery",
            )
        ],
    )

    graph = build_evidence_graph(
        files=files,
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[worker],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    worker_edge = next(
        edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.ROUTE_TO_WORKER_CANDIDATE
    )
    consumer_edge = next(
        edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.ROUTE_TO_CONSUMER_CANDIDATE
    )
    entrypoint_node = next(node for node in graph.nodes if node.ref_id == "ep_0001")
    worker_node = next(node for node in graph.nodes if node.ref_id == "worker_0001")
    consumer_node = next(node for node in graph.nodes if node.ref_id == "cons_0001")

    assert worker_edge.source == entrypoint_node.id
    assert worker_edge.target == worker_node.id
    assert worker_edge.evidence_ids == ["ev_ep_0001", "ev_worker_0001"]
    assert "runtime dispatch" in worker_edge.missing_evidence[0]
    assert consumer_edge.source == entrypoint_node.id
    assert consumer_edge.target == consumer_node.id
    assert consumer_edge.evidence_ids == ["ev_ep_0001", "ev_cons_0001"]


def test_build_evidence_graph_projects_static_flow_candidate():
    files = [
        FileRecord(path="routes.xml", language="xml", size_bytes=10, sha256="abc"),
        FileRecord(path="src/ReportServlet.java", language="java", size_bytes=10, sha256="def"),
    ]
    entrypoint_evidence = _evidence("ev_ep_0001", "routes.xml", 4, "product_api_xml")
    consumer_evidence = _evidence("ev_cons_0001", "src/ReportServlet.java", 12, "database_operation")
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="routes.xml",
        line=4,
        route_path="/reports/export",
        handler="com.example.ReportServlet",
        evidence=[entrypoint_evidence],
    )
    consumer = Consumer(
        id="cons_0001",
        type=ConsumerType.DATABASE_OPERATION,
        file="src/ReportServlet.java",
        line=12,
        pattern="database_operation",
        evidence=[consumer_evidence],
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
                evidence_ids=["ev_ep_0001"],
            )
        ],
        evidence=[entrypoint_evidence, consumer_evidence],
        missing_evidence=["confirm runtime dispatch"],
    )

    graph = build_evidence_graph(
        files=files,
        entrypoints=[entrypoint],
        consumers=[consumer],
        workers=[],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[candidate],
    )

    flow_node = next(node for node in graph.nodes if node.ref_id == "flow_0001")
    entrypoint_node = next(node for node in graph.nodes if node.ref_id == "ep_0001")
    consumer_node = next(node for node in graph.nodes if node.ref_id == "cons_0001")
    source_edge = next(edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.STATIC_FLOW_SOURCE)
    target_edge = next(edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.STATIC_FLOW_TARGET)

    assert flow_node.type == EvidenceGraphNodeType.STATIC_FLOW
    assert flow_node.metadata == {"confidence": "high", "score": "110", "target_type": "consumer"}
    assert source_edge.source == entrypoint_node.id
    assert source_edge.target == flow_node.id
    assert target_edge.source == flow_node.id
    assert target_edge.target == consumer_node.id
    assert target_edge.reason == candidate.summary
    assert target_edge.missing_evidence == ["confirm runtime dispatch"]
    assert target_edge.evidence_ids == ["ev_ep_0001", "ev_cons_0001"]


def test_build_evidence_graph_caps_same_file_correlations_per_entrypoint():
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="app.js",
        line=3,
        route_path="/import",
        evidence=[_evidence("ev_ep_0001", "app.js", 3, "express_route")],
    )
    consumers = [
        Consumer(
            id=f"cons_{index:04d}",
            type=ConsumerType.FILE_OPERATION,
            file="app.js",
            line=10 + index,
            pattern="file_operation",
            evidence=[_evidence(f"ev_cons_{index:04d}", "app.js", 10 + index, "file_operation")],
        )
        for index in range(1, 9)
    ]

    graph = build_evidence_graph(
        files=[FileRecord(path="app.js", language="javascript", size_bytes=10, sha256="abc")],
        entrypoints=[entrypoint],
        consumers=consumers,
        workers=[],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    same_file_edges = [
        edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.SAME_FILE_CORRELATION
    ]
    assert len(same_file_edges) == 5
    assert [edge.target for edge in same_file_edges] == [
        "node_consumer_0001",
        "node_consumer_0002",
        "node_consumer_0003",
        "node_consumer_0004",
        "node_consumer_0005",
    ]


def test_build_evidence_graph_caps_handler_name_correlations_per_entrypoint():
    files = [FileRecord(path="routes.xml", language="xml", size_bytes=10, sha256="abc")]
    entrypoint = Entrypoint(
        id="ep_0001",
        type=EntrypointType.HTTP_ROUTE,
        file="routes.xml",
        line=4,
        route_path="/reports/export",
        handler="com.example.ReportHandler#exportReport",
        evidence=[_evidence("ev_ep_0001", "routes.xml", 4, "product_api_xml")],
    )
    workers = []
    for index in range(1, 11):
        file = f"tasks/task_{index}.xml"
        files.append(FileRecord(path=file, language="xml", size_bytes=10, sha256=f"hash{index}"))
        workers.append(
            Worker(
                id=f"worker_{index:04d}",
                type=WorkerType.BACKGROUND_TASK,
                file=file,
                line=index,
                pattern="taskengine_task",
                evidence=[
                    _evidence(
                        f"ev_worker_{index:04d}",
                        file,
                        index,
                        '<TaskEngine_Task class_name="com.example.ReportHandler" />',
                    )
                ],
            )
        )

    graph = build_evidence_graph(
        files=files,
        entrypoints=[entrypoint],
        consumers=[],
        workers=workers,
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    handler_edges = [
        edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION
    ]
    assert len(handler_edges) == 8
    assert [edge.target for edge in handler_edges] == [
        "node_worker_0001",
        "node_worker_0002",
        "node_worker_0003",
        "node_worker_0004",
        "node_worker_0005",
        "node_worker_0006",
        "node_worker_0007",
        "node_worker_0008",
    ]


def test_build_evidence_graph_caps_total_low_signal_correlations(monkeypatch):
    monkeypatch.setattr(graph_module, "MAX_TOTAL_LOW_SIGNAL_CORRELATION_EDGES", 7, raising=False)
    entrypoints = [
        Entrypoint(
            id=f"ep_{index:04d}",
            type=EntrypointType.HTTP_ROUTE,
            file="app.js",
            line=index,
            route_path=f"/route-{index}",
            evidence=[_evidence(f"ev_ep_{index:04d}", "app.js", index, "express_route")],
        )
        for index in range(1, 4)
    ]
    consumers = [
        Consumer(
            id=f"cons_{index:04d}",
            type=ConsumerType.FILE_OPERATION,
            file="app.js",
            line=20 + index,
            pattern="file_operation",
            evidence=[_evidence(f"ev_cons_{index:04d}", "app.js", 20 + index, "file_operation")],
        )
        for index in range(1, 5)
    ]

    graph = build_evidence_graph(
        files=[FileRecord(path="app.js", language="javascript", size_bytes=10, sha256="abc")],
        entrypoints=entrypoints,
        consumers=consumers,
        workers=[],
        boundaries=[],
        primitive_candidates=[],
        static_flow_candidates=[],
    )

    low_signal_edges = [
        edge
        for edge in graph.edges
        if edge.type
        in {
            EvidenceGraphEdgeType.SAME_FILE_CORRELATION,
            EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION,
        }
    ]
    assert len(low_signal_edges) == 7
