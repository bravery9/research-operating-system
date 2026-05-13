# InvariantOS v0.2 Evidence Graph and Flow Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use TDD for every behavior change: write a failing test, verify it fails for the expected reason, implement the smallest static-only change, then run focused tests. Do not commit unless the user explicitly asks.

**Goal:** Add a deterministic evidence graph and conservative flow-correlation layer to InvariantOS so v0.2 can connect entrypoint, handler, worker, consumer, boundary, and primitive candidates without claiming exploitability.

**Architecture:** Keep the existing local-first static pipeline: index files, detect candidates, infer boundaries, classify primitives, then build an evidence graph from already-collected facts. Add graph models to `invariant_os/core/models.py`, graph construction in a new `invariant_os/analysis/graph.py`, a new `evidence_graph.json` artifact, and a compact graph summary in `research_brief.md`. The graph must store candidate relationships with evidence IDs, reasons, confidence, and missing-evidence language; it must not execute target code, resolve runtime dispatch, or claim confirmed dataflow.

**Tech Stack:** Python 3.11+, Pydantic v2, Typer, pytest, ruff, mypy, stdlib JSON/path utilities.

---

## Product and Safety Constraints

Preserve the current product boundary:

```text
LLM proposes. Tools prove. Human approves.
```

Mandatory safety language and behavior:

- Analyze only authorized local directories.
- Static analysis only; do not execute target code, startup scripts, Java classes, or config-defined handlers.
- Do not scan public targets.
- Do not generate exploit payloads, exploit chains, or exploitation instructions.
- Do not claim confirmed exploitability, RCE, compromise, or impact.
- Report candidate/hypothesis relationships, evidence, missing evidence, and safe manual review steps.

The v0.2 graph is a correlation aid, not a proof engine. Use names like `candidate`, `hypothesis`, `correlates`, and `missing evidence`; avoid names like `confirmed_flow`, `exploit_path`, or `vulnerable_path`.

---

## Current v0.1 Baseline

Important current files:

- `invariant_os/core/models.py` — Pydantic models for `AuditResult`, `Entrypoint`, `Consumer`, `Worker`, `BoundaryCandidate`, `PrimitiveCandidate`, `Evidence`, enums, and summary.
- `invariant_os/core/audit.py` — orchestration: index → detect entrypoints/consumers/workers → infer boundaries → classify primitives → return `AuditResult`.
- `invariant_os/core/output.py` — writes `audit_result.json` and `research_brief.md`.
- `invariant_os/analysis/detectors.py` — deterministic local static detectors, including ADAudit security XML and enterprise Java endpoint candidates.
- `invariant_os/analysis/boundary.py` — coarse boundary inference from detection groups.
- `invariant_os/analysis/primitives.py` — primitive classification from boundaries and consumers/workers.
- `invariant_os/report/markdown.py` — conservative Markdown research brief.
- `tests/test_models.py`, `tests/test_audit_cli.py`, `tests/test_report.py` — primary tests to extend.

Current output files:

```text
outputs/audit_result.json
outputs/research_brief.md
```

v0.2 should add:

```text
outputs/evidence_graph.json
```

and include the same graph in `audit_result.json` for single-file consumers.

---

## Proposed Graph Semantics

### Node Types

Add graph nodes for:

- `file` — indexed source/config file.
- `entrypoint` — existing `Entrypoint` candidate.
- `consumer` — existing `Consumer` candidate.
- `worker` — existing `Worker` candidate.
- `boundary` — existing `BoundaryCandidate`.
- `primitive` — existing `PrimitiveCandidate`.

Do not add separate `evidence` nodes in v0.2. Evidence remains embedded in detections and edges by ID/reference to avoid graph bloat on large enterprise repos.

### Edge Types

Add graph edges for:

- `defined_in` — detection candidate is located in a file.
- `same_file_correlation` — entrypoint and consumer/worker are in the same file.
- `handler_name_correlation` — entrypoint handler text correlates with a Java/class/config consumer or worker snippet.
- `route_to_worker_candidate` — request/API/URL config candidate correlates with a TaskEngine or background worker candidate.
- `route_to_consumer_candidate` — request/API/URL config candidate correlates with a dangerous consumer candidate.
- `boundary_evidence` — boundary candidate references detection evidence.
- `primitive_evidence` — primitive candidate references boundary/consumer/worker evidence.

Edge confidence should use existing `Confidence` values:

- `high`: same object/reference edge such as `defined_in`, boundary/primitive evidence edge.
- `medium`: same file or explicit handler/class string appears in both endpoints/config and candidate evidence.
- `low`: broad request-to-worker or route-to-consumer hypothesis where no direct handler/file correlation exists.

---

## Task 1: Add Evidence Graph Models

**Files:**

- Modify: `invariant_os/core/models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Write failing model tests**

Add to `tests/test_models.py`:

```python
from invariant_os.core.models import EvidenceGraph, EvidenceGraphEdge, EvidenceGraphEdgeType, EvidenceGraphNode, EvidenceGraphNodeType


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


def test_audit_result_defaults_to_empty_evidence_graph_and_schema_02():
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

    assert dumped["schema_version"] == "0.2"
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
```

- [ ] **Step 2: Run model tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_models.py -v
```

Expected: fails because `EvidenceGraph`, `EvidenceGraphNode`, `EvidenceGraphEdge`, `EvidenceGraphNodeType`, `EvidenceGraphEdgeType`, and `AuditResult.evidence_graph` do not exist, and schema is still `0.1`.

- [ ] **Step 3: Implement minimal graph models**

Add to `invariant_os/core/models.py` after `PrimitiveType`:

```python
class EvidenceGraphNodeType(str, Enum):
    FILE = "file"
    ENTRYPOINT = "entrypoint"
    CONSUMER = "consumer"
    WORKER = "worker"
    BOUNDARY = "boundary"
    PRIMITIVE = "primitive"


class EvidenceGraphEdgeType(str, Enum):
    DEFINED_IN = "defined_in"
    SAME_FILE_CORRELATION = "same_file_correlation"
    HANDLER_NAME_CORRELATION = "handler_name_correlation"
    ROUTE_TO_WORKER_CANDIDATE = "route_to_worker_candidate"
    ROUTE_TO_CONSUMER_CANDIDATE = "route_to_consumer_candidate"
    BOUNDARY_EVIDENCE = "boundary_evidence"
    PRIMITIVE_EVIDENCE = "primitive_evidence"
```

Add near the detection models:

```python
class EvidenceGraphNode(BaseModel):
    id: str
    type: EvidenceGraphNodeType
    label: str
    ref_id: str | None = None
    file: str | None = None
    line: int | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    id: str
    type: EvidenceGraphEdgeType
    source: str
    target: str
    confidence: Confidence
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class EvidenceGraph(BaseModel):
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)
```

Update `AuditResult`:

```python
class AuditResult(BaseModel):
    project: Project
    files: list[FileRecord] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    consumers: list[Consumer] = Field(default_factory=list)
    workers: list[Worker] = Field(default_factory=list)
    boundaries: list[BoundaryCandidate] = Field(default_factory=list)
    primitive_candidates: list[PrimitiveCandidate] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    summary: AuditSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = "0.2"
    tool: str = "invariant-os"
```

- [ ] **Step 4: Run model tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_models.py -v
```

Expected: all model tests pass after updating existing schema assertions from `0.1` to `0.2`.

---

## Task 2: Build Basic Graph Nodes and `defined_in` Edges

**Files:**

- Create: `invariant_os/analysis/graph.py`
- Create: `tests/test_graph.py`

- [ ] **Step 1: Write failing graph construction test**

Create `tests/test_graph.py`:

```python
from invariant_os.analysis.graph import build_evidence_graph
from invariant_os.core.models import (
    Confidence,
    Consumer,
    ConsumerType,
    Entrypoint,
    EntrypointType,
    Evidence,
    EvidenceType,
    EvidenceGraphEdgeType,
    EvidenceGraphNodeType,
    FileRecord,
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
    )

    node_types = {node.type for node in graph.nodes}
    assert EvidenceGraphNodeType.FILE in node_types
    assert EvidenceGraphNodeType.ENTRYPOINT in node_types
    assert EvidenceGraphNodeType.CONSUMER in node_types
    defined_edges = [edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.DEFINED_IN]
    assert len(defined_edges) == 2
    assert all(edge.confidence == Confidence.HIGH for edge in defined_edges)
```

- [ ] **Step 2: Run graph test and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_graph.py -v
```

Expected: fails because `invariant_os.analysis.graph` does not exist.

- [ ] **Step 3: Implement minimal graph builder**

Create `invariant_os/analysis/graph.py`:

```python
"""Evidence graph construction from deterministic audit candidates."""

from invariant_os.core.models import (
    BoundaryCandidate,
    Confidence,
    Consumer,
    Entrypoint,
    Evidence,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphEdgeType,
    EvidenceGraphNode,
    EvidenceGraphNodeType,
    FileRecord,
    PrimitiveCandidate,
    Worker,
)


def build_evidence_graph(
    *,
    files: list[FileRecord],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
    boundaries: list[BoundaryCandidate],
    primitive_candidates: list[PrimitiveCandidate],
) -> EvidenceGraph:
    nodes: list[EvidenceGraphNode] = []
    edges: list[EvidenceGraphEdge] = []
    node_by_ref: dict[str, str] = {}
    file_node_by_path: dict[str, str] = {}

    for index, record in enumerate(files, start=1):
        node = EvidenceGraphNode(
            id=f"node_file_{index:04d}",
            type=EvidenceGraphNodeType.FILE,
            label=record.path,
            file=record.path,
            metadata={"language": record.language},
        )
        nodes.append(node)
        file_node_by_path[record.path] = node.id

    for entrypoint in entrypoints:
        _add_detection_node(
            nodes,
            edges,
            node_by_ref,
            file_node_by_path,
            ref_id=entrypoint.id,
            node_type=EvidenceGraphNodeType.ENTRYPOINT,
            label=_entrypoint_label(entrypoint),
            file=entrypoint.file,
            line=entrypoint.line,
            evidence=entrypoint.evidence,
        )

    for consumer in consumers:
        _add_detection_node(
            nodes,
            edges,
            node_by_ref,
            file_node_by_path,
            ref_id=consumer.id,
            node_type=EvidenceGraphNodeType.CONSUMER,
            label=consumer.pattern,
            file=consumer.file,
            line=consumer.line,
            evidence=consumer.evidence,
        )

    for worker in workers:
        _add_detection_node(
            nodes,
            edges,
            node_by_ref,
            file_node_by_path,
            ref_id=worker.id,
            node_type=EvidenceGraphNodeType.WORKER,
            label=worker.pattern,
            file=worker.file,
            line=worker.line,
            evidence=worker.evidence,
        )

    # Boundary and primitive nodes/edges are added in later tasks.
    return EvidenceGraph(nodes=nodes, edges=edges)
```

Add helpers in the same file:

```python
def _add_detection_node(
    nodes: list[EvidenceGraphNode],
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    file_node_by_path: dict[str, str],
    *,
    ref_id: str,
    node_type: EvidenceGraphNodeType,
    label: str,
    file: str,
    line: int,
    evidence: list[Evidence],
) -> None:
    node_id = f"node_{node_type.value}_{len([node for node in nodes if node.type == node_type]) + 1:04d}"
    node = EvidenceGraphNode(
        id=node_id,
        type=node_type,
        label=label,
        ref_id=ref_id,
        file=file,
        line=line,
    )
    nodes.append(node)
    node_by_ref[ref_id] = node_id

    file_node_id = file_node_by_path.get(file)
    if file_node_id is None:
        return
    edges.append(
        EvidenceGraphEdge(
            id=f"edge_{len(edges) + 1:04d}",
            type=EvidenceGraphEdgeType.DEFINED_IN,
            source=node_id,
            target=file_node_id,
            confidence=Confidence.HIGH,
            evidence_ids=_evidence_ids(evidence),
            reason=f"Candidate is defined in `{file}`.",
        )
    )


def _entrypoint_label(entrypoint: Entrypoint) -> str:
    parts = [part for part in (entrypoint.method.upper() if entrypoint.method else None, entrypoint.route_path, entrypoint.handler) if part]
    return " ".join(parts) if parts else entrypoint.type.value


def _evidence_ids(evidence: list[Evidence]) -> list[str]:
    return [item.id for item in evidence]
```

If ruff objects to list comprehensions for node counting, replace with a per-type counter dictionary.

- [ ] **Step 4: Run graph test and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_graph.py -v
```

Expected: graph test passes.

---

## Task 3: Add Same-File and Handler Correlation Edges

**Files:**

- Modify: `invariant_os/analysis/graph.py`
- Modify: `tests/test_graph.py`

- [ ] **Step 1: Write failing same-file correlation test**

Add to `tests/test_graph.py`:

```python
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
    )

    edge = next(edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.SAME_FILE_CORRELATION)
    assert edge.confidence == Confidence.MEDIUM
    assert edge.evidence_ids == ["ev_ep_0001", "ev_cons_0001"]
    assert "does not prove dataflow" in edge.missing_evidence[0]
```

- [ ] **Step 2: Write failing handler correlation test**

Add to `tests/test_graph.py`:

```python
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
    )

    edge = next(edge for edge in graph.edges if edge.type == EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION)
    assert edge.confidence == Confidence.MEDIUM
    assert edge.evidence_ids == ["ev_ep_0001", "ev_worker_0001"]
```

Import `Worker`, `WorkerType` in `tests/test_graph.py`.

- [ ] **Step 3: Run tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_graph.py -v
```

Expected: new correlation tests fail because no correlation edges exist.

- [ ] **Step 4: Implement same-file and handler correlation**

In `invariant_os/analysis/graph.py`, after adding nodes, call:

```python
_add_same_file_correlations(edges, node_by_ref, entrypoints, consumers, workers)
_add_handler_correlations(edges, node_by_ref, entrypoints, consumers, workers)
```

Implement:

```python
def _add_same_file_correlations(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
) -> None:
    for entrypoint in entrypoints:
        for target in [*consumers, *workers]:
            if entrypoint.file != target.file:
                continue
            _append_edge(
                edges,
                edge_type=EvidenceGraphEdgeType.SAME_FILE_CORRELATION,
                source=node_by_ref[entrypoint.id],
                target=node_by_ref[target.id],
                confidence=Confidence.MEDIUM,
                evidence_ids=_combined_evidence_ids(entrypoint.evidence, target.evidence),
                reason=f"Candidate correlation because `{entrypoint.id}` and `{target.id}` are in `{entrypoint.file}`.",
                missing_evidence=["same-file correlation does not prove dataflow; confirm source, validation, and sink reachability manually"],
            )
```

Implement handler correlation conservatively:

```python
def _add_handler_correlations(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
) -> None:
    targets = [*consumers, *workers]
    for entrypoint in entrypoints:
        handler_terms = _handler_terms(entrypoint.handler)
        if not handler_terms:
            continue
        for target in targets:
            target_text = _evidence_text(target.evidence)
            if not any(term in target_text for term in handler_terms):
                continue
            _append_edge(
                edges,
                edge_type=EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION,
                source=node_by_ref[entrypoint.id],
                target=node_by_ref[target.id],
                confidence=Confidence.MEDIUM,
                evidence_ids=_combined_evidence_ids(entrypoint.evidence, target.evidence),
                reason=f"Candidate correlation because handler text from `{entrypoint.id}` appears in `{target.id}` evidence.",
                missing_evidence=["confirm runtime dispatch and whether request-controlled data reaches the target candidate"],
            )
```

Add helpers:

```python
def _handler_terms(handler: str | None) -> list[str]:
    if handler is None:
        return []
    class_part = handler.split("#", 1)[0]
    terms = [class_part]
    if "." in class_part:
        terms.append(class_part.rsplit(".", 1)[-1])
    return [term for term in terms if len(term) >= 4]


def _evidence_text(evidence: list[Evidence]) -> str:
    return "\n".join(part for item in evidence for part in (item.snippet or "", item.message or "", item.symbol or ""))


def _combined_evidence_ids(*groups: list[Evidence]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item.id in seen:
                continue
            seen.add(item.id)
            ids.append(item.id)
    return ids


def _append_edge(
    edges: list[EvidenceGraphEdge],
    *,
    edge_type: EvidenceGraphEdgeType,
    source: str,
    target: str,
    confidence: Confidence,
    evidence_ids: list[str],
    reason: str,
    missing_evidence: list[str],
) -> None:
    edges.append(
        EvidenceGraphEdge(
            id=f"edge_{len(edges) + 1:04d}",
            type=edge_type,
            source=source,
            target=target,
            confidence=confidence,
            evidence_ids=evidence_ids,
            reason=reason,
            missing_evidence=missing_evidence,
        )
    )
```

- [ ] **Step 5: Run graph tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_graph.py -v
```

Expected: graph tests pass.

---

## Task 4: Add Boundary and Primitive Graph Nodes/Edges

**Files:**

- Modify: `invariant_os/analysis/graph.py`
- Modify: `tests/test_graph.py`

- [ ] **Step 1: Write failing boundary/primitive edge test**

Add to `tests/test_graph.py`:

```python
from invariant_os.core.models import BoundaryCandidate, BoundaryType, PrimitiveCandidate, PrimitiveType


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
    )

    assert any(node.type == EvidenceGraphNodeType.BOUNDARY and node.ref_id == "boundary_0001" for node in graph.nodes)
    assert any(node.type == EvidenceGraphNodeType.PRIMITIVE and node.ref_id == "primitive_0001" for node in graph.nodes)
    assert any(edge.type == EvidenceGraphEdgeType.BOUNDARY_EVIDENCE for edge in graph.edges)
    assert any(edge.type == EvidenceGraphEdgeType.PRIMITIVE_EVIDENCE for edge in graph.edges)
```

- [ ] **Step 2: Run graph tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_graph.py -v
```

Expected: fails because boundary/primitive graph nodes and evidence edges are missing.

- [ ] **Step 3: Implement boundary and primitive nodes/edges**

In `build_evidence_graph()`, add nodes for boundaries and primitives after detection nodes:

```python
for boundary in boundaries:
    _add_reference_node(
        nodes,
        node_by_ref,
        ref_id=boundary.id,
        node_type=EvidenceGraphNodeType.BOUNDARY,
        label=boundary.type.value,
        metadata={"confidence": boundary.confidence.value},
    )

for primitive in primitive_candidates:
    _add_reference_node(
        nodes,
        node_by_ref,
        ref_id=primitive.id,
        node_type=EvidenceGraphNodeType.PRIMITIVE,
        label=primitive.primitive.value,
        metadata={"confidence": primitive.confidence.value},
    )
```

Add evidence-linking helpers:

```python
_add_evidence_reference_edges(
    edges,
    node_by_ref,
    edge_type=EvidenceGraphEdgeType.BOUNDARY_EVIDENCE,
    sources=boundaries,
    targets=[*entrypoints, *consumers, *workers],
)
_add_evidence_reference_edges(
    edges,
    node_by_ref,
    edge_type=EvidenceGraphEdgeType.PRIMITIVE_EVIDENCE,
    sources=primitive_candidates,
    targets=[*entrypoints, *consumers, *workers, *boundaries],
)
```

Implement:

```python
def _add_reference_node(
    nodes: list[EvidenceGraphNode],
    node_by_ref: dict[str, str],
    *,
    ref_id: str,
    node_type: EvidenceGraphNodeType,
    label: str,
    metadata: dict[str, str],
) -> None:
    node_id = f"node_{node_type.value}_{len([node for node in nodes if node.type == node_type]) + 1:04d}"
    nodes.append(EvidenceGraphNode(id=node_id, type=node_type, label=label, ref_id=ref_id, metadata=metadata))
    node_by_ref[ref_id] = node_id
```

Use a `Protocol` for items with `id` and `evidence` if mypy needs it:

```python
class _GraphEvidenceSource(Protocol):
    id: str
    evidence: list[Evidence]
```

Then:

```python
def _add_evidence_reference_edges(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    *,
    edge_type: EvidenceGraphEdgeType,
    sources: list[_GraphEvidenceSource],
    targets: list[_GraphEvidenceSource],
) -> None:
    targets_by_evidence: dict[str, list[_GraphEvidenceSource]] = {}
    for target in targets:
        for evidence in target.evidence:
            targets_by_evidence.setdefault(evidence.id, []).append(target)

    for source in sources:
        source_node = node_by_ref[source.id]
        linked_targets: set[str] = set()
        for evidence in source.evidence:
            for target in targets_by_evidence.get(evidence.id, []):
                target_node = node_by_ref[target.id]
                if target_node == source_node or target_node in linked_targets:
                    continue
                linked_targets.add(target_node)
                _append_edge(
                    edges,
                    edge_type=edge_type,
                    source=source_node,
                    target=target_node,
                    confidence=Confidence.HIGH,
                    evidence_ids=[evidence.id],
                    reason=f"Candidate graph link because `{source.id}` references evidence from `{target.id}`.",
                    missing_evidence=[],
                )
```

- [ ] **Step 4: Run graph tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_graph.py -v
```

Expected: graph tests pass.

---

## Task 5: Integrate Evidence Graph Into Audit Pipeline

**Files:**

- Modify: `invariant_os/core/audit.py`
- Modify: `tests/test_audit_cli.py`

- [ ] **Step 1: Write failing CLI integration assertions**

Add to `test_audit_writes_json_and_markdown_for_fixture()` in `tests/test_audit_cli.py`:

```python
    assert audit_result.evidence_graph.nodes
    assert audit_result.evidence_graph.edges
    assert any(edge.type.value == "defined_in" for edge in audit_result.evidence_graph.edges)
```

Add to `test_audit_writes_java_tomcat_fixture_signals()`:

```python
    graph_edge_types = {edge.type.value for edge in audit_result.evidence_graph.edges}
    assert "defined_in" in graph_edge_types
    assert "boundary_evidence" in graph_edge_types
    assert "primitive_evidence" in graph_edge_types
    assert any(
        edge.type.value in {"handler_name_correlation", "same_file_correlation", "route_to_worker_candidate", "route_to_consumer_candidate"}
        for edge in audit_result.evidence_graph.edges
    )
```

- [ ] **Step 2: Run CLI tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py -v
```

Expected: fails because `run_audit()` does not populate `evidence_graph` yet.

- [ ] **Step 3: Populate graph in `run_audit()`**

Modify `invariant_os/core/audit.py` imports:

```python
from invariant_os.analysis.graph import build_evidence_graph
```

After primitive classification:

```python
evidence_graph = build_evidence_graph(
    files=files,
    entrypoints=entrypoints,
    consumers=consumers,
    workers=workers,
    boundaries=boundaries,
    primitive_candidates=primitive_candidates,
)
```

Pass into `AuditResult`:

```python
        evidence_graph=evidence_graph,
```

- [ ] **Step 4: Run CLI tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py -v
```

Expected: CLI tests pass.

---

## Task 6: Write `evidence_graph.json` Output Artifact

**Files:**

- Modify: `invariant_os/core/output.py`
- Modify: `invariant_os/cli.py`
- Modify: `tests/test_audit_cli.py`

- [ ] **Step 1: Write failing output artifact test**

In `tests/test_audit_cli.py`, update output checks in tests that assert output files exist:

```python
    graph_path = output_dir / "evidence_graph.json"
    assert graph_path.exists()
```

In `test_audit_writes_json_and_markdown_for_fixture()`, add:

```python
    graph_payload = graph_path.read_text(encoding="utf-8")
    assert '"nodes"' in graph_payload
    assert '"edges"' in graph_payload
```

- [ ] **Step 2: Run CLI tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py -v
```

Expected: fails because `evidence_graph.json` is not written.

- [ ] **Step 3: Write graph artifact**

Modify `invariant_os/core/output.py`:

```python
def write_audit_outputs(result: AuditResult, output_dir: Path) -> tuple[Path, Path, Path]:
    """Write stable JSON, Markdown, and graph audit artifacts."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    json_path = target_dir / "audit_result.json"
    graph_path = target_dir / "evidence_graph.json"
    markdown_path = target_dir / "research_brief.md"

    json_payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    graph_payload = json.dumps(result.evidence_graph.model_dump(mode="json"), indent=2, sort_keys=True)
    json_path.write_text(f"{json_payload}\n", encoding="utf-8")
    graph_path.write_text(f"{graph_payload}\n", encoding="utf-8")
    markdown_path.write_text(render_research_brief(result), encoding="utf-8")

    return json_path, markdown_path, graph_path
```

Modify `invariant_os/cli.py`:

```python
    json_path, markdown_path, graph_path = write_audit_outputs(result, output_dir)
```

and print:

```python
    console.print(f"Evidence graph: {graph_path}")
```

- [ ] **Step 4: Run CLI tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py -v
```

Expected: CLI tests pass.

---

## Task 7: Add Graph Summary to Markdown Brief

**Files:**

- Modify: `invariant_os/report/markdown.py`
- Modify: `tests/test_report.py`

- [ ] **Step 1: Write failing Markdown section test**

Update `REQUIRED_SECTIONS` in `tests/test_report.py` to include:

```python
    "## Evidence Graph Summary",
```

Add a test:

```python
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
```

Add required imports from `invariant_os.core.models`.

- [ ] **Step 2: Run report tests and verify RED**

Run:

```bash
.venv/bin/pytest tests/test_report.py -v
```

Expected: fails because the section is missing.

- [ ] **Step 3: Render graph summary conservatively**

In `render_research_brief()`, add before `## Suggested Security Invariants`:

```python
        "## Evidence Graph Summary",
        "",
        *_render_evidence_graph(result),
        "",
```

Implement:

```python
def _render_evidence_graph(result: AuditResult) -> list[str]:
    if not result.evidence_graph.nodes and not result.evidence_graph.edges:
        return ["No evidence graph candidates were generated."]
    lines = [
        f"- Graph nodes: {len(result.evidence_graph.nodes)}",
        f"- Graph edges: {len(result.evidence_graph.edges)}",
    ]
    for edge in result.evidence_graph.edges[:20]:
        lines.append(
            f"- `{edge.id}` {edge.type.value} ({edge.confidence.value} confidence): "
            f"{edge.reason} Evidence: {_join_or_none(edge.evidence_ids)}. "
            f"Missing evidence: {_join_or_none(edge.missing_evidence)}"
        )
    if len(result.evidence_graph.edges) > 20:
        lines.append("- Additional graph edges are available in `evidence_graph.json`.")
    return lines
```

- [ ] **Step 4: Run report tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_report.py -v
```

Expected: report tests pass and safety-language tests still pass.

---

## Task 8: Add ADAudit-Style Graph Regression

**Files:**

- Modify: `tests/test_audit_cli.py`
- No fixture changes expected unless test reveals insufficient compact fixture coverage.

- [ ] **Step 1: Write failing ADAudit-style graph assertions**

In `test_audit_writes_java_tomcat_fixture_signals()`, add assertions that the compact Tomcat fixture produces meaningful graph correlations:

```python
    graph = audit_result.evidence_graph
    node_labels = {node.label for node in graph.nodes}
    edge_types = {edge.type.value for edge in graph.edges}

    assert any("/reports/export" in label or "/legacy/report.do" in label for label in node_labels)
    assert "defined_in" in edge_types
    assert "boundary_evidence" in edge_types
    assert "primitive_evidence" in edge_types
    assert all("exploit" not in edge.reason.lower() for edge in graph.edges)
```

If the existing fixture does not produce a same-file or handler correlation edge, add one compact fixture relationship rather than weakening the test. For example, add a Java file or XML task where a handler class from a product API mapping appears in a TaskEngine or consumer evidence snippet.

- [ ] **Step 2: Run audit CLI tests and verify RED if needed**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py::test_audit_writes_java_tomcat_fixture_signals -v
```

Expected: either passes if earlier graph work is sufficient, or fails for the missing compact correlation. If it passes immediately, this is acceptable because earlier tests already drove the new behavior; do not force an artificial failure.

- [ ] **Step 3: Fix fixture or graph logic minimally**

Only if the test fails for missing compact correlation, add the smallest fixture content needed under `tests/fixtures/mini_tomcat_app/` using existing detector patterns. Do not add new production detector behavior in this task unless the failure shows the graph builder is incorrectly ignoring already-detected facts.

- [ ] **Step 4: Run audit CLI tests and verify GREEN**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py -v
```

Expected: all CLI tests pass.

---

## Task 9: Documentation Update

**Files:**

- Modify: `README.md`

- [ ] **Step 1: Update output file list**

In `README.md`, under `## Output Files`, add:

```markdown
- `evidence_graph.json`: deterministic graph of candidate relationships between files, entrypoints, workers, consumers, boundaries, primitives, and supporting evidence IDs.
```

- [ ] **Step 2: Update supported detection/reporting areas**

In `README.md`, under `## Supported Detection Areas`, add:

```markdown
- Evidence graph generation for candidate same-file, handler-name, route-to-worker, route-to-consumer, boundary-evidence, and primitive-evidence correlations.
```

- [ ] **Step 3: Update limitations**

In `README.md`, under `## Limitations`, add:

```markdown
- Evidence graph edges are conservative static correlations, not confirmed runtime dataflows.
```

- [ ] **Step 4: Run docs-adjacent tests**

Run:

```bash
.venv/bin/pytest tests/test_audit_cli.py tests/test_report.py -v
```

Expected: tests pass.

---

## Task 10: Full Verification and Local Smoke Audit

**Files:**

- No source changes expected unless verification finds issues.

- [ ] **Step 1: Run focused tests**

Run:

```bash
.venv/bin/pytest tests/test_models.py tests/test_graph.py tests/test_audit_cli.py tests/test_report.py -v
```

Expected: all focused tests pass.

- [ ] **Step 2: Run full quality gates**

Run:

```bash
.venv/bin/ruff check .
.venv/bin/mypy invariant_os
.venv/bin/pytest
```

Expected:

```text
All checks passed!
Success: no issues found
all tests passed
```

- [ ] **Step 3: Run authorized local smoke audit on compact fixture**

Run:

```bash
.venv/bin/python -m invariant_os.cli audit tests/fixtures/mini_tomcat_app --output-dir outputs/mini-tomcat-v02
```

Expected files:

```text
outputs/mini-tomcat-v02/audit_result.json
outputs/mini-tomcat-v02/evidence_graph.json
outputs/mini-tomcat-v02/research_brief.md
```

Inspect the graph artifact with Python, not `jq`, to avoid adding dependencies:

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
payload = json.loads(Path('outputs/mini-tomcat-v02/evidence_graph.json').read_text())
print('nodes', len(payload['nodes']))
print('edges', len(payload['edges']))
print('edge_types', sorted({edge['type'] for edge in payload['edges']}))
assert payload['nodes']
assert payload['edges']
assert 'defined_in' in {edge['type'] for edge in payload['edges']}
assert all('exploit' not in edge['reason'].lower() for edge in payload['edges'])
PY
```

- [ ] **Step 4: Run authorized local smoke audit on ADAudit sample if available**

Only run this if `/home/noname/ADAudit-Plus-8606` exists and remains an authorized local sample:

```bash
.venv/bin/invariant-os audit /home/noname/ADAudit-Plus-8606 --output-dir outputs/adaudit-plus-8606-v02
```

Inspect graph counts:

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
payload = json.loads(Path('outputs/adaudit-plus-8606-v02/evidence_graph.json').read_text())
edge_types = sorted({edge['type'] for edge in payload['edges']})
print('nodes', len(payload['nodes']))
print('edges', len(payload['edges']))
print('edge_types', edge_types)
assert payload['nodes']
assert payload['edges']
assert 'defined_in' in edge_types
assert all('confirmed exploitability' not in edge['reason'].lower() for edge in payload['edges'])
PY
```

- [ ] **Step 5: Verify research brief language remains safe**

Run:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
brief = Path('outputs/mini-tomcat-v02/research_brief.md').read_text().lower()
assert 'authorized local repository analysis' in brief
assert 'does not prove exploitability' in brief
for forbidden in ('confirmed exploitability', 'confirmed exploitable', 'exploit payload'):
    assert forbidden not in brief
PY
```

Expected: no assertion failures.

---

## Acceptance Criteria

- `AuditResult.schema_version` is `0.2`.
- `AuditResult` includes `evidence_graph` with stable JSON serialization.
- `evidence_graph.json` is written next to `audit_result.json` and `research_brief.md`.
- Graph nodes represent files, entrypoints, consumers, workers, boundaries, and primitives.
- Graph edges include `defined_in`, boundary evidence, primitive evidence, and conservative route/handler/same-file correlations when evidence exists.
- Every graph edge has a reason, confidence, and evidence IDs when supporting evidence exists.
- Every uncertain correlation edge includes missing-evidence language.
- Markdown includes an `Evidence Graph Summary` section but remains concise for large repositories.
- The implementation remains deterministic and local-only.
- No target code is executed.
- No exploit payloads or exploitation instructions are generated.
- No confirmed vulnerability/exploitability/RCE/compromise claims are added.
- `ruff`, `mypy`, and `pytest` pass.
