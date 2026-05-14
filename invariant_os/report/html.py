"""Deterministic static HTML rendering for audit evidence workspaces."""

from collections.abc import Iterable, Sequence
from html import escape

from invariant_os.core.models import (
    AuditResult,
    BoundaryCandidate,
    Consumer,
    Entrypoint,
    Evidence,
    EvidenceGraphEdge,
    EvidenceGraphEdgeType,
    EvidenceGraphNode,
    PrimitiveCandidate,
    StaticFlowCandidate,
    StaticFlowSignal,
    Worker,
)

_GRAPH_EDGE_PRIORITY = {
    EvidenceGraphEdgeType.STATIC_FLOW_SOURCE: 0,
    EvidenceGraphEdgeType.STATIC_FLOW_TARGET: 1,
    EvidenceGraphEdgeType.ROUTE_TO_WORKER_CANDIDATE: 2,
    EvidenceGraphEdgeType.ROUTE_TO_CONSUMER_CANDIDATE: 3,
    EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION: 4,
    EvidenceGraphEdgeType.SAME_FILE_CORRELATION: 5,
    EvidenceGraphEdgeType.BOUNDARY_EVIDENCE: 6,
    EvidenceGraphEdgeType.PRIMITIVE_EVIDENCE: 7,
    EvidenceGraphEdgeType.DEFINED_IN: 8,
}
_GRAPH_PREVIEW_EDGE_LIMIT = 50


def render_evidence_viewer(result: AuditResult) -> str:
    """Render a deterministic static HTML evidence workspace."""
    sections = [
        _section("Summary", _render_summary(result)),
        _section("Scope and Safety", _render_safety(result)),
        _section("Entrypoints", _render_entrypoints(result.entrypoints)),
        _section("Worker and Background Job Candidates", _render_workers(result.workers)),
        _section("Dangerous Consumer Inventory", _render_consumers(result.consumers)),
        _section("Trust Boundary Candidates", _render_boundaries(result.boundaries)),
        _section("Primitive Candidates", _render_primitives(result.primitive_candidates)),
        _section("Static Flow/Dataflow Candidates", _render_static_flows(result.static_flow_candidates)),
        _section("Evidence Graph Preview", _render_graph_preview(result)),
        _section("Missing Evidence", _render_missing_evidence(result)),
        _section("Safe Manual Review Steps", _render_manual_review(result.primitive_candidates)),
        _section("Evidence Index", _render_evidence_index(result)),
    ]
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>InvariantOS Static Evidence Workspace</title>",
            "<style>",
            _stylesheet(),
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            "<h1>InvariantOS Static Evidence Workspace</h1>",
            '<p class="lede">Local, read-only workspace for static candidates, evidence, missing evidence, and safe manual review.</p>',
            '<nav aria-label="Workspace sections">',
            _render_nav(),
            "</nav>",
            *sections,
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def _stylesheet() -> str:
    return """
:root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }
body { margin: 0; background: #f8fafc; color: #0f172a; }
main { max-width: 1180px; margin: 0 auto; padding: 2rem; }
section, nav { background: #ffffff; border: 1px solid #cbd5e1; border-radius: 0.75rem; margin: 1rem 0; padding: 1rem; }
h1, h2, h3 { line-height: 1.2; }
a { color: #1d4ed8; }
code, pre { background: #e2e8f0; border-radius: 0.25rem; padding: 0.1rem 0.25rem; }
pre { white-space: pre-wrap; padding: 0.75rem; overflow-x: auto; }
ul { padding-left: 1.25rem; }
.card { border-top: 1px solid #e2e8f0; padding: 0.75rem 0; }
.card:first-child { border-top: 0; }
.meta { color: #475569; }
.badge { display: inline-block; background: #e0f2fe; border-radius: 999px; padding: 0.1rem 0.5rem; margin-right: 0.25rem; }
.lede { color: #334155; font-size: 1.05rem; }
""".strip()


def _render_nav() -> str:
    links = [
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
    return "<ul>" + "".join(
        f'<li><a href="#{_section_id(label)}">{_text(label)}</a></li>' for label in links
    ) + "</ul>"


def _section(title: str, body: str) -> str:
    return f'<section id="{_section_id(title)}">\n<h2>{_text(title)}</h2>\n{body}\n</section>'


def _render_summary(result: AuditResult) -> str:
    rows = [
        ("Project", result.project.name),
        ("Root", result.project.root),
        ("Schema version", result.schema_version),
        ("Files indexed", str(result.summary.files)),
        ("Entrypoints", str(result.summary.entrypoints)),
        ("Dangerous consumers", str(result.summary.consumers)),
        ("Worker/background candidates", str(result.summary.workers)),
        ("Trust boundary candidates", str(result.summary.boundaries)),
        ("Primitive candidates", str(result.summary.primitive_candidates)),
        ("Static flow/dataflow candidates", str(result.summary.static_flow_candidates)),
    ]
    return _definition_list(rows)


def _render_safety(result: AuditResult) -> str:
    limitations = "".join(f"<li>{_text(item)}</li>" for item in result.safety.limitations)
    return "\n".join(
        [
            "<p>This workspace is limited to authorized local analysis. It summarizes static candidates and hypotheses only; it does not prove exploitability.</p>",
            f"<p><strong>Scope:</strong> {_text(result.safety.scope)}</p>",
            f"<p><strong>Core principle:</strong> {_text(result.safety.principle)}</p>",
            f"<ul>{limitations}</ul>",
        ]
    )


def _render_entrypoints(entrypoints: list[Entrypoint]) -> str:
    if not entrypoints:
        return "<p>No entrypoint candidates were detected.</p>"
    cards = []
    for entrypoint in entrypoints:
        cards.append(
            _card(
                f"entrypoint-{entrypoint.id}",
                f"{entrypoint.id} — {entrypoint.type.value}",
                [
                    ("Location", _location(entrypoint.file, entrypoint.line)),
                    ("Method", entrypoint.method or "none recorded"),
                    ("Route", entrypoint.route_path or "none recorded"),
                    ("Handler", entrypoint.handler or "none recorded"),
                    ("Framework hint", entrypoint.framework_hint or "none recorded"),
                    ("Evidence", _evidence_refs(entrypoint.evidence)),
                ],
            )
        )
    return "\n".join(cards)


def _render_workers(workers: list[Worker]) -> str:
    if not workers:
        return "<p>No worker or background job candidates were detected.</p>"
    return "\n".join(
        _card(
            f"worker-{worker.id}",
            f"{worker.id} — {worker.type.value}",
            [
                ("Location", _location(worker.file, worker.line)),
                ("Pattern", worker.pattern),
                ("Framework hint", worker.framework_hint or "none recorded"),
                ("Evidence", _evidence_refs(worker.evidence)),
            ],
        )
        for worker in workers
    )


def _render_consumers(consumers: list[Consumer]) -> str:
    if not consumers:
        return "<p>No dangerous consumer candidates were detected.</p>"
    return "\n".join(
        _card(
            f"consumer-{consumer.id}",
            f"{consumer.id} — {consumer.type.value}",
            [
                ("Location", _location(consumer.file, consumer.line)),
                ("Pattern", consumer.pattern),
                ("Symbol", consumer.symbol or "none recorded"),
                ("Evidence", _evidence_refs(consumer.evidence)),
            ],
        )
        for consumer in consumers
    )


def _render_boundaries(boundaries: list[BoundaryCandidate]) -> str:
    if not boundaries:
        return "<p>No trust boundary candidates were inferred.</p>"
    return "\n".join(
        _card(
            f"boundary-{boundary.id}",
            f"{boundary.id} — {boundary.type.value}",
            [
                ("Confidence", boundary.confidence.value),
                ("Reason", boundary.reason),
                ("Evidence", _evidence_refs(boundary.evidence)),
            ],
        )
        for boundary in boundaries
    )


def _render_primitives(primitives: list[PrimitiveCandidate]) -> str:
    if not primitives:
        return "<p>No primitive candidates were classified. This is not a security conclusion.</p>"
    return "\n".join(
        _card(
            f"primitive-{primitive.id}",
            f"{primitive.id} — {primitive.primitive.value} hypothesis",
            [
                ("Confidence", primitive.confidence.value),
                ("Evidence", _evidence_refs(primitive.evidence)),
                ("Missing evidence", _join_or_none(primitive.missing_evidence)),
                ("Safe next steps", _join_or_none(primitive.safe_next_steps)),
            ],
        )
        for primitive in primitives
    )


def _render_static_flows(candidates: list[StaticFlowCandidate]) -> str:
    if not candidates:
        return "<p>No static flow/dataflow candidates were inferred.</p>"
    return "\n".join(
        _card(
            f"flow-{candidate.id}",
            f"{candidate.id} — {candidate.target_type.value} candidate",
            [
                ("Source entrypoint", candidate.source_entrypoint_id),
                ("Target", candidate.target_ref_id),
                ("Confidence", candidate.confidence.value),
                ("Score", str(candidate.score)),
                ("Summary", candidate.summary),
                ("Signals", _render_flow_signals(candidate.signals)),
                ("Evidence", _evidence_refs(candidate.evidence)),
                ("Missing evidence", _join_or_none(candidate.missing_evidence)),
            ],
        )
        for candidate in candidates
    )


def _render_flow_signals(signals: list[StaticFlowSignal]) -> str:
    if not signals:
        return "none recorded"
    return "; ".join(
        f"{signal.type.value}:{signal.term} (+{signal.score}, evidence {_join_or_none(signal.evidence_ids)})"
        for signal in signals
    )


def _render_graph_preview(result: AuditResult) -> str:
    graph = result.evidence_graph
    if not graph.nodes and not graph.edges:
        return "<p>No evidence graph candidates were generated.</p>"
    nodes_by_id = {node.id: node for node in graph.nodes}
    lines = [
        f"<p>Graph nodes: {_text(str(len(graph.nodes)))}. Graph edges: {_text(str(len(graph.edges)))}.</p>",
    ]
    preview_edges = sorted(
        graph.edges,
        key=lambda edge: (_GRAPH_EDGE_PRIORITY.get(edge.type, 99), edge.id),
    )[:_GRAPH_PREVIEW_EDGE_LIMIT]
    for edge in preview_edges:
        lines.append(_render_graph_edge(edge, nodes_by_id))
    if len(graph.edges) > _GRAPH_PREVIEW_EDGE_LIMIT:
        lines.append("<p>Additional graph edges are available in evidence_graph.json.</p>")
    return "\n".join(lines)


def _render_graph_edge(edge: EvidenceGraphEdge, nodes_by_id: dict[str, EvidenceGraphNode]) -> str:
    source = _node_label(nodes_by_id.get(edge.source), edge.source)
    target = _node_label(nodes_by_id.get(edge.target), edge.target)
    return _card(
        f"edge-{edge.id}",
        f"{edge.id} — {edge.type.value}",
        [
            ("Source", source),
            ("Target", target),
            ("Confidence", edge.confidence.value),
            ("Reason", edge.reason),
            ("Evidence", _evidence_id_refs(edge.evidence_ids)),
            ("Missing evidence", _join_or_none(edge.missing_evidence)),
        ],
    )


def _render_missing_evidence(result: AuditResult) -> str:
    items: list[tuple[str, str]] = []
    for primitive in result.primitive_candidates:
        items.extend((primitive.id, missing) for missing in primitive.missing_evidence)
    for candidate in result.static_flow_candidates:
        items.extend((candidate.id, missing) for missing in candidate.missing_evidence)
    for edge in result.evidence_graph.edges:
        items.extend((edge.id, missing) for missing in edge.missing_evidence)
    if not items:
        return "<p>No candidate-specific missing evidence was recorded.</p>"
    return "<ul>" + "".join(
        f"<li><code>{_text(ref_id)}</code>: {_text(missing)}</li>" for ref_id, missing in items
    ) + "</ul>"


def _render_manual_review(primitives: list[PrimitiveCandidate]) -> str:
    steps = [
        "Review candidates with benign inputs only.",
        "Confirm data origin, validation, authorization, and sink semantics before changing code.",
        "Use local code review and tests; do not execute target startup scripts or scan public targets.",
    ]
    for primitive in primitives:
        steps.extend(f"{primitive.id}: {step}" for step in primitive.safe_next_steps)
    return "<ul>" + "".join(f"<li>{_text(step)}</li>" for step in steps) + "</ul>"


def _render_evidence_index(result: AuditResult) -> str:
    evidence = _unique_evidence(
        *[entrypoint.evidence for entrypoint in result.entrypoints],
        *[consumer.evidence for consumer in result.consumers],
        *[worker.evidence for worker in result.workers],
        *[boundary.evidence for boundary in result.boundaries],
        *[primitive.evidence for primitive in result.primitive_candidates],
        *[candidate.evidence for candidate in result.static_flow_candidates],
    )
    if not evidence:
        return "<p>No evidence records were collected.</p>"
    cards = []
    for item in evidence:
        body = [
            ("Type", item.type.value),
            ("Location", _location(item.file, item.line)),
            ("Pattern", item.pattern or "none recorded"),
            ("Symbol", item.symbol or "none recorded"),
            ("Message", item.message or "none recorded"),
        ]
        snippet = f"<pre>{_text(item.snippet)}</pre>" if item.snippet else ""
        cards.append(
            f'<article class="card" id="evidence-{_attr(item.id)}">'
            f"<h3>{_text(item.id)}</h3>"
            f"{_definition_list(body)}"
            f"{snippet}"
            "</article>"
        )
    return "\n".join(cards)


def _card(anchor_id: str, title: str, rows: Sequence[tuple[str, str]]) -> str:
    return (
        f'<article class="card" id="{_attr(anchor_id)}">'
        f"<h3>{_text(title)}</h3>"
        f"{_definition_list(rows)}"
        "</article>"
    )


def _definition_list(rows: Sequence[tuple[str, str]]) -> str:
    items = []
    for key, value in rows:
        items.append(f"<dt>{_text(key)}</dt><dd>{_html_value(value)}</dd>")
    return "<dl>" + "".join(items) + "</dl>"


def _html_value(value: str) -> str:
    if value.startswith('<a href="#') or value.startswith("<span"):
        return value
    return _text(value)


def _location(file: str, line: int | None) -> str:
    if line is None:
        return file
    return f"{file}:{line}"


def _node_label(node: EvidenceGraphNode | None, fallback: str) -> str:
    if node is None:
        return fallback
    if node.ref_id:
        return f"{node.id} ({node.type.value}, {node.ref_id})"
    return f"{node.id} ({node.type.value})"


def _evidence_refs(evidence: list[Evidence]) -> str:
    if not evidence:
        return "none recorded"
    return _evidence_id_refs([item.id for item in evidence])


def _evidence_id_refs(evidence_ids: list[str]) -> str:
    if not evidence_ids:
        return "none recorded"
    return ", ".join(
        f'<a href="#evidence-{_attr(evidence_id)}"><code>{_text(evidence_id)}</code></a>'
        for evidence_id in evidence_ids
    )


def _join_or_none(values: list[str]) -> str:
    return "; ".join(values) if values else "none recorded"


def _unique_evidence(*groups: Iterable[Evidence]) -> list[Evidence]:
    records: list[Evidence] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item.id in seen:
                continue
            seen.add(item.id)
            records.append(item)
    return records


def _section_id(title: str) -> str:
    return title.lower().replace("/", "-").replace(" ", "-")


def _text(value: object) -> str:
    return escape(_defang_url_schemes(str(value)), quote=False)


def _attr(value: object) -> str:
    return escape(_defang_url_schemes(str(value)), quote=True)


def _defang_url_schemes(value: str) -> str:
    return value.replace("https://", "hxxps://").replace("http://", "hxxp://")
