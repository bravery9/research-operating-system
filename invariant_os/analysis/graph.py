"""Evidence graph construction from deterministic audit candidates."""

from collections.abc import Sequence
from typing import Protocol

from invariant_os.analysis.enterprise_resolver import ResolvedGraphEdge, resolve_enterprise_graph_edges
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
    StaticFlowCandidate,
    Worker,
)


MAX_RESOLVER_EDGES_PER_ENTRYPOINT = 8
MAX_SAME_FILE_EDGES_PER_ENTRYPOINT = 5
MAX_HANDLER_CORRELATION_EDGES_PER_ENTRYPOINT = 8
MAX_TOTAL_LOW_SIGNAL_CORRELATION_EDGES = 20_000


class _GraphEvidenceSource(Protocol):
    id: str
    evidence: list[Evidence]


def build_evidence_graph(
    *,
    files: list[FileRecord],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
    boundaries: list[BoundaryCandidate],
    primitive_candidates: list[PrimitiveCandidate],
    static_flow_candidates: list[StaticFlowCandidate],
) -> EvidenceGraph:
    nodes: list[EvidenceGraphNode] = []
    edges: list[EvidenceGraphEdge] = []
    node_by_ref: dict[str, str] = {}
    file_node_by_path: dict[str, str] = {}
    node_counts: dict[EvidenceGraphNodeType, int] = {}

    for record in files:
        node_counts[EvidenceGraphNodeType.FILE] = node_counts.get(EvidenceGraphNodeType.FILE, 0) + 1
        node = EvidenceGraphNode(
            id=f"node_file_{node_counts[EvidenceGraphNodeType.FILE]:04d}",
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
            node_counts,
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
            node_counts,
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
            node_counts,
            ref_id=worker.id,
            node_type=EvidenceGraphNodeType.WORKER,
            label=worker.pattern,
            file=worker.file,
            line=worker.line,
            evidence=worker.evidence,
        )

    for boundary in boundaries:
        _add_reference_node(
            nodes,
            node_by_ref,
            node_counts,
            ref_id=boundary.id,
            node_type=EvidenceGraphNodeType.BOUNDARY,
            label=boundary.type.value,
            metadata={"confidence": boundary.confidence.value},
        )

    for primitive in primitive_candidates:
        _add_reference_node(
            nodes,
            node_by_ref,
            node_counts,
            ref_id=primitive.id,
            node_type=EvidenceGraphNodeType.PRIMITIVE,
            label=primitive.primitive.value,
            metadata={"confidence": primitive.confidence.value},
        )

    for candidate in static_flow_candidates:
        _add_reference_node(
            nodes,
            node_by_ref,
            node_counts,
            ref_id=candidate.id,
            node_type=EvidenceGraphNodeType.STATIC_FLOW,
            label=f"{candidate.source_entrypoint_id} -> {candidate.target_ref_id}",
            metadata={
                "confidence": candidate.confidence.value,
                "score": str(candidate.score),
                "target_type": candidate.target_type.value,
            },
        )

    detection_targets: list[_GraphEvidenceSource] = [*entrypoints, *consumers, *workers]
    primitive_targets: list[_GraphEvidenceSource] = [*detection_targets, *boundaries]

    resolved_edges = resolve_enterprise_graph_edges(
        entrypoints=entrypoints,
        consumers=consumers,
        workers=workers,
        max_edges_per_entrypoint=MAX_RESOLVER_EDGES_PER_ENTRYPOINT,
    )
    _add_static_flow_edges(edges, node_by_ref, static_flow_candidates)
    _add_resolved_candidate_edges(edges, node_by_ref, resolved_edges)
    remaining_low_signal_edges = MAX_TOTAL_LOW_SIGNAL_CORRELATION_EDGES
    same_file_edges = _add_same_file_correlations(
        edges,
        node_by_ref,
        entrypoints,
        consumers,
        workers,
        remaining_low_signal_edges,
    )
    remaining_low_signal_edges -= same_file_edges
    _add_handler_correlations(
        edges,
        node_by_ref,
        entrypoints,
        consumers,
        workers,
        remaining_low_signal_edges,
    )
    _add_evidence_reference_edges(
        edges,
        node_by_ref,
        edge_type=EvidenceGraphEdgeType.BOUNDARY_EVIDENCE,
        sources=boundaries,
        targets=detection_targets,
    )
    _add_evidence_reference_edges(
        edges,
        node_by_ref,
        edge_type=EvidenceGraphEdgeType.PRIMITIVE_EVIDENCE,
        sources=primitive_candidates,
        targets=primitive_targets,
    )

    return EvidenceGraph(nodes=nodes, edges=edges)


def _add_detection_node(
    nodes: list[EvidenceGraphNode],
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    file_node_by_path: dict[str, str],
    node_counts: dict[EvidenceGraphNodeType, int],
    *,
    ref_id: str,
    node_type: EvidenceGraphNodeType,
    label: str,
    file: str,
    line: int,
    evidence: list[Evidence],
) -> None:
    node_counts[node_type] = node_counts.get(node_type, 0) + 1
    node_id = f"node_{node_type.value}_{node_counts[node_type]:04d}"
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
    _append_edge(
        edges,
        edge_type=EvidenceGraphEdgeType.DEFINED_IN,
        source=node_id,
        target=file_node_id,
        confidence=Confidence.HIGH,
        evidence_ids=_evidence_ids(evidence),
        reason=f"Candidate is defined in `{file}`.",
        missing_evidence=[],
    )


def _add_reference_node(
    nodes: list[EvidenceGraphNode],
    node_by_ref: dict[str, str],
    node_counts: dict[EvidenceGraphNodeType, int],
    *,
    ref_id: str,
    node_type: EvidenceGraphNodeType,
    label: str,
    metadata: dict[str, str],
) -> None:
    node_counts[node_type] = node_counts.get(node_type, 0) + 1
    node_id = f"node_{node_type.value}_{node_counts[node_type]:04d}"
    nodes.append(
        EvidenceGraphNode(
            id=node_id,
            type=node_type,
            label=label,
            ref_id=ref_id,
            metadata=metadata,
        )
    )
    node_by_ref[ref_id] = node_id


def _add_static_flow_edges(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    static_flow_candidates: Sequence[StaticFlowCandidate],
) -> None:
    for candidate in static_flow_candidates:
        source_node = node_by_ref.get(candidate.source_entrypoint_id)
        flow_node = node_by_ref.get(candidate.id)
        target_node = node_by_ref.get(candidate.target_ref_id)
        if source_node is None or flow_node is None or target_node is None:
            continue
        evidence_ids = _evidence_ids(candidate.evidence)
        _append_edge(
            edges,
            edge_type=EvidenceGraphEdgeType.STATIC_FLOW_SOURCE,
            source=source_node,
            target=flow_node,
            confidence=candidate.confidence,
            evidence_ids=evidence_ids,
            reason=f"Candidate static flow source for `{candidate.id}`.",
            missing_evidence=candidate.missing_evidence,
        )
        _append_edge(
            edges,
            edge_type=EvidenceGraphEdgeType.STATIC_FLOW_TARGET,
            source=flow_node,
            target=target_node,
            confidence=candidate.confidence,
            evidence_ids=evidence_ids,
            reason=candidate.summary,
            missing_evidence=candidate.missing_evidence,
        )


def _add_resolved_candidate_edges(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    resolved_edges: Sequence[ResolvedGraphEdge],
) -> None:
    for resolved_edge in resolved_edges:
        source_node = node_by_ref.get(resolved_edge.source_ref)
        target_node = node_by_ref.get(resolved_edge.target_ref)
        if source_node is None or target_node is None:
            continue
        _append_edge(
            edges,
            edge_type=resolved_edge.edge_type,
            source=source_node,
            target=target_node,
            confidence=resolved_edge.confidence,
            evidence_ids=resolved_edge.evidence_ids,
            reason=resolved_edge.reason,
            missing_evidence=resolved_edge.missing_evidence,
        )


def _add_same_file_correlations(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
    remaining_low_signal_edges: int,
) -> int:
    targets: list[Consumer | Worker] = [*consumers, *workers]
    targets_by_file: dict[str, list[Consumer | Worker]] = {}
    for target in targets:
        targets_by_file.setdefault(target.file, []).append(target)

    added_edges = 0
    for entrypoint in entrypoints:
        if added_edges >= remaining_low_signal_edges:
            break
        ranked_targets = sorted(
            targets_by_file.get(entrypoint.file, []),
            key=lambda target: _same_file_target_sort_key(target),
        )[:MAX_SAME_FILE_EDGES_PER_ENTRYPOINT]
        for target in ranked_targets:
            if added_edges >= remaining_low_signal_edges:
                break
            _append_edge(
                edges,
                edge_type=EvidenceGraphEdgeType.SAME_FILE_CORRELATION,
                source=node_by_ref[entrypoint.id],
                target=node_by_ref[target.id],
                confidence=Confidence.MEDIUM,
                evidence_ids=_combined_evidence_ids(entrypoint.evidence, target.evidence),
                reason=(
                    f"Candidate correlation because `{entrypoint.id}` and `{target.id}` "
                    f"are in `{entrypoint.file}`."
                ),
                missing_evidence=[
                    "same-file correlation does not prove dataflow; confirm source, validation, and sink reachability manually"
                ],
            )
            added_edges += 1
    return added_edges


def _add_handler_correlations(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
    remaining_low_signal_edges: int,
) -> int:
    targets: list[Consumer | Worker] = [*consumers, *workers]
    added_edges = 0
    for entrypoint in entrypoints:
        if added_edges >= remaining_low_signal_edges:
            break
        handler_terms = _handler_terms(entrypoint.handler)
        if not handler_terms:
            continue
        ranked_targets = sorted(
            (target for target in targets if _handler_match_rank(handler_terms, target) < 2),
            key=lambda target: (_handler_match_rank(handler_terms, target), target.id),
        )[:MAX_HANDLER_CORRELATION_EDGES_PER_ENTRYPOINT]
        for target in ranked_targets:
            if added_edges >= remaining_low_signal_edges:
                break
            _append_edge(
                edges,
                edge_type=EvidenceGraphEdgeType.HANDLER_NAME_CORRELATION,
                source=node_by_ref[entrypoint.id],
                target=node_by_ref[target.id],
                confidence=Confidence.MEDIUM,
                evidence_ids=_combined_evidence_ids(entrypoint.evidence, target.evidence),
                reason=(
                    f"Candidate correlation because handler text from `{entrypoint.id}` "
                    f"appears in `{target.id}` evidence."
                ),
                missing_evidence=[
                    "confirm runtime dispatch and whether request-controlled data reaches the target candidate"
                ],
            )
            added_edges += 1
    return added_edges


def _same_file_target_sort_key(target: Consumer | Worker) -> tuple[int, str]:
    target_type_rank = 0 if isinstance(target, Worker) else 1
    return target_type_rank, target.id


def _handler_match_rank(handler_terms: list[str], target: Consumer | Worker) -> int:
    target_text = _evidence_text(target.evidence).lower()
    if handler_terms and handler_terms[0] in target_text:
        return 0
    if any(term in target_text for term in handler_terms[1:]):
        return 1
    return 2


def _add_evidence_reference_edges(
    edges: list[EvidenceGraphEdge],
    node_by_ref: dict[str, str],
    *,
    edge_type: EvidenceGraphEdgeType,
    sources: Sequence[_GraphEvidenceSource],
    targets: Sequence[_GraphEvidenceSource],
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


def _entrypoint_label(entrypoint: Entrypoint) -> str:
    parts = [
        part
        for part in (
            entrypoint.method.upper() if entrypoint.method else None,
            entrypoint.route_path,
            entrypoint.handler,
        )
        if part
    ]
    return " ".join(parts) if parts else entrypoint.type.value


def _handler_terms(handler: str | None) -> list[str]:
    if handler is None:
        return []
    class_part = handler.split("#", 1)[0]
    terms = [class_part]
    if "." in class_part:
        terms.append(class_part.rsplit(".", 1)[-1])
    return [term.lower() for term in terms if len(term) >= 4]


def _evidence_text(evidence: list[Evidence]) -> str:
    return "\n".join(
        part
        for item in evidence
        for part in (item.snippet or "", item.message or "", item.symbol or "")
    )


def _evidence_ids(evidence: list[Evidence]) -> list[str]:
    return [item.id for item in evidence]


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
