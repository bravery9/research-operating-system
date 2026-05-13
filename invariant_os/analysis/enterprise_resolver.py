"""Enterprise route correlation resolver for evidence graph candidate edges."""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from invariant_os.core.models import (
    Confidence,
    Consumer,
    Entrypoint,
    Evidence,
    EvidenceGraphEdgeType,
    Worker,
)

_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")
_QUALIFIED_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
_STOP_WORDS = {
    "api",
    "action",
    "call",
    "class",
    "config",
    "controller",
    "data",
    "default",
    "do",
    "get",
    "handler",
    "http",
    "https",
    "id",
    "list",
    "method",
    "name",
    "path",
    "post",
    "request",
    "response",
    "rest",
    "service",
    "servlet",
    "url",
}
_MISSING_EVIDENCE = [
    "confirm runtime dispatch, authorization context, validation, and whether "
    "request-controlled data reaches this candidate target"
]


@dataclass(frozen=True)
class ResolvedGraphEdge:
    edge_type: EvidenceGraphEdgeType
    source_ref: str
    target_ref: str
    confidence: Confidence
    score: int
    reason: str
    evidence_ids: list[str]
    missing_evidence: list[str]


@dataclass(frozen=True)
class _IndexedWorker:
    target: Worker
    text: str
    tokens: set[str]
    phrases: set[str]


@dataclass(frozen=True)
class _IndexedConsumer:
    target: Consumer
    text: str
    tokens: set[str]
    phrases: set[str]


def resolve_enterprise_graph_edges(
    *,
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
    max_edges_per_entrypoint: int = 8,
) -> list[ResolvedGraphEdge]:
    if max_edges_per_entrypoint <= 0:
        return []

    worker_targets = [_index_worker(worker) for worker in workers]
    consumer_targets = [_index_consumer(consumer) for consumer in consumers]
    worker_phrase_index, worker_token_index = _build_worker_indexes(worker_targets)
    consumer_phrase_index, consumer_token_index = _build_consumer_indexes(consumer_targets)

    edges: list[ResolvedGraphEdge] = []
    for entrypoint in entrypoints:
        entrypoint_edges: list[ResolvedGraphEdge] = []
        source_tokens = _source_tokens(entrypoint)
        handler_class, simple_class, handler_method = _handler_parts(entrypoint.handler)

        for worker in _candidate_workers(
            handler_class,
            simple_class,
            handler_method,
            worker_phrase_index,
            worker_token_index,
        ):
            edge = _worker_edge(entrypoint, source_tokens, handler_class, simple_class, handler_method, worker)
            if edge is not None:
                entrypoint_edges.append(edge)
        for consumer in _candidate_consumers(
            handler_class,
            simple_class,
            handler_method,
            consumer_phrase_index,
            consumer_token_index,
        ):
            edge = _consumer_edge(
                entrypoint,
                source_tokens,
                handler_class,
                simple_class,
                handler_method,
                consumer,
            )
            if edge is not None:
                entrypoint_edges.append(edge)

        entrypoint_edges = _dedupe_edges(entrypoint_edges)
        entrypoint_edges.sort(key=lambda edge: (-edge.score, edge.edge_type.value, edge.target_ref))
        edges.extend(entrypoint_edges[:max_edges_per_entrypoint])

    return sorted(edges, key=lambda edge: (edge.source_ref, -edge.score, edge.edge_type.value, edge.target_ref))


def _worker_edge(
    entrypoint: Entrypoint,
    source_tokens: set[str],
    handler_class: str | None,
    simple_class: str | None,
    handler_method: str | None,
    worker: _IndexedWorker,
) -> ResolvedGraphEdge | None:
    score, signal = _score_target(
        source_tokens,
        handler_class,
        simple_class,
        handler_method,
        worker.text,
        worker.tokens,
    )
    if score < 40 or signal is None:
        return None
    return ResolvedGraphEdge(
        edge_type=EvidenceGraphEdgeType.ROUTE_TO_WORKER_CANDIDATE,
        source_ref=entrypoint.id,
        target_ref=worker.target.id,
        confidence=_confidence_for_score(score),
        score=score,
        reason=(
            f"Candidate enterprise route-to-worker link because {signal} appears in "
            f"worker evidence for `{worker.target.id}`."
        ),
        evidence_ids=_combined_evidence_ids(entrypoint.evidence, worker.target.evidence),
        missing_evidence=list(_MISSING_EVIDENCE),
    )


def _consumer_edge(
    entrypoint: Entrypoint,
    source_tokens: set[str],
    handler_class: str | None,
    simple_class: str | None,
    handler_method: str | None,
    consumer: _IndexedConsumer,
) -> ResolvedGraphEdge | None:
    score, signal = _score_target(
        source_tokens,
        handler_class,
        simple_class,
        handler_method,
        consumer.text,
        consumer.tokens,
    )
    if score < 40 or signal is None:
        return None
    return ResolvedGraphEdge(
        edge_type=EvidenceGraphEdgeType.ROUTE_TO_CONSUMER_CANDIDATE,
        source_ref=entrypoint.id,
        target_ref=consumer.target.id,
        confidence=_confidence_for_score(score),
        score=score,
        reason=(
            f"Candidate enterprise route-to-consumer link because {signal} appears in "
            f"consumer evidence for `{consumer.target.id}`."
        ),
        evidence_ids=_combined_evidence_ids(entrypoint.evidence, consumer.target.evidence),
        missing_evidence=list(_MISSING_EVIDENCE),
    )


def _score_target(
    source_tokens: set[str],
    handler_class: str | None,
    simple_class: str | None,
    handler_method: str | None,
    target_text: str,
    target_tokens: set[str],
) -> tuple[int, str | None]:
    target_lower = target_text.lower()
    score = 0
    signal: str | None = None

    if handler_class and handler_class.lower() in target_lower:
        score += 90
        signal = f"handler `{handler_class}`"
    elif simple_class and simple_class.lower() in target_tokens:
        score += 60
        signal = f"handler class `{simple_class}`"

    if handler_method and handler_method.lower() in target_tokens:
        score += 45
        if signal is None:
            signal = f"handler method `{handler_method}`"

    if signal is None:
        return 0, None

    overlap = source_tokens & target_tokens
    score += min(30, len(overlap) * 10)
    return score, signal


def _candidate_workers(
    handler_class: str | None,
    simple_class: str | None,
    handler_method: str | None,
    phrase_index: dict[str, list[_IndexedWorker]],
    token_index: dict[str, list[_IndexedWorker]],
) -> list[_IndexedWorker]:
    candidates: dict[str, _IndexedWorker] = {}
    if handler_class:
        for target in phrase_index.get(handler_class.lower(), []):
            candidates[target.target.id] = target
    for token in _handler_tokens(simple_class, handler_method):
        for target in token_index.get(token, []):
            candidates[target.target.id] = target
    return sorted(candidates.values(), key=lambda target: target.target.id)


def _candidate_consumers(
    handler_class: str | None,
    simple_class: str | None,
    handler_method: str | None,
    phrase_index: dict[str, list[_IndexedConsumer]],
    token_index: dict[str, list[_IndexedConsumer]],
) -> list[_IndexedConsumer]:
    candidates: dict[str, _IndexedConsumer] = {}
    if handler_class:
        for target in phrase_index.get(handler_class.lower(), []):
            candidates[target.target.id] = target
    for token in _handler_tokens(simple_class, handler_method):
        for target in token_index.get(token, []):
            candidates[target.target.id] = target
    return sorted(candidates.values(), key=lambda target: target.target.id)


def _handler_tokens(simple_class: str | None, handler_method: str | None) -> list[str]:
    tokens: list[str] = []
    for token in (simple_class, handler_method):
        if token is None:
            continue
        normalized = token.lower()
        if len(normalized) >= 4 and normalized not in _STOP_WORDS:
            tokens.append(normalized)
    return tokens


def _build_worker_indexes(
    targets: list[_IndexedWorker],
) -> tuple[dict[str, list[_IndexedWorker]], dict[str, list[_IndexedWorker]]]:
    phrase_index: dict[str, list[_IndexedWorker]] = {}
    token_index: dict[str, list[_IndexedWorker]] = {}
    for target in targets:
        for phrase in target.phrases:
            phrase_index.setdefault(phrase, []).append(target)
        for token in target.tokens:
            token_index.setdefault(token, []).append(target)
    return phrase_index, token_index


def _build_consumer_indexes(
    targets: list[_IndexedConsumer],
) -> tuple[dict[str, list[_IndexedConsumer]], dict[str, list[_IndexedConsumer]]]:
    phrase_index: dict[str, list[_IndexedConsumer]] = {}
    token_index: dict[str, list[_IndexedConsumer]] = {}
    for target in targets:
        for phrase in target.phrases:
            phrase_index.setdefault(phrase, []).append(target)
        for token in target.tokens:
            token_index.setdefault(token, []).append(target)
    return phrase_index, token_index


def _index_worker(worker: Worker) -> _IndexedWorker:
    text = _target_text(worker.file, worker.pattern, worker.evidence)
    return _IndexedWorker(
        target=worker,
        text=text,
        tokens=_meaningful_tokens(text),
        phrases=_qualified_phrases(text),
    )


def _index_consumer(consumer: Consumer) -> _IndexedConsumer:
    text = _target_text(consumer.file, consumer.pattern, consumer.evidence, consumer.symbol)
    return _IndexedConsumer(
        target=consumer,
        text=text,
        tokens=_meaningful_tokens(text),
        phrases=_qualified_phrases(text),
    )


def _handler_parts(handler: str | None) -> tuple[str | None, str | None, str | None]:
    if not handler:
        return None, None, None
    class_part, separator, method_part = handler.partition("#")
    handler_class = class_part or None
    simple_class = handler_class.rsplit(".", 1)[-1] if handler_class else None
    handler_method = method_part if separator and method_part else None
    return handler_class, simple_class, handler_method


def _source_tokens(entrypoint: Entrypoint) -> set[str]:
    return _meaningful_tokens(
        entrypoint.route_path,
        entrypoint.framework_hint,
        entrypoint.handler,
        _evidence_text(entrypoint.evidence),
    )


def _target_text(
    file: str,
    pattern: str,
    evidence: list[Evidence],
    symbol: str | None = None,
) -> str:
    return "\n".join((file, pattern, symbol or "", _evidence_text(evidence)))


def _evidence_text(evidence: list[Evidence]) -> str:
    return "\n".join(
        part
        for item in evidence
        for part in (item.snippet or "", item.message or "", item.symbol or "")
    )


def _meaningful_tokens(*values: str | None) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if not value:
            continue
        for token in _TOKEN_PATTERN.findall(value):
            normalized = token.lower()
            if len(normalized) >= 4 and normalized not in _STOP_WORDS:
                tokens.add(normalized)
    return tokens


def _qualified_phrases(value: str) -> set[str]:
    return {phrase.lower() for phrase in _QUALIFIED_NAME_PATTERN.findall(value)}


def _combined_evidence_ids(*groups: Iterable[Evidence]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item.id in seen:
                continue
            seen.add(item.id)
            ids.append(item.id)
    return ids


def _confidence_for_score(score: int) -> Confidence:
    return Confidence.HIGH if score >= 80 else Confidence.MEDIUM


def _dedupe_edges(edges: list[ResolvedGraphEdge]) -> list[ResolvedGraphEdge]:
    deduped: dict[tuple[EvidenceGraphEdgeType, str, str], ResolvedGraphEdge] = {}
    for edge in edges:
        key = (edge.edge_type, edge.source_ref, edge.target_ref)
        existing = deduped.get(key)
        if existing is None or edge.score > existing.score:
            deduped[key] = edge
    return list(deduped.values())
