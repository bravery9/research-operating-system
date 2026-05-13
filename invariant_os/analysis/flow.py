"""Bounded static flow/dataflow candidate enrichment."""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from invariant_os.core.models import (
    Confidence,
    Consumer,
    Entrypoint,
    Evidence,
    FileRecord,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
    Worker,
)

MAX_STATIC_FLOW_CANDIDATES_TOTAL = 500
MAX_STATIC_FLOW_CANDIDATES_PER_ENTRYPOINT = 8
MAX_SOURCE_TERMS_PER_ENTRYPOINT = 40
MAX_TARGET_TERMS_PER_TARGET = 80
SAME_FILE_PROXIMITY_LINES = 80
MIN_STATIC_FLOW_SCORE = 60

_MISSING_EVIDENCE = [
    "confirm runtime dispatch, authorization context, validation, and whether "
    "request-controlled data reaches this target"
]
_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")
_METADATA_PATTERN = re.compile(
    r"\b(param|PARAM_NAME|ACCESS_ID|MTCALL_VALUE|SERVLET_CLASS_NAME|CLASS_NAME|METHOD_NAME)"
    r"\s*=\s*[\"']?([A-Za-z0-9_.$#/-]+)",
    re.IGNORECASE,
)
_JAVA_REQUEST_PARAMETER_PATTERN = re.compile(r"\.getParameter\(\s*[\"']([A-Za-z0-9_.$-]+)[\"']\s*\)")
_JS_REQUEST_PARAMETER_PATTERN = re.compile(
    r"\b(?:req|request)\.(?:query|body)\.([A-Za-z_][A-Za-z0-9_]*)"
)
_PYTHON_REQUEST_PARAMETER_PATTERN = re.compile(
    r"\brequest\.(?:args|form|json)\.get\(\s*[\"']([A-Za-z0-9_.$-]+)[\"']\s*\)"
)
_STOP_WORDS = {
    "api",
    "class",
    "conf",
    "config",
    "data",
    "default",
    "get",
    "http",
    "https",
    "java",
    "method",
    "path",
    "post",
    "request",
    "response",
    "rest",
    "service",
    "servlet",
    "src",
    "url",
}


@dataclass(frozen=True)
class _Term:
    signal_type: StaticFlowSignalType
    value: str
    score: int
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class _Target:
    ref_id: str
    target_type: StaticFlowTargetType
    file: str
    line: int
    text: str
    tokens: set[str]
    evidence: list[Evidence]


@dataclass(frozen=True)
class _ScoredCandidate:
    source_entrypoint_id: str
    target_ref_id: str
    target_type: StaticFlowTargetType
    confidence: Confidence
    score: int
    signals: list[StaticFlowSignal]
    evidence: list[Evidence]
    missing_evidence: list[str]


def enrich_static_flows(
    *,
    repo_root: Path,
    files: list[FileRecord],
    entrypoints: list[Entrypoint],
    consumers: list[Consumer],
    workers: list[Worker],
    max_candidates_total: int = MAX_STATIC_FLOW_CANDIDATES_TOTAL,
    max_candidates_per_entrypoint: int = MAX_STATIC_FLOW_CANDIDATES_PER_ENTRYPOINT,
) -> list[StaticFlowCandidate]:
    if max_candidates_total <= 0 or max_candidates_per_entrypoint <= 0:
        return []

    _ = files
    targets = [_index_worker(worker) for worker in workers]
    targets.extend(_index_consumer(consumer) for consumer in consumers)
    flow_candidates: list[_ScoredCandidate] = []

    for entrypoint in entrypoints:
        source_terms = _source_terms(repo_root, entrypoint)
        entrypoint_candidates = _dedupe_candidates(
            _score_target(entrypoint, source_terms, target) for target in targets
        )
        entrypoint_candidates.sort(
            key=lambda candidate: (
                -candidate.score,
                _target_type_rank(candidate.target_type),
                candidate.target_ref_id,
            )
        )
        flow_candidates.extend(entrypoint_candidates[:max_candidates_per_entrypoint])
        if len(flow_candidates) >= max_candidates_total:
            break

    return [
        StaticFlowCandidate(
            id=f"flow_{index:04d}",
            source_entrypoint_id=candidate.source_entrypoint_id,
            target_ref_id=candidate.target_ref_id,
            target_type=candidate.target_type,
            confidence=candidate.confidence,
            score=candidate.score,
            summary=_candidate_summary(candidate),
            signals=candidate.signals,
            evidence=candidate.evidence,
            missing_evidence=candidate.missing_evidence,
        )
        for index, candidate in enumerate(flow_candidates[:max_candidates_total], start=1)
    ]


def _score_target(
    entrypoint: Entrypoint,
    source_terms: list[_Term],
    target: _Target,
) -> _ScoredCandidate | None:
    signals: list[StaticFlowSignal] = []
    score_by_type: dict[StaticFlowSignalType, int] = {}
    target_text = target.text.lower()

    for term in source_terms:
        if not _term_matches_target(term, target_text, target.tokens):
            continue
        capped_score = _capped_signal_score(term, score_by_type)
        if capped_score <= 0:
            continue
        score_by_type[term.signal_type] = score_by_type.get(term.signal_type, 0) + capped_score
        signals.append(
            StaticFlowSignal(
                type=term.signal_type,
                term=term.value,
                score=capped_score,
                evidence_ids=list(term.evidence_ids),
            )
        )

    has_non_proximity_signal = bool(signals)
    if _same_file_proximity(entrypoint, target):
        signals.append(
            StaticFlowSignal(
                type=StaticFlowSignalType.SAME_FILE_PROXIMITY,
                term=entrypoint.file,
                score=20,
                evidence_ids=_combined_evidence_ids(entrypoint.evidence, target.evidence),
            )
        )
        score_by_type[StaticFlowSignalType.SAME_FILE_PROXIMITY] = 20

    if not has_non_proximity_signal:
        return None

    score = sum(score_by_type.values())
    if score < MIN_STATIC_FLOW_SCORE:
        return None

    return _ScoredCandidate(
        source_entrypoint_id=entrypoint.id,
        target_ref_id=target.ref_id,
        target_type=target.target_type,
        confidence=_confidence_for_score(score),
        score=score,
        signals=signals,
        evidence=_combined_evidence(entrypoint.evidence, target.evidence),
        missing_evidence=list(_MISSING_EVIDENCE),
    )


def _source_terms(repo_root: Path, entrypoint: Entrypoint) -> list[_Term]:
    evidence_ids = tuple(item.id for item in entrypoint.evidence)
    terms: list[_Term] = []
    terms.extend(_handler_terms(entrypoint.handler, evidence_ids))
    terms.extend(_metadata_terms(entrypoint.evidence))
    terms.extend(_route_terms(entrypoint.route_path, evidence_ids))
    terms.extend(_request_parameter_terms(repo_root, entrypoint, evidence_ids))
    return _dedupe_terms(terms)[:MAX_SOURCE_TERMS_PER_ENTRYPOINT]


def _handler_terms(handler: str | None, evidence_ids: tuple[str, ...]) -> list[_Term]:
    if not handler:
        return []
    class_part, separator, method_part = handler.partition("#")
    handler_class = class_part or None
    simple_class = handler_class.rsplit(".", 1)[-1] if handler_class else None
    terms: list[_Term] = []
    if handler_class:
        terms.append(_Term(StaticFlowSignalType.HANDLER_EXACT, handler_class, 90, evidence_ids))
    if simple_class and _is_meaningful_token(simple_class):
        terms.append(_Term(StaticFlowSignalType.HANDLER_CLASS, simple_class, 60, evidence_ids))
    if separator and method_part and _is_meaningful_token(method_part):
        terms.append(_Term(StaticFlowSignalType.HANDLER_METHOD, method_part, 45, evidence_ids))
    return terms


def _metadata_terms(evidence: Sequence[Evidence]) -> list[_Term]:
    terms: list[_Term] = []
    for item in evidence:
        text = "\n".join(part for part in (item.message, item.snippet, item.symbol) if part)
        for key, value in _METADATA_PATTERN.findall(text):
            normalized_key = key.lower()
            if normalized_key in {"servlet_class_name", "class_name"}:
                terms.extend(_metadata_class_terms(value, item.id))
                continue
            signal_type = _metadata_signal_type(key)
            if _is_meaningful_token(value):
                terms.append(_Term(signal_type, value, _metadata_score(signal_type), (item.id,)))
    return terms


def _metadata_class_terms(value: str, evidence_id: str) -> list[_Term]:
    if not _is_meaningful_token(value):
        return []
    terms = [_Term(StaticFlowSignalType.HANDLER_EXACT, value, 90, (evidence_id,))]
    if "." not in value or "/" in value:
        return terms
    simple_class = value.rsplit(".", 1)[-1]
    if _is_meaningful_token(simple_class) and simple_class != value:
        terms.append(_Term(StaticFlowSignalType.HANDLER_CLASS, simple_class, 60, (evidence_id,)))
    return terms


def _metadata_signal_type(key: str) -> StaticFlowSignalType:
    normalized = key.lower()
    if normalized in {"servlet_class_name", "class_name"}:
        return StaticFlowSignalType.HANDLER_EXACT
    if normalized == "method_name":
        return StaticFlowSignalType.HANDLER_METHOD
    return StaticFlowSignalType.DECLARED_PARAMETER


def _metadata_score(signal_type: StaticFlowSignalType) -> int:
    if signal_type == StaticFlowSignalType.HANDLER_EXACT:
        return 90
    if signal_type == StaticFlowSignalType.HANDLER_METHOD:
        return 45
    return 20


def _metadata_values(value: str) -> list[str]:
    if "." in value and "/" not in value:
        return [value, value.rsplit(".", 1)[-1]]
    return [value]


def _route_terms(route_path: str | None, evidence_ids: tuple[str, ...]) -> list[_Term]:
    if not route_path:
        return []
    terms: list[_Term] = []
    for token in _TOKEN_PATTERN.findall(route_path):
        if not _is_meaningful_token(token):
            continue
        terms.append(_Term(StaticFlowSignalType.ROUTE_TOKEN, token, 10, evidence_ids))
        if token.lower().endswith("s") and len(token) > 4:
            terms.append(_Term(StaticFlowSignalType.ROUTE_TOKEN, token[:-1], 10, evidence_ids))
    return terms


def _request_parameter_terms(
    repo_root: Path,
    entrypoint: Entrypoint,
    evidence_ids: tuple[str, ...],
) -> list[_Term]:
    path = repo_root / entrypoint.file
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    start = max(0, entrypoint.line - SAME_FILE_PROXIMITY_LINES - 1)
    end = min(len(lines), entrypoint.line + SAME_FILE_PROXIMITY_LINES)
    text = "\n".join(lines[start:end])
    terms: list[_Term] = []
    for pattern in (
        _JAVA_REQUEST_PARAMETER_PATTERN,
        _JS_REQUEST_PARAMETER_PATTERN,
        _PYTHON_REQUEST_PARAMETER_PATTERN,
    ):
        for value in pattern.findall(text):
            if _is_meaningful_token(value):
                terms.append(_Term(StaticFlowSignalType.REQUEST_PARAMETER, value, 40, evidence_ids))
    return terms


def _term_matches_target(term: _Term, target_text: str, target_tokens: set[str]) -> bool:
    normalized = _normalize_token(term.value)
    if not normalized:
        return False
    if term.signal_type == StaticFlowSignalType.HANDLER_EXACT:
        return term.value.lower() in target_text
    return normalized in target_tokens or normalized in target_text


def _capped_signal_score(
    term: _Term,
    score_by_type: dict[StaticFlowSignalType, int],
) -> int:
    cap = _signal_cap(term.signal_type)
    current = score_by_type.get(term.signal_type, 0)
    if current >= cap:
        return 0
    return min(term.score, cap - current)


def _signal_cap(signal_type: StaticFlowSignalType) -> int:
    if signal_type in {
        StaticFlowSignalType.DECLARED_PARAMETER,
        StaticFlowSignalType.REQUEST_PARAMETER,
    }:
        return 40
    if signal_type == StaticFlowSignalType.ROUTE_TOKEN:
        return 20
    return 200


def _same_file_proximity(entrypoint: Entrypoint, target: _Target) -> bool:
    return (
        entrypoint.file == target.file
        and abs(entrypoint.line - target.line) <= SAME_FILE_PROXIMITY_LINES
    )


def _index_worker(worker: Worker) -> _Target:
    text = _target_text(worker.file, worker.pattern, None, worker.evidence)
    return _Target(
        ref_id=worker.id,
        target_type=StaticFlowTargetType.WORKER,
        file=worker.file,
        line=worker.line,
        text=text,
        tokens=_meaningful_tokens(text),
        evidence=worker.evidence,
    )


def _index_consumer(consumer: Consumer) -> _Target:
    text = _target_text(consumer.file, consumer.pattern, consumer.symbol, consumer.evidence)
    return _Target(
        ref_id=consumer.id,
        target_type=StaticFlowTargetType.CONSUMER,
        file=consumer.file,
        line=consumer.line,
        text=text,
        tokens=_meaningful_tokens(text),
        evidence=consumer.evidence,
    )


def _target_text(file: str, pattern: str, symbol: str | None, evidence: Sequence[Evidence]) -> str:
    parts = [file, pattern, symbol or ""]
    for item in evidence:
        parts.extend(part for part in (item.snippet, item.message, item.symbol) if part)
    return "\n".join(parts)


def _meaningful_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for token in _TOKEN_PATTERN.findall(value):
        normalized = _normalize_token(token)
        if normalized and normalized not in _STOP_WORDS:
            tokens.add(normalized)
    return set(list(tokens)[:MAX_TARGET_TERMS_PER_TARGET])


def _normalize_token(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "", value).lower()
    if len(normalized) < 3 or normalized in _STOP_WORDS:
        return ""
    return normalized


def _is_meaningful_token(value: str) -> bool:
    return bool(_normalize_token(value))


def _dedupe_terms(terms: Iterable[_Term]) -> list[_Term]:
    deduped: dict[tuple[StaticFlowSignalType, str], _Term] = {}
    for term in terms:
        key = (term.signal_type, _normalize_token(term.value))
        if key[1] and key not in deduped:
            deduped[key] = term
    return list(deduped.values())


def _dedupe_candidates(candidates: Iterable[_ScoredCandidate | None]) -> list[_ScoredCandidate]:
    deduped: dict[tuple[str, StaticFlowTargetType, str], _ScoredCandidate] = {}
    for candidate in candidates:
        if candidate is None:
            continue
        key = (candidate.source_entrypoint_id, candidate.target_type, candidate.target_ref_id)
        existing = deduped.get(key)
        if existing is None or candidate.score > existing.score:
            deduped[key] = candidate
    return list(deduped.values())


def _target_type_rank(target_type: StaticFlowTargetType) -> int:
    return 0 if target_type == StaticFlowTargetType.WORKER else 1


def _candidate_summary(candidate: _ScoredCandidate) -> str:
    return (
        f"Candidate static flow from `{candidate.source_entrypoint_id}` to "
        f"`{candidate.target_ref_id}` based on {_signal_summary(candidate.signals)} overlap."
    )


def _signal_summary(signals: Sequence[StaticFlowSignal]) -> str:
    signal_types = {signal.type for signal in signals}
    if StaticFlowSignalType.HANDLER_EXACT in signal_types:
        return "handler and metadata"
    if signal_types & {StaticFlowSignalType.HANDLER_CLASS, StaticFlowSignalType.HANDLER_METHOD}:
        return "handler and metadata"
    if StaticFlowSignalType.REQUEST_PARAMETER in signal_types:
        if StaticFlowSignalType.SAME_FILE_PROXIMITY in signal_types:
            return "request parameter and same-file"
        return "request parameter"
    return "metadata"


def _confidence_for_score(score: int) -> Confidence:
    return Confidence.HIGH if score >= 90 else Confidence.MEDIUM


def _combined_evidence(*groups: Iterable[Evidence]) -> list[Evidence]:
    evidence: list[Evidence] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item.id in seen:
                continue
            seen.add(item.id)
            evidence.append(item)
    return evidence


def _combined_evidence_ids(*groups: Iterable[Evidence]) -> list[str]:
    return [item.id for item in _combined_evidence(*groups)]
