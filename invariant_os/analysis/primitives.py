"""Heuristic primitive classification from inferred boundaries."""

from collections.abc import Iterable
from typing import Protocol

from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Consumer,
    ConsumerType,
    Evidence,
    PrimitiveCandidate,
    PrimitiveType,
    Worker,
)


class _HasEvidence(Protocol):
    evidence: list[Evidence]


def classify_primitives(
    boundaries: list[BoundaryCandidate], consumers: list[Consumer], workers: list[Worker]
) -> list[PrimitiveCandidate]:
    """Classify candidate primitives suggested by boundaries and detections."""
    candidates: list[tuple[PrimitiveType, Confidence, list[Evidence], list[str], list[str]]] = []
    boundary_by_type = {boundary.type: boundary for boundary in boundaries}

    file_boundary = boundary_by_type.get(BoundaryType.DATA_TO_FILE)
    if file_boundary is not None:
        file_consumers = _consumers_of_type(consumers, ConsumerType.FILE_OPERATION)
        file_evidence = _evidence_from([file_boundary], file_consumers)
        if _has_write_pattern(file_consumers):
            candidates.append(
                _candidate(
                    PrimitiveType.FILE_WRITE,
                    file_boundary.confidence,
                    file_evidence,
                    "confirmation of whether the write target is influenced by request or job data",
                    "Trace a benign sample value from ingress to the file write target and contents.",
                )
            )
        if _has_read_pattern(file_consumers):
            candidates.append(
                _candidate(
                    PrimitiveType.FILE_READ,
                    file_boundary.confidence,
                    file_evidence,
                    "confirmation of whether the read target is influenced by external or queued data",
                    "Trace a benign sample value from ingress to the file read target.",
                )
            )
        if _has_path_pattern(file_consumers) or not (_has_write_pattern(file_consumers) or _has_read_pattern(file_consumers)):
            candidates.append(
                _candidate(
                    PrimitiveType.PATH_CONTROL,
                    file_boundary.confidence,
                    file_evidence,
                    "confirmation of path normalization, base directory checks, and data origin",
                    "Review path construction with benign sample paths and expected directory constraints.",
                )
            )

    url_boundary = boundary_by_type.get(BoundaryType.DATA_TO_URL)
    if url_boundary is not None:
        url_evidence = _evidence_from([url_boundary], _consumers_of_type(consumers, ConsumerType.NETWORK_OPERATION))
        candidates.append(
            _candidate(
                PrimitiveType.URL_CONTROL,
                url_boundary.confidence,
                url_evidence,
                "confirmation of which URL components are data-influenced",
                "Trace benign URL values through validation and outbound request construction.",
            )
        )
        candidates.append(
            _candidate(
                PrimitiveType.INTERNAL_REQUEST_TRIGGER,
                Confidence.LOW,
                url_evidence,
                "confirmation of reachable internal destinations and request context",
                "Map allowed destinations and compare them with observed outbound request construction.",
            )
        )

    template_boundary = boundary_by_type.get(BoundaryType.DATA_TO_TEMPLATE)
    if template_boundary is not None:
        candidates.append(
            _candidate(
                PrimitiveType.TEMPLATE_CONTROL,
                template_boundary.confidence,
                _evidence_from([template_boundary], _consumers_of_type(consumers, ConsumerType.TEMPLATE_OPERATION)),
                "confirmation of whether data influences template name, context, or rendering options",
                "Review benign template inputs and rendering context assembly.",
            )
        )

    if BoundaryType.DATA_TO_JOB in boundary_by_type or BoundaryType.REQUEST_TO_WORKER in boundary_by_type:
        job_boundary = boundary_by_type.get(BoundaryType.DATA_TO_JOB) or boundary_by_type[BoundaryType.REQUEST_TO_WORKER]
        candidates.append(
            _candidate(
                PrimitiveType.JOB_CONTROL,
                job_boundary.confidence,
                _evidence_from(
                    [job_boundary],
                    _consumers_of_type(consumers, ConsumerType.QUEUE_OPERATION),
                    workers,
                ),
                "confirmation of which job fields, queue names, or worker parameters are data-influenced",
                "Trace a benign job submission through queue enqueueing and worker handling.",
            )
        )

    config_boundary = boundary_by_type.get(BoundaryType.DATA_TO_CONFIG)
    if config_boundary is not None:
        candidates.append(
            _candidate(
                PrimitiveType.CONFIG_CONTROL,
                config_boundary.confidence,
                _evidence_from([config_boundary], _consumers_of_type(consumers, ConsumerType.CONFIG_OPERATION)),
                "confirmation of which configuration keys are data-influenced",
                "Review benign configuration samples and the resulting application settings.",
            )
        )

    parser_boundary = boundary_by_type.get(BoundaryType.PARSER_TO_CONSUMER)
    if parser_boundary is not None:
        candidates.append(
            _candidate(
                PrimitiveType.PARSER_DIFFERENTIAL,
                parser_boundary.confidence,
                _evidence_from(
                    [parser_boundary],
                    _consumers_of_type(consumers, ConsumerType.PARSER_OPERATION),
                    _consumers_of_type(consumers, ConsumerType.ARCHIVE_OPERATION),
                ),
                "confirmation of parser expectations, accepted formats, and downstream consumer assumptions",
                "Compare benign parser inputs across documented formats and downstream consumer expectations.",
            )
        )

    deserialization_consumers = _consumers_of_type(consumers, ConsumerType.DESERIALIZATION)
    if deserialization_consumers:
        candidates.append(
            _candidate(
                PrimitiveType.TYPE_CONTROL,
                Confidence.LOW,
                _evidence_from(deserialization_consumers),
                "confirmation of allowed serialized types, schema enforcement, and data origin",
                "Review benign serialized samples against type allowlists and schema validation.",
            )
        )

    cache_consumers = _consumers_with_terms(consumers, ("cache", "session"))
    if cache_consumers:
        candidates.append(
            _candidate(
                PrimitiveType.CACHE_POISONING,
                Confidence.LOW,
                _evidence_from(cache_consumers),
                "confirmation of cache key construction, session scoping, and data origin",
                "Trace benign cache and session inputs through key construction and expiration handling.",
            )
        )

    auth_consumers = _consumers_with_terms(consumers, ("auth", "permission", "admin"))
    if auth_consumers:
        candidates.append(
            _candidate(
                PrimitiveType.AUTH_CONTEXT_CONFUSION,
                Confidence.LOW,
                _evidence_from(auth_consumers),
                "confirmation of authentication context, permission checks, and administrative role boundaries",
                "Trace benign identity and permission values through authorization decisions.",
            )
        )

    tenant_consumers = _consumers_with_terms(consumers, ("tenant", "workspace", "org"))
    if tenant_consumers:
        candidates.append(
            _candidate(
                PrimitiveType.TENANT_CONFUSION,
                Confidence.LOW,
                _evidence_from(tenant_consumers),
                "confirmation of tenant, workspace, or organization scoping and data origin",
                "Trace benign tenant identifiers through workspace or organization selection checks.",
            )
        )

    return [
        PrimitiveCandidate(
            id=f"primitive_{index:04d}",
            primitive=primitive,
            confidence=confidence,
            evidence=evidence,
            missing_evidence=missing_evidence,
            safe_next_steps=safe_next_steps,
        )
        for index, (primitive, confidence, evidence, missing_evidence, safe_next_steps) in enumerate(candidates, start=1)
    ]


def _candidate(
    primitive: PrimitiveType,
    confidence: Confidence,
    evidence: list[Evidence],
    missing_evidence: str,
    safe_next_step: str,
) -> tuple[PrimitiveType, Confidence, list[Evidence], list[str], list[str]]:
    return (
        primitive,
        confidence,
        evidence,
        [missing_evidence],
        [safe_next_step, "Document assumptions and ask for human review before changing behavior."],
    )


def _consumers_of_type(consumers: list[Consumer], consumer_type: ConsumerType) -> list[Consumer]:
    return [consumer for consumer in consumers if consumer.type == consumer_type]


def _evidence_from(*groups: Iterable[_HasEvidence]) -> list[Evidence]:
    evidence: list[Evidence] = []
    seen: set[str] = set()
    for group in groups:
        for detection in group:
            for item in detection.evidence:
                if item.id in seen:
                    continue
                seen.add(item.id)
                evidence.append(item)
    return evidence


def _has_write_pattern(consumers: list[Consumer]) -> bool:
    write_terms = ("writefile", ".write(")
    return any(_snippet_contains(consumer, write_terms) or _has_open_write_mode(consumer) for consumer in consumers)


def _has_read_pattern(consumers: list[Consumer]) -> bool:
    read_terms = ("readfile", ".read(")
    return any(_snippet_contains(consumer, read_terms) or _has_open_read_mode(consumer) for consumer in consumers)


def _has_path_pattern(consumers: list[Consumer]) -> bool:
    path_terms = ("path.join", "path.resolve", "os.path.join", "path(")
    return any(_snippet_contains(consumer, path_terms) for consumer in consumers)


def _has_open_write_mode(consumer: Consumer) -> bool:
    snippets = "\n".join(evidence.snippet or "" for evidence in consumer.evidence).lower()
    return any(_is_write_open_args(args, is_method) for args, is_method in _open_call_arguments(snippets))


def _has_open_read_mode(consumer: Consumer) -> bool:
    snippets = "\n".join(evidence.snippet or "" for evidence in consumer.evidence).lower()
    return any(_is_read_open_args(args, is_method) for args, is_method in _open_call_arguments(snippets))


def _is_write_open_args(args: str, is_method: bool) -> bool:
    mode = _open_mode(args, positional_mode_index=0 if is_method else 1)
    return mode is not None and any(flag in mode for flag in ("w", "a", "x", "+"))


def _is_read_open_args(args: str, is_method: bool) -> bool:
    mode = _open_mode(args, positional_mode_index=0 if is_method else 1)
    return not _is_write_open_args(args, is_method) and (mode is None or any(flag in mode for flag in ("r", "b", "t")))


def _open_mode(args: str, *, positional_mode_index: int) -> str | None:
    parts = _top_level_arguments(args)
    for part in parts:
        name, separator, value = part.partition("=")
        if separator and name.strip() == "mode":
            return _string_literal_value(value)
    if len(parts) > positional_mode_index:
        return _string_literal_value(parts[positional_mode_index])
    return None


def _open_call_arguments(snippet: str) -> list[tuple[str, bool]]:
    calls: list[tuple[str, bool]] = []
    index = 0
    while True:
        start = snippet.find("open", index)
        if start == -1:
            return calls
        before = snippet[start - 1] if start > 0 else ""
        if before.isalnum() or before == "_":
            index = start + 4
            continue
        cursor = start + 4
        while cursor < len(snippet) and snippet[cursor].isspace():
            cursor += 1
        if cursor >= len(snippet) or snippet[cursor] != "(":
            index = cursor
            continue
        end = _matching_close_paren(snippet, cursor)
        if end is not None:
            calls.append((snippet[cursor + 1 : end], before == "."))
            index = end + 1
        else:
            index = cursor + 1


def _matching_close_paren(text: str, open_index: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(open_index, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _top_level_arguments(args: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(args):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(args[start:index].strip())
            start = index + 1
    parts.append(args[start:].strip())
    return parts


def _string_literal_value(value: str) -> str | None:
    stripped = value.strip()
    if len(stripped) < 2 or stripped[0] not in {"'", '"'}:
        return None
    quote = stripped[0]
    end = 1
    escaped = False
    while end < len(stripped):
        char = stripped[end]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return stripped[1:end]
        end += 1
    return None


def _consumers_with_terms(consumers: list[Consumer], terms: tuple[str, ...]) -> list[Consumer]:
    return [consumer for consumer in consumers if _snippet_contains(consumer, terms)]


def _snippet_contains(consumer: Consumer, terms: tuple[str, ...]) -> bool:
    snippets = "\n".join(evidence.snippet or "" for evidence in consumer.evidence).lower()
    return any(term in snippets for term in terms)
