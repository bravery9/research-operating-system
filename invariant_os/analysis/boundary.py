"""Heuristic trust-boundary inference from static detections."""

from collections.abc import Iterable
from typing import Protocol

from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Consumer,
    ConsumerType,
    Entrypoint,
    Evidence,
    Worker,
)


class _HasEvidence(Protocol):
    evidence: list[Evidence]


def infer_boundaries(
    entrypoints: list[Entrypoint], consumers: list[Consumer], workers: list[Worker]
) -> list[BoundaryCandidate]:
    """Infer candidate boundaries from entrypoint, consumer, and worker detections."""
    candidates: list[tuple[BoundaryType, Confidence, str, list[Evidence]]] = []

    file_consumers = _consumers_of_type(consumers, ConsumerType.FILE_OPERATION)
    network_consumers = _consumers_of_type(consumers, ConsumerType.NETWORK_OPERATION)
    template_consumers = _consumers_of_type(consumers, ConsumerType.TEMPLATE_OPERATION)
    config_consumers = _consumers_of_type(consumers, ConsumerType.CONFIG_OPERATION)
    queue_consumers = _consumers_of_type(consumers, ConsumerType.QUEUE_OPERATION)
    parser_consumers = _consumers_of_type(consumers, ConsumerType.PARSER_OPERATION)
    archive_consumers = _consumers_of_type(consumers, ConsumerType.ARCHIVE_OPERATION)

    if entrypoints and workers:
        candidates.append(
            (
                BoundaryType.REQUEST_TO_WORKER,
                Confidence.MEDIUM,
                "Candidate boundary where request-handling code appears connected to worker-handled activity.",
                _evidence_from(entrypoints, workers),
            )
        )

    if file_consumers:
        candidates.append(
            (
                BoundaryType.DATA_TO_FILE,
                Confidence.MEDIUM,
                "Candidate boundary where application data reaches file-system operations.",
                _evidence_from(file_consumers),
            )
        )

    if network_consumers:
        candidates.append(
            (
                BoundaryType.DATA_TO_URL,
                Confidence.MEDIUM,
                "Candidate boundary where application data may influence outbound network requests.",
                _evidence_from(network_consumers),
            )
        )

    if template_consumers:
        candidates.append(
            (
                BoundaryType.DATA_TO_TEMPLATE,
                Confidence.MEDIUM,
                "Candidate boundary where application data may reach template rendering.",
                _evidence_from(template_consumers),
            )
        )

    if config_consumers:
        candidates.append(
            (
                BoundaryType.DATA_TO_CONFIG,
                Confidence.MEDIUM,
                "Candidate boundary where parsed or supplied data may reach configuration loading.",
                _evidence_from(config_consumers),
            )
        )

    if queue_consumers or workers:
        candidates.append(
            (
                BoundaryType.DATA_TO_JOB,
                Confidence.MEDIUM,
                "Candidate boundary where data appears to cross into queued or background job handling.",
                _evidence_from(queue_consumers, workers),
            )
        )

    if entrypoints and network_consumers:
        candidates.append(
            (
                BoundaryType.EXTERNAL_TO_INTERNAL,
                Confidence.MEDIUM,
                "Hypothesis that external request handling can lead to internal service interaction.",
                _evidence_from(entrypoints, network_consumers),
            )
        )

    if entrypoints and (workers or queue_consumers):
        candidates.append(
            (
                BoundaryType.LOW_PRIV_TO_PRIVILEGED_CONSUMER,
                Confidence.LOW,
                "Low-confidence hypothesis that request-originated data may reach a more privileged consumer context.",
                _evidence_from(entrypoints, workers, queue_consumers),
            )
        )

    parser_sources = [*parser_consumers, *archive_consumers]
    parser_targets = [*file_consumers, *template_consumers, *config_consumers]
    if parser_sources and parser_targets:
        candidates.append(
            (
                BoundaryType.PARSER_TO_CONSUMER,
                Confidence.MEDIUM,
                "Candidate boundary where parsed or archive-derived data may feed file, template, or configuration consumers.",
                _evidence_from(parser_sources, parser_targets),
            )
        )

    return [
        BoundaryCandidate(
            id=f"boundary_{index:04d}",
            type=boundary_type,
            confidence=confidence,
            reason=reason,
            evidence=evidence,
        )
        for index, (boundary_type, confidence, reason, evidence) in enumerate(candidates, start=1)
    ]


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
