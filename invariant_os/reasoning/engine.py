"""Deterministic offline reasoning over structured audit artifacts."""

from collections.abc import Iterable
import re

from invariant_os.core.models import (
    AuditResult,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Evidence,
    EvidenceGraphEdge,
    EvidenceGraphEdgeType,
    ReasoningCategory,
    ReasoningItem,
    ReasoningResult,
    ReasoningSummary,
)

MAX_ITEMS_PER_CATEGORY = 50
_FORBIDDEN_PATTERN = re.compile(
    r"confirmed vulnerable|confirmed exploitable|exploitability proved|payload to exploit",
    re.IGNORECASE,
)


def build_reasoning_result(result: AuditResult, source_audit_file: str) -> ReasoningResult:
    evidence_ids = _collect_evidence_ids(result)
    items = [
        *_high_value_surfaces(result, evidence_ids),
        *_invariant_hypotheses(result, evidence_ids),
        *_primitive_triage(result, evidence_ids),
        *_missing_evidence(result, evidence_ids),
        *_safe_next_steps(result, evidence_ids),
    ]
    return ReasoningResult(
        source_schema_version=result.schema_version,
        source_project=result.project,
        source_audit_file=source_audit_file,
        items=items,
        summary=_summary(items),
        safety=result.safety,
    )


def _high_value_surfaces(result: AuditResult, evidence_ids: set[str]) -> list[ReasoningItem]:
    items: list[ReasoningItem] = []
    for flow in result.static_flow_candidates[:MAX_ITEMS_PER_CATEGORY]:
        items.append(
            _item(
                prefix="reason_surface",
                index=len(items) + 1,
                category=ReasoningCategory.HIGH_VALUE_SURFACE,
                title=f"Candidate static flow surface {flow.id}",
                summary=(
                    f"Candidate high-value review surface because static evidence links "
                    f"entrypoint `{flow.source_entrypoint_id}` to `{flow.target_ref_id}`."
                ),
                confidence=flow.confidence,
                related_ids=[flow.id, flow.source_entrypoint_id, flow.target_ref_id],
                evidence_ids=_filtered_evidence_ids([evidence.id for evidence in flow.evidence], evidence_ids),
                missing_evidence=flow.missing_evidence,
            )
        )
    remaining = MAX_ITEMS_PER_CATEGORY - len(items)
    if remaining <= 0:
        return items
    for primitive in result.primitive_candidates[:remaining]:
        items.append(
            _item(
                prefix="reason_surface",
                index=len(items) + 1,
                category=ReasoningCategory.HIGH_VALUE_SURFACE,
                title=f"Candidate primitive review surface {primitive.id}",
                summary=(
                    f"Candidate high-value review surface because primitive hypothesis "
                    f"`{primitive.id}` is classified as `{primitive.primitive.value}`."
                ),
                confidence=primitive.confidence,
                related_ids=[primitive.id],
                evidence_ids=_filtered_evidence_ids(
                    [evidence.id for evidence in primitive.evidence], evidence_ids
                ),
                missing_evidence=primitive.missing_evidence,
            )
        )
    return items


def _invariant_hypotheses(result: AuditResult, evidence_ids: set[str]) -> list[ReasoningItem]:
    items: list[ReasoningItem] = []
    for boundary in result.boundaries[:MAX_ITEMS_PER_CATEGORY]:
        items.append(
            _item(
                prefix="reason_invariant",
                index=len(items) + 1,
                category=ReasoningCategory.SECURITY_INVARIANT_HYPOTHESIS,
                title=f"Invariant hypothesis for {boundary.type.value}",
                summary=_boundary_invariant(boundary),
                confidence=boundary.confidence,
                related_ids=[boundary.id],
                evidence_ids=_filtered_evidence_ids(
                    [evidence.id for evidence in boundary.evidence], evidence_ids
                ),
                missing_evidence=["confirm the runtime path and authorization context before drawing conclusions"],
            )
        )
    return items


def _primitive_triage(result: AuditResult, evidence_ids: set[str]) -> list[ReasoningItem]:
    items: list[ReasoningItem] = []
    primitives = sorted(
        result.primitive_candidates,
        key=lambda primitive: (
            _confidence_rank(primitive.confidence),
            -len(primitive.evidence),
            primitive.id,
        ),
    )[:MAX_ITEMS_PER_CATEGORY]
    for primitive in primitives:
        items.append(
            _item(
                prefix="reason_primitive",
                index=len(items) + 1,
                category=ReasoningCategory.PRIMITIVE_TRIAGE,
                title=f"Primitive hypothesis triage {primitive.id}",
                summary=(
                    f"Review primitive hypothesis `{primitive.id}` for `{primitive.primitive.value}` "
                    "using the linked evidence and missing-evidence notes."
                ),
                confidence=primitive.confidence,
                related_ids=[primitive.id],
                evidence_ids=_filtered_evidence_ids(
                    [evidence.id for evidence in primitive.evidence], evidence_ids
                ),
                missing_evidence=primitive.missing_evidence,
                safe_next_steps=primitive.safe_next_steps,
            )
        )
    return items


def _missing_evidence(result: AuditResult, evidence_ids: set[str]) -> list[ReasoningItem]:
    items: list[ReasoningItem] = []
    for primitive in result.primitive_candidates:
        for missing in primitive.missing_evidence:
            items.append(
                _item(
                    prefix="reason_missing",
                    index=len(items) + 1,
                    category=ReasoningCategory.MISSING_EVIDENCE,
                    title=f"Missing evidence for {primitive.id}",
                    summary="Candidate reasoning needs additional evidence before any security conclusion.",
                    confidence=primitive.confidence,
                    related_ids=[primitive.id],
                    evidence_ids=_filtered_evidence_ids(
                        [evidence.id for evidence in primitive.evidence], evidence_ids
                    ),
                    missing_evidence=[missing],
                )
            )
            if len(items) >= MAX_ITEMS_PER_CATEGORY:
                return items
    for flow in result.static_flow_candidates:
        for missing in flow.missing_evidence:
            items.append(
                _item(
                    prefix="reason_missing",
                    index=len(items) + 1,
                    category=ReasoningCategory.MISSING_EVIDENCE,
                    title=f"Missing evidence for {flow.id}",
                    summary="Static flow candidate needs runtime and data-influence review.",
                    confidence=flow.confidence,
                    related_ids=[flow.id, flow.source_entrypoint_id, flow.target_ref_id],
                    evidence_ids=_filtered_evidence_ids(
                        [evidence.id for evidence in flow.evidence], evidence_ids
                    ),
                    missing_evidence=[missing],
                )
            )
            if len(items) >= MAX_ITEMS_PER_CATEGORY:
                return items
    for edge in _non_defined_graph_edges(result.evidence_graph.edges):
        for missing in edge.missing_evidence:
            items.append(
                _item(
                    prefix="reason_missing",
                    index=len(items) + 1,
                    category=ReasoningCategory.MISSING_EVIDENCE,
                    title=f"Missing evidence for {edge.id}",
                    summary="Evidence graph candidate needs manual confirmation before conclusions.",
                    confidence=edge.confidence,
                    related_ids=[edge.id, edge.source, edge.target],
                    evidence_ids=_filtered_evidence_ids(edge.evidence_ids, evidence_ids),
                    missing_evidence=[missing],
                )
            )
            if len(items) >= MAX_ITEMS_PER_CATEGORY:
                return items
    return items


def _safe_next_steps(result: AuditResult, evidence_ids: set[str]) -> list[ReasoningItem]:
    items: list[ReasoningItem] = []
    for primitive in result.primitive_candidates:
        for step in primitive.safe_next_steps:
            items.append(
                _item(
                    prefix="reason_step",
                    index=len(items) + 1,
                    category=ReasoningCategory.SAFE_NEXT_STEP,
                    title=f"Safe review step for {primitive.id}",
                    summary="Use benign local review to evaluate this candidate hypothesis.",
                    confidence=primitive.confidence,
                    related_ids=[primitive.id],
                    evidence_ids=_filtered_evidence_ids(
                        [evidence.id for evidence in primitive.evidence], evidence_ids
                    ),
                    safe_next_steps=[step],
                )
            )
            if len(items) >= MAX_ITEMS_PER_CATEGORY:
                return items
    if result.primitive_candidates or result.static_flow_candidates or result.boundaries:
        items.append(
            _item(
                prefix="reason_step",
                index=len(items) + 1,
                category=ReasoningCategory.SAFE_NEXT_STEP,
                title="Global safe manual review step",
                summary="Review candidate paths with benign inputs and local evidence only.",
                confidence=Confidence.LOW,
                safe_next_steps=[
                    "Confirm data origin, validation, authorization, and sink semantics before changing code."
                ],
            )
        )
    return items


def _boundary_invariant(boundary: BoundaryCandidate) -> str:
    templates = {
        BoundaryType.REQUEST_TO_WORKER: "Hypothesis: request-to-worker boundaries should revalidate job payloads before privileged consumption.",
        BoundaryType.DATA_TO_FILE: "Hypothesis: data-to-file boundaries should validate and normalize paths before file operations.",
        BoundaryType.DATA_TO_URL: "Hypothesis: data-to-url boundaries should ensure validated URLs match requested URLs.",
        BoundaryType.DATA_TO_TEMPLATE: "Hypothesis: data-to-template boundaries should prevent untrusted template control.",
        BoundaryType.DATA_TO_CONFIG: "Hypothesis: data-to-config boundaries should prevent untrusted configuration from changing runtime behavior.",
        BoundaryType.DATA_TO_JOB: "Hypothesis: data-to-job boundaries should constrain job type and payload fields before enqueueing.",
        BoundaryType.EXTERNAL_TO_INTERNAL: "Hypothesis: external-to-internal boundaries should require explicit authorization and routing constraints.",
        BoundaryType.LOW_PRIV_TO_PRIVILEGED_CONSUMER: "Hypothesis: low-privilege to privileged-consumer boundaries should recheck authorization at consumption time.",
        BoundaryType.PARSER_TO_CONSUMER: "Hypothesis: parser-to-consumer boundaries should validate parsed structure before downstream use.",
        BoundaryType.DATA_TO_DATABASE: "Hypothesis: data-to-database boundaries should preserve query construction and authorization invariants.",
        BoundaryType.DATA_TO_DIRECTORY: "Hypothesis: data-to-directory boundaries should constrain directory query scope before lookup.",
    }
    return templates[boundary.type]


def _item(
    *,
    prefix: str,
    index: int,
    category: ReasoningCategory,
    title: str,
    summary: str,
    confidence: Confidence,
    related_ids: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    safe_next_steps: list[str] | None = None,
) -> ReasoningItem:
    return ReasoningItem(
        id=f"{prefix}_{index:04d}",
        category=category,
        title=_safe_text(title),
        summary=_safe_text(summary),
        confidence=confidence,
        related_ids=[_safe_text(value) for value in related_ids or []],
        evidence_ids=evidence_ids or [],
        missing_evidence=[_safe_text(value) for value in missing_evidence or []],
        safe_next_steps=[_safe_text(value) for value in safe_next_steps or []],
    )


def _summary(items: list[ReasoningItem]) -> ReasoningSummary:
    return ReasoningSummary(
        high_value_surfaces=_count_category(items, ReasoningCategory.HIGH_VALUE_SURFACE),
        invariant_hypotheses=_count_category(
            items, ReasoningCategory.SECURITY_INVARIANT_HYPOTHESIS
        ),
        primitive_triage_items=_count_category(items, ReasoningCategory.PRIMITIVE_TRIAGE),
        missing_evidence_items=_count_category(items, ReasoningCategory.MISSING_EVIDENCE),
        safe_next_steps=_count_category(items, ReasoningCategory.SAFE_NEXT_STEP),
    )


def _count_category(items: list[ReasoningItem], category: ReasoningCategory) -> int:
    return sum(1 for item in items if item.category == category)


def _collect_evidence_ids(result: AuditResult) -> set[str]:
    return {
        evidence.id
        for evidence in _unique_evidence(
            *[entrypoint.evidence for entrypoint in result.entrypoints],
            *[consumer.evidence for consumer in result.consumers],
            *[worker.evidence for worker in result.workers],
            *[boundary.evidence for boundary in result.boundaries],
            *[primitive.evidence for primitive in result.primitive_candidates],
            *[candidate.evidence for candidate in result.static_flow_candidates],
        )
    }


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


def _filtered_evidence_ids(values: list[str], evidence_ids: set[str]) -> list[str]:
    return [value for value in values if value in evidence_ids]


def _non_defined_graph_edges(edges: list[EvidenceGraphEdge]) -> list[EvidenceGraphEdge]:
    return [edge for edge in edges if edge.type != EvidenceGraphEdgeType.DEFINED_IN]


def _confidence_rank(confidence: Confidence) -> int:
    if confidence == Confidence.HIGH:
        return 0
    if confidence == Confidence.MEDIUM:
        return 1
    return 2


def _safe_text(value: str) -> str:
    return _FORBIDDEN_PATTERN.sub("candidate review statement", value)
