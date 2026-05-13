"""Deterministic Markdown rendering for audit research briefs."""

from collections.abc import Iterable

from invariant_os.core.models import (
    AuditResult,
    BoundaryCandidate,
    Consumer,
    Entrypoint,
    Evidence,
    PrimitiveCandidate,
    Worker,
)


def render_research_brief(result: AuditResult) -> str:
    """Render a conservative research brief for an authorized local audit."""
    lines: list[str] = [
        "# InvariantOS Research Brief",
        "",
        "## Scope and Safety",
        "",
        "This brief is limited to authorized local repository analysis. It summarizes static candidates and hypotheses only; it does not prove exploitability.",
        f"Core principle: {result.safety.principle}",
        "",
        "## Summary",
        "",
        f"- Files indexed: {result.summary.files}",
        f"- Entrypoints: {result.summary.entrypoints}",
        f"- Dangerous consumers: {result.summary.consumers}",
        f"- Worker/background candidates: {result.summary.workers}",
        f"- Trust boundary candidates: {result.summary.boundaries}",
        f"- Primitive candidates to investigate: {result.summary.primitive_candidates}",
        "",
        "## Repository Profile",
        "",
        f"- Project: {result.project.name}",
        f"- Root: {result.project.root}",
        f"- Schema version: {result.schema_version}",
        "",
        "## Entrypoints",
        "",
        *_render_entrypoints(result.entrypoints),
        "",
        "## Worker and Background Job Candidates",
        "",
        *_render_workers(result.workers),
        "",
        "## Dangerous Consumer Inventory",
        "",
        *_render_consumers(result.consumers),
        "",
        "## Trust Boundary Candidates",
        "",
        *_render_boundaries(result.boundaries),
        "",
        "## Primitive Candidates To Investigate",
        "",
        *_render_primitives(result.primitive_candidates),
        "",
        "## Suggested Security Invariants",
        "",
        *_render_invariants(result.boundaries),
        "",
        "## Missing Evidence",
        "",
        *_render_missing_evidence(result.primitive_candidates),
        "",
        "## Safe Manual Review Plan",
        "",
        *_render_manual_review(result.primitive_candidates),
        "",
        "## Appendix: Evidence Index",
        "",
        *_render_evidence_index(result),
        "",
    ]
    return "\n".join(lines)


def _render_entrypoints(entrypoints: list[Entrypoint]) -> list[str]:
    if not entrypoints:
        return ["No entrypoint candidates were detected."]
    return [
        f"- `{entrypoint.id}` {entrypoint.type.value} candidate in `{entrypoint.file}:{entrypoint.line}`"
        f"{_route_suffix(entrypoint)}; evidence: {_evidence_refs(entrypoint.evidence)}"
        for entrypoint in entrypoints
    ]


def _render_workers(workers: list[Worker]) -> list[str]:
    if not workers:
        return ["No worker or background job candidates were detected."]
    return [
        f"- `{worker.id}` {worker.type.value} candidate in `{worker.file}:{worker.line}` "
        f"via `{worker.pattern}`; evidence: {_evidence_refs(worker.evidence)}"
        for worker in workers
    ]


def _render_consumers(consumers: list[Consumer]) -> list[str]:
    if not consumers:
        return ["No dangerous consumer candidates were detected."]
    return [
        f"- `{consumer.id}` {consumer.type.value} candidate in `{consumer.file}:{consumer.line}` "
        f"via `{consumer.pattern}`; evidence: {_evidence_refs(consumer.evidence)}"
        for consumer in consumers
    ]


def _render_boundaries(boundaries: list[BoundaryCandidate]) -> list[str]:
    if not boundaries:
        return ["No trust boundary candidates were inferred."]
    return [
        f"- `{boundary.id}` {boundary.type.value} ({boundary.confidence.value} confidence): "
        f"{boundary.reason} Evidence: {_evidence_refs(boundary.evidence)}"
        for boundary in boundaries
    ]


def _render_primitives(primitives: list[PrimitiveCandidate]) -> list[str]:
    if not primitives:
        return ["No primitive candidates were classified. This is not a security conclusion."]
    return [
        f"- `{primitive.id}` {primitive.primitive.value} hypothesis ({primitive.confidence.value} confidence). "
        f"Evidence: {_evidence_refs(primitive.evidence)}. Missing evidence: {_join_or_none(primitive.missing_evidence)}"
        for primitive in primitives
    ]


def _render_invariants(boundaries: list[BoundaryCandidate]) -> list[str]:
    if not boundaries:
        return ["- Preserve explicit validation before data crosses any newly identified trust boundary."]
    return [
        f"- For `{boundary.type.value}`, require documented validation, normalization, authorization, and logging before data crosses this candidate boundary."
        for boundary in boundaries
    ]


def _render_missing_evidence(primitives: list[PrimitiveCandidate]) -> list[str]:
    items: list[str] = []
    for primitive in primitives:
        for missing in primitive.missing_evidence:
            items.append(f"- `{primitive.id}`: {missing}")
    return items or ["No primitive-specific missing evidence was recorded."]


def _render_manual_review(primitives: list[PrimitiveCandidate]) -> list[str]:
    steps: list[str] = [
        "- Review candidates with benign inputs only.",
        "- Confirm data origin, validation, authorization, and sink semantics before changing code.",
    ]
    for primitive in primitives:
        for step in primitive.safe_next_steps:
            steps.append(f"- `{primitive.id}`: {step}")
    return steps


def _render_evidence_index(result: AuditResult) -> list[str]:
    evidence = _unique_evidence(
        *[entrypoint.evidence for entrypoint in result.entrypoints],
        *[consumer.evidence for consumer in result.consumers],
        *[worker.evidence for worker in result.workers],
        *[boundary.evidence for boundary in result.boundaries],
        *[primitive.evidence for primitive in result.primitive_candidates],
    )
    if not evidence:
        return ["No evidence records were collected."]
    return [
        f"- `{item.id}` {item.type.value} `{item.file}:{item.line}` pattern `{item.pattern or 'n/a'}`"
        for item in evidence
    ]


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


def _route_suffix(entrypoint: Entrypoint) -> str:
    details = []
    if entrypoint.method:
        details.append(entrypoint.method.upper())
    if entrypoint.route_path:
        details.append(entrypoint.route_path)
    if entrypoint.framework_hint:
        details.append(entrypoint.framework_hint)
    return f" ({', '.join(details)})" if details else ""


def _evidence_refs(evidence: list[Evidence]) -> str:
    if not evidence:
        return "none recorded"
    return ", ".join(f"`{item.id}`" for item in evidence)


def _join_or_none(values: list[str]) -> str:
    return "; ".join(values) if values else "none recorded"
