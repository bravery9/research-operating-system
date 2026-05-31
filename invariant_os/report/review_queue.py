import json
from typing import Any

from invariant_os.core.focus import (
    focus_sort_key,
    parse_focus_mode,
    score_boundary_focus,
    score_primitive_focus,
    score_static_flow_focus,
)
from invariant_os.core.models import (
    REVIEW_QUEUE_SCHEMA_VERSION,
    AuditResult,
    BoundaryCandidate,
    Evidence,
    PrimitiveCandidate,
    StaticFlowCandidate,
)

_REVIEW_SUMMARY = (
    "Manual review candidate based on local static evidence; "
    "this does not confirm vulnerability or exploitability."
)
_SAFE_REVIEW_NOTE = (
    "Review the referenced static evidence and document missing runtime context before drawing conclusions."
)


def render_review_queue_jsonl(result: AuditResult) -> str:
    focus_value = result.focus.get("mode") if isinstance(result.focus, dict) else result.focus.mode
    focus_mode = parse_focus_mode(focus_value)
    rows = [
        *_boundary_rows(result.boundaries, focus_mode),
        *_primitive_rows(result.primitive_candidates, focus_mode),
        *_static_flow_rows(result.static_flow_candidates, focus_mode),
    ]
    rows.sort(key=_row_sort_key)
    if not rows:
        return ""
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


def _boundary_rows(candidates: list[BoundaryCandidate], focus_mode: str) -> list[dict[str, Any]]:
    rows = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        if not candidate.evidence:
            continue
        focus_metadata = score_boundary_focus(candidate, focus_mode)
        rows.append(
            _build_row(
                category="boundary",
                candidate_id=candidate.id,
                kind=candidate.type.value,
                confidence=candidate.confidence.value,
                evidence=candidate.evidence,
                missing_evidence=[],
                safe_review_notes=[_SAFE_REVIEW_NOTE],
                focus_metadata=focus_metadata,
                properties={
                    "boundary_type": candidate.type.value,
                    "reason": candidate.reason,
                },
            )
        )
    return rows


def _primitive_rows(candidates: list[PrimitiveCandidate], focus_mode: str) -> list[dict[str, Any]]:
    rows = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        focus_metadata = score_primitive_focus(candidate, focus_mode)
        rows.append(
            _build_row(
                category="primitive",
                candidate_id=candidate.id,
                kind=candidate.primitive.value,
                confidence=candidate.confidence.value,
                evidence=candidate.evidence,
                missing_evidence=candidate.missing_evidence,
                safe_review_notes=[_SAFE_REVIEW_NOTE, *candidate.safe_next_steps],
                focus_metadata=focus_metadata,
                properties={
                    "primitive": candidate.primitive.value,
                    "safe_next_steps": candidate.safe_next_steps,
                },
            )
        )
    return rows


def _static_flow_rows(candidates: list[StaticFlowCandidate], focus_mode: str) -> list[dict[str, Any]]:
    rows = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        focus_metadata = score_static_flow_focus(candidate, focus_mode)
        rows.append(
            _build_row(
                category="static_flow",
                candidate_id=candidate.id,
                kind=candidate.target_type.value,
                confidence=candidate.confidence.value,
                evidence=candidate.evidence,
                missing_evidence=candidate.missing_evidence,
                safe_review_notes=[_SAFE_REVIEW_NOTE],
                focus_metadata=focus_metadata,
                properties={
                    "flow_summary": candidate.summary,
                    "score": candidate.score,
                    "signals": [
                        {
                            "evidence_ids": signal.evidence_ids,
                            "score": signal.score,
                            "term": signal.term,
                            "type": signal.type.value,
                        }
                        for signal in candidate.signals
                    ],
                    "source_entrypoint_id": candidate.source_entrypoint_id,
                    "target_ref_id": candidate.target_ref_id,
                    "target_type": candidate.target_type.value,
                },
            )
        )
    return rows


def _build_row(
    *,
    category: str,
    candidate_id: str,
    kind: str,
    confidence: str,
    evidence: list[Evidence],
    missing_evidence: list[str],
    safe_review_notes: list[str],
    focus_metadata: Any,
    properties: dict[str, Any],
) -> dict[str, Any]:
    primary = _primary_evidence(evidence)
    return {
        "schema_version": REVIEW_QUEUE_SCHEMA_VERSION,
        "queue_type": "manual_review_candidate",
        "category": category,
        "candidate_id": candidate_id,
        "kind": kind,
        "confidence": confidence,
        "summary": _REVIEW_SUMMARY,
        "focus_mode": focus_metadata.focus_mode,
        "focus_match": focus_metadata.focus_match,
        "focus_score": focus_metadata.focus_score,
        "focus_reasons": focus_metadata.focus_reasons,
        "primary_file": primary.file if primary else None,
        "primary_line": primary.line if primary else None,
        "evidence_ids": [item.id for item in evidence],
        "evidence_locations": _evidence_locations(evidence),
        "missing_evidence": missing_evidence,
        "safe_review_notes": safe_review_notes,
        "properties": properties,
    }


def _primary_evidence(evidence: list[Evidence]) -> Evidence | None:
    for item in evidence:
        if item.file and item.line > 0:
            return item
    return None


def _evidence_locations(evidence: list[Evidence]) -> list[dict[str, Any]]:
    return [
        {
            "id": item.id,
            "file": item.file,
            "line": item.line,
            "type": item.type.value,
        }
        for item in evidence
        if item.file and item.line > 0
    ]


def _row_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    existing_key = (
        row["category"],
        row["kind"],
        row["candidate_id"],
        row["primary_file"] or "",
        row["primary_line"] or 0,
    )
    return focus_sort_key(row, existing_key)
