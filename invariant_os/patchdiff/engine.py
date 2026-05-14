"""Deterministic patch-diff correlation over audit artifacts."""

from __future__ import annotations

import re

from invariant_os.core.models import (
    AuditResult,
    Confidence,
    Evidence,
    PatchChangedFile,
    PatchCorrelation,
    PatchCorrelationType,
    PatchDiffInputType,
    PatchDiffResult,
    PatchDiffSummary,
    PatchHunk,
    PatchVariantCandidate,
    PatchVariantSourceType,
)

LINE_PROXIMITY_WINDOW = 20
MAX_CORRELATIONS = 200
MAX_VARIANT_CANDIDATES = 100
_FORBIDDEN_PATTERN = re.compile(
    r"confirmed vulnerable|confirmed exploitable|exploitability proved|payload to exploit|proof of exploit",
    re.IGNORECASE,
)


def build_patch_diff_result(
    audit: AuditResult,
    source_audit_file: str,
    changed_files: list[PatchChangedFile],
    *,
    input_type: PatchDiffInputType,
    patch_file: str | None = None,
    repo_path: str | None = None,
    base_ref: str | None = None,
    head_ref: str | None = None,
) -> PatchDiffResult:
    evidence_records = _collect_evidence_records(audit)
    correlations = _build_correlations(changed_files, evidence_records)
    variants = _build_variants(correlations, evidence_records)[:MAX_VARIANT_CANDIDATES]
    return PatchDiffResult(
        source_schema_version=audit.schema_version,
        source_project=audit.project,
        source_audit_file=source_audit_file,
        input_type=input_type,
        patch_file=patch_file,
        repo_path=repo_path,
        base_ref=base_ref,
        head_ref=head_ref,
        changed_files=changed_files,
        correlations=correlations,
        variant_candidates=variants,
        summary=PatchDiffSummary(
            changed_files=len(changed_files),
            hunks=sum(len(changed_file.hunks) for changed_file in changed_files),
            correlations=len(correlations),
            variant_candidates=len(variants),
            files_with_audit_context=len({correlation.changed_file_id for correlation in correlations}),
        ),
        safety=audit.safety,
    )


def _build_correlations(
    changed_files: list[PatchChangedFile], records: list["_EvidenceRecord"]
) -> list[PatchCorrelation]:
    correlations: list[PatchCorrelation] = []
    seen: set[tuple[str, str | None, str, PatchVariantSourceType, PatchCorrelationType]] = set()
    for changed_file in changed_files:
        paths = _changed_paths(changed_file)
        file_records = [record for record in records if _normalize_path(record.evidence.file) in paths]
        if not file_records:
            continue
        hunk_matched = False
        for hunk in changed_file.hunks:
            for record in file_records:
                correlation_type = _hunk_correlation_type(record.evidence.line, hunk)
                if correlation_type is None:
                    continue
                hunk_matched = True
                _append_correlation(
                    correlations,
                    seen,
                    changed_file,
                    hunk,
                    record,
                    correlation_type,
                )
                if len(correlations) >= MAX_CORRELATIONS:
                    return correlations
        if hunk_matched:
            continue
        for record in file_records:
            _append_correlation(
                correlations,
                seen,
                changed_file,
                None,
                record,
                PatchCorrelationType.SAME_FILE,
            )
            if len(correlations) >= MAX_CORRELATIONS:
                return correlations
    return correlations


def _append_correlation(
    correlations: list[PatchCorrelation],
    seen: set[tuple[str, str | None, str, PatchVariantSourceType, PatchCorrelationType]],
    changed_file: PatchChangedFile,
    hunk: PatchHunk | None,
    record: "_EvidenceRecord",
    correlation_type: PatchCorrelationType,
) -> None:
    key = (changed_file.id, hunk.id if hunk else None, record.related_id, record.related_type, correlation_type)
    if key in seen:
        return
    seen.add(key)
    correlations.append(
        PatchCorrelation(
            id=f"patch_corr_{len(correlations) + 1:04d}",
            type=correlation_type,
            changed_file_id=changed_file.id,
            hunk_id=hunk.id if hunk else None,
            related_id=record.related_id,
            related_type=record.related_type,
            file=record.evidence.file,
            line=record.evidence.line,
            confidence=_correlation_confidence(correlation_type),
            reason=_correlation_reason(correlation_type),
            evidence_ids=[record.evidence.id],
            missing_evidence=[
                "confirm whether the changed code affects the audited path before drawing conclusions"
            ],
        )
    )


def _build_variants(
    correlations: list[PatchCorrelation], records: list["_EvidenceRecord"]
) -> list[PatchVariantCandidate]:
    variants: list[PatchVariantCandidate] = []
    by_related = {(record.related_type, record.related_id): record for record in records}
    seen: set[tuple[PatchVariantSourceType, str, str, str | None]] = set()
    for correlation in correlations:
        key = (
            correlation.related_type,
            correlation.related_id,
            correlation.changed_file_id,
            correlation.hunk_id,
        )
        if key in seen:
            continue
        seen.add(key)
        record = by_related.get((correlation.related_type, correlation.related_id))
        variants.append(
            PatchVariantCandidate(
                id=f"patch_variant_{len(variants) + 1:04d}",
                source_type=correlation.related_type,
                source_id=correlation.related_id,
                changed_file_id=correlation.changed_file_id,
                hunk_id=correlation.hunk_id,
                confidence=correlation.confidence,
                title=_variant_title(correlation),
                summary=_variant_summary(correlation, record),
                related_ids=[correlation.related_id],
                evidence_ids=correlation.evidence_ids,
                missing_evidence=[
                    "confirm data origin, validation, authorization, and sink semantics with benign local review"
                ],
                safe_next_steps=[
                    "Review the changed lines and linked audit evidence locally without executing target code.",
                    "Check whether validation, authorization, or normalization assumptions changed.",
                ],
            )
        )
    return variants


def _hunk_correlation_type(line: int, hunk: PatchHunk) -> PatchCorrelationType | None:
    if line in hunk.added_lines or hunk.new_start <= line < hunk.new_start + hunk.new_count:
        return PatchCorrelationType.LINE_OVERLAP
    start = hunk.new_start - LINE_PROXIMITY_WINDOW
    end = hunk.new_start + hunk.new_count + LINE_PROXIMITY_WINDOW
    if start <= line <= end:
        return PatchCorrelationType.LINE_PROXIMITY
    return None


def _correlation_confidence(correlation_type: PatchCorrelationType) -> Confidence:
    if correlation_type == PatchCorrelationType.LINE_OVERLAP:
        return Confidence.MEDIUM
    return Confidence.LOW


def _correlation_reason(correlation_type: PatchCorrelationType) -> str:
    if correlation_type == PatchCorrelationType.LINE_OVERLAP:
        return "Candidate correlation because changed lines overlap existing audit evidence in the same local file."
    if correlation_type == PatchCorrelationType.LINE_PROXIMITY:
        return "Candidate correlation because changed lines are near existing audit evidence in the same local file."
    return "Candidate file-level correlation because the patch changes a file with existing audit context."


def _variant_title(correlation: PatchCorrelation) -> str:
    labels = {
        PatchVariantSourceType.PRIMITIVE: "primitive hypothesis",
        PatchVariantSourceType.BOUNDARY: "boundary hypothesis",
        PatchVariantSourceType.STATIC_FLOW: "static-flow hypothesis",
        PatchVariantSourceType.EVIDENCE: "evidence review",
    }
    return _safe_text(f"Patch-adjacent {labels[correlation.related_type]} {correlation.related_id}")


def _variant_summary(correlation: PatchCorrelation, record: "_EvidenceRecord" | None) -> str:
    if correlation.related_type == PatchVariantSourceType.PRIMITIVE:
        detail = f" for `{record.detail}`" if record and record.detail else ""
        return _safe_text(
            f"Candidate variant review item because the patch changes code near an existing{detail} primitive hypothesis. This does not confirm exploitability."
        )
    if correlation.related_type == PatchVariantSourceType.BOUNDARY:
        detail = f" `{record.detail}`" if record and record.detail else ""
        return _safe_text(
            f"Candidate variant review item because the patch changes code near an existing{detail} boundary hypothesis. This does not confirm a vulnerability."
        )
    if correlation.related_type == PatchVariantSourceType.STATIC_FLOW:
        return _safe_text(
            "Candidate variant review item because the patch changes code near an existing static-flow candidate. Runtime dispatch and data influence remain missing evidence."
        )
    return _safe_text(
        "Candidate review item because the patch changes code near existing audit evidence. This is a hypothesis for manual review only."
    )


def _collect_evidence_records(audit: AuditResult) -> list["_EvidenceRecord"]:
    records: list[_EvidenceRecord] = []
    seen: set[tuple[str, str, PatchVariantSourceType]] = set()
    for entrypoint in audit.entrypoints:
        _add_direct_records(
            records, seen, entrypoint.id, PatchVariantSourceType.EVIDENCE, entrypoint.evidence
        )
    for consumer in audit.consumers:
        _add_direct_records(records, seen, consumer.id, PatchVariantSourceType.EVIDENCE, consumer.evidence)
    for worker in audit.workers:
        _add_direct_records(records, seen, worker.id, PatchVariantSourceType.EVIDENCE, worker.evidence)
    for boundary in audit.boundaries:
        _add_candidate_records(
            records,
            seen,
            boundary.id,
            PatchVariantSourceType.BOUNDARY,
            boundary.evidence,
            boundary.type.value,
        )
    for primitive in audit.primitive_candidates:
        _add_candidate_records(
            records,
            seen,
            primitive.id,
            PatchVariantSourceType.PRIMITIVE,
            primitive.evidence,
            primitive.primitive.value,
        )
    for flow in audit.static_flow_candidates:
        _add_candidate_records(
            records,
            seen,
            flow.id,
            PatchVariantSourceType.STATIC_FLOW,
            flow.evidence,
            flow.target_ref_id,
        )
    return records


def _add_direct_records(
    records: list["_EvidenceRecord"],
    seen: set[tuple[str, str, PatchVariantSourceType]],
    related_id: str,
    related_type: PatchVariantSourceType,
    evidence_items: list[Evidence],
) -> None:
    _add_candidate_records(records, seen, related_id, related_type, evidence_items, None)


def _add_candidate_records(
    records: list["_EvidenceRecord"],
    seen: set[tuple[str, str, PatchVariantSourceType]],
    related_id: str,
    related_type: PatchVariantSourceType,
    evidence_items: list[Evidence],
    detail: str | None,
) -> None:
    for evidence in evidence_items:
        key = (evidence.id, related_id, related_type)
        if key in seen:
            continue
        seen.add(key)
        records.append(_EvidenceRecord(evidence, related_id, related_type, detail))


def _changed_paths(changed_file: PatchChangedFile) -> set[str]:
    return {
        normalized
        for normalized in (
            _normalize_path(changed_file.old_path),
            _normalize_path(changed_file.new_path),
        )
        if normalized is not None
    }


def _normalize_path(value: str | None) -> str | None:
    if value is None:
        return None
    path = value.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path


def _safe_text(value: str) -> str:
    return _FORBIDDEN_PATTERN.sub("candidate review statement", value)


class _EvidenceRecord:
    def __init__(
        self,
        evidence: Evidence,
        related_id: str,
        related_type: PatchVariantSourceType,
        detail: str | None,
    ) -> None:
        self.evidence = evidence
        self.related_id = related_id
        self.related_type = related_type
        self.detail = detail
