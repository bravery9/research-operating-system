from invariant_os.core.models import (
    AUDIT_SCHEMA_VERSION,
    AuditResult,
    AuditSummary,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Evidence,
    EvidenceType,
    PatchChangedFile,
    PatchChangeType,
    PatchCorrelationType,
    PatchDiffInputType,
    PatchHunk,
    PrimitiveCandidate,
    PrimitiveType,
    Project,
)
from invariant_os.patchdiff.engine import build_patch_diff_result

_FORBIDDEN_PATCH_DIFF_TERMS = [
    "confirmed vulnerable",
    "confirmed exploitable",
    "exploitability proved",
    "payload to exploit",
    "proof of exploit",
]


def _audit_with_primitive_boundary() -> AuditResult:
    evidence = Evidence(
        id="ev_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=12,
        pattern="open(",
        snippet="open(user_path)",
    )
    return AuditResult(
        project=Project(name="example", root="/repo"),
        boundaries=[
            BoundaryCandidate(
                id="boundary_0001",
                type=BoundaryType.DATA_TO_FILE,
                confidence=Confidence.MEDIUM,
                reason="Candidate boundary where request-shaped data reaches file operations.",
                evidence=[evidence],
            )
        ],
        primitive_candidates=[
            PrimitiveCandidate(
                id="primitive_0001",
                primitive=PrimitiveType.PATH_CONTROL,
                confidence=Confidence.MEDIUM,
                evidence=[evidence],
                missing_evidence=["confirm whether request-controlled data reaches the path operation"],
                safe_next_steps=["Trace a benign sample path through the candidate operation."],
            )
        ],
        summary=AuditSummary(
            files=1,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=1,
            primitive_candidates=1,
            static_flow_candidates=0,
        ),
    )


def _changed_file(path: str, added_lines: list[int], new_start: int = 10) -> PatchChangedFile:
    return PatchChangedFile(
        id="patch_file_0001",
        old_path=path,
        new_path=path,
        change_type=PatchChangeType.MODIFIED,
        hunks=[
            PatchHunk(
                id="patch_hunk_0001_0001",
                old_start=new_start,
                old_count=3,
                new_start=new_start,
                new_count=4,
                added_lines=added_lines,
                removed_lines=[new_start + 1],
                context="handler",
            )
        ],
    )


def test_build_patch_diff_result_correlates_line_overlap_and_variant_candidate():
    result = build_patch_diff_result(
        _audit_with_primitive_boundary(),
        "/repo/audit_result.json",
        [_changed_file("app.py", [12])],
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
    )

    assert result.schema_version == "0.7"
    assert result.source_schema_version == AUDIT_SCHEMA_VERSION
    assert result.summary.changed_files == 1
    assert result.summary.hunks == 1
    assert result.summary.correlations >= 1
    assert result.summary.variant_candidates >= 1
    assert result.summary.files_with_audit_context == 1
    assert any(c.type == PatchCorrelationType.LINE_OVERLAP for c in result.correlations)
    assert any(v.source_id == "primitive_0001" for v in result.variant_candidates)


def test_build_patch_diff_result_uses_same_file_when_no_hunk_overlap():
    result = build_patch_diff_result(
        _audit_with_primitive_boundary(),
        "/repo/audit_result.json",
        [_changed_file("app.py", [101], new_start=100)],
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
    )

    assert any(c.type == PatchCorrelationType.SAME_FILE for c in result.correlations)
    assert result.summary.files_with_audit_context == 1


def test_build_patch_diff_result_has_empty_candidates_for_unrelated_file():
    result = build_patch_diff_result(
        _audit_with_primitive_boundary(),
        "/repo/audit_result.json",
        [_changed_file("other.py", [1], new_start=1)],
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
    )

    assert result.summary.changed_files == 1
    assert result.summary.correlations == 0
    assert result.summary.variant_candidates == 0
    assert result.summary.files_with_audit_context == 0


def test_patch_diff_correlation_evidence_ids_exist_in_source_audit():
    audit = _audit_with_primitive_boundary()

    result = build_patch_diff_result(
        audit,
        "/repo/audit_result.json",
        [_changed_file("app.py", [12])],
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
    )

    source_evidence_ids = {evidence.id for primitive in audit.primitive_candidates for evidence in primitive.evidence}
    for correlation in result.correlations:
        assert set(correlation.evidence_ids).issubset(source_evidence_ids)


def test_patch_diff_result_text_avoids_confirmation_and_payload_language():
    result = build_patch_diff_result(
        _audit_with_primitive_boundary(),
        "/repo/audit_result.json",
        [_changed_file("app.py", [12])],
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
    )

    text = result.model_dump_json().lower()

    for term in _FORBIDDEN_PATCH_DIFF_TERMS:
        assert term not in text
