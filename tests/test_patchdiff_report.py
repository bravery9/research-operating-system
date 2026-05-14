from invariant_os.core.models import (
    Confidence,
    PatchChangedFile,
    PatchChangeType,
    PatchCorrelation,
    PatchCorrelationType,
    PatchDiffInputType,
    PatchDiffResult,
    PatchDiffSummary,
    PatchHunk,
    PatchVariantCandidate,
    PatchVariantSourceType,
    Project,
)
from invariant_os.report.patch_diff_markdown import render_patch_diff_brief

REQUIRED_SECTIONS = [
    "# InvariantOS Patch Diff Brief",
    "## Scope and Safety",
    "## Source Audit",
    "## Diff Input",
    "## Summary",
    "## Changed Files",
    "## Correlations",
    "## Variant Candidates",
    "## Missing Evidence",
    "## Safe Next Steps",
]


def _patch_diff_result() -> PatchDiffResult:
    return PatchDiffResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/repo/audit_result.json",
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
        changed_files=[
            PatchChangedFile(
                id="patch_file_0001",
                old_path="app.py",
                new_path="app.py",
                change_type=PatchChangeType.MODIFIED,
                hunks=[
                    PatchHunk(
                        id="patch_hunk_0001_0001",
                        old_start=10,
                        old_count=3,
                        new_start=10,
                        new_count=4,
                        added_lines=[12],
                        removed_lines=[11],
                    )
                ],
            )
        ],
        correlations=[
            PatchCorrelation(
                id="patch_corr_0001",
                type=PatchCorrelationType.LINE_OVERLAP,
                changed_file_id="patch_file_0001",
                hunk_id="patch_hunk_0001_0001",
                related_id="primitive_0001",
                related_type=PatchVariantSourceType.PRIMITIVE,
                file="app.py",
                line=12,
                confidence=Confidence.MEDIUM,
                reason="Candidate correlation because changed lines overlap existing audit evidence.",
                evidence_ids=["ev_0001"],
                missing_evidence=[
                    "confirm whether the changed code affects the audited path before drawing conclusions"
                ],
            )
        ],
        variant_candidates=[
            PatchVariantCandidate(
                id="patch_variant_0001",
                source_type=PatchVariantSourceType.PRIMITIVE,
                source_id="primitive_0001",
                changed_file_id="patch_file_0001",
                hunk_id="patch_hunk_0001_0001",
                confidence=Confidence.MEDIUM,
                title="Patch-adjacent primitive hypothesis primitive_0001",
                summary="Candidate variant review item only.",
                related_ids=["primitive_0001"],
                evidence_ids=["ev_0001"],
                missing_evidence=[
                    "confirm data origin, validation, authorization, and sink semantics with benign local review"
                ],
                safe_next_steps=[
                    "Review the changed lines and linked audit evidence locally without executing target code."
                ],
            )
        ],
        summary=PatchDiffSummary(
            changed_files=1,
            hunks=1,
            correlations=1,
            variant_candidates=1,
            files_with_audit_context=1,
        ),
    )


def test_render_patch_diff_brief_includes_required_sections_and_metadata():
    markdown = render_patch_diff_brief(_patch_diff_result())

    for section in REQUIRED_SECTIONS:
        assert section in markdown
    assert markdown.startswith("# InvariantOS Patch Diff Brief")
    assert "authorized local repository analysis" in markdown
    assert "does not prove vulnerability or exploitability" in markdown
    assert "- Project: `example`" in markdown
    assert "- Patch diff schema version: `0.7`" in markdown
    assert "- Input type: `patch_file`" in markdown
    assert "- Changed files: 1" in markdown
    assert "`patch_file_0001` `app.py` modified" in markdown
    assert "`patch_hunk_0001_0001`" in markdown
    assert "`patch_corr_0001`" in markdown
    assert "`patch_variant_0001`" in markdown
    assert "`ev_0001`" in markdown


def test_render_patch_diff_brief_uses_none_recorded_for_empty_sections():
    result = PatchDiffResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/repo/audit_result.json",
        input_type=PatchDiffInputType.GIT_DIFF,
        repo_path="/repo",
        base_ref="main",
        head_ref="feature",
        summary=PatchDiffSummary(
            changed_files=0,
            hunks=0,
            correlations=0,
            variant_candidates=0,
            files_with_audit_context=0,
        ),
    )

    markdown = render_patch_diff_brief(result)

    assert "No changed files were parsed." in markdown
    assert "No patch correlations were generated." in markdown
    assert "No patch variant candidates were generated." in markdown
    assert "- Patch file: none recorded" in markdown


def test_patch_diff_markdown_avoids_confirmation_and_payload_language():
    markdown = render_patch_diff_brief(_patch_diff_result()).lower()

    for term in [
        "confirmed vulnerable",
        "confirmed exploitable",
        "exploitability proved",
        "payload to exploit",
        "proof of exploit",
    ]:
        assert term not in markdown
