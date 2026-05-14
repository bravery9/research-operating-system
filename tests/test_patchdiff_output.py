from invariant_os.core.models import (
    PatchDiffInputType,
    PatchDiffResult,
    PatchDiffSummary,
    Project,
)
from invariant_os.patchdiff.output import write_patch_diff_outputs


def test_write_patch_diff_outputs_writes_json_and_markdown(tmp_path):
    result = PatchDiffResult(
        source_schema_version="0.5",
        source_project=Project(name="example", root="/repo"),
        source_audit_file="/repo/audit_result.json",
        input_type=PatchDiffInputType.PATCH_FILE,
        patch_file="/repo/change.patch",
        summary=PatchDiffSummary(
            changed_files=0,
            hunks=0,
            correlations=0,
            variant_candidates=0,
            files_with_audit_context=0,
        ),
    )

    json_path, markdown_path = write_patch_diff_outputs(result, tmp_path)

    assert json_path == tmp_path / "patch_diff_result.json"
    assert markdown_path == tmp_path / "patch_diff_brief.md"
    assert json_path.exists()
    assert markdown_path.exists()
    json_payload = json_path.read_text(encoding="utf-8")
    assert '"schema_version": "0.7"' in json_payload
    assert json_payload.endswith("\n")
    assert "# InvariantOS Patch Diff Brief" in markdown_path.read_text(encoding="utf-8")
