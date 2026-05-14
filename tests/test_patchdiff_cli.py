from pathlib import Path
import subprocess
import sys

from typer.testing import CliRunner

from invariant_os.cli import app
from invariant_os.core.models import AuditResult, AuditSummary, Project

runner = CliRunner()


def _audit_result_json() -> str:
    result = AuditResult(
        project=Project(name="example", root="/repo"),
        summary=AuditSummary(
            files=0,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
            static_flow_candidates=0,
        ),
    )
    return result.model_dump_json()


def _patch_text() -> str:
    return """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,1 @@
-old
+new
"""


def test_cli_help_shows_patch_diff_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "patch-diff" in result.output


def test_patch_diff_rejects_url_audit_input():
    result = runner.invoke(app, ["patch-diff", "https://example.com/audit_result.json"])

    assert result.exit_code != 0
    assert "local json file" in result.output.lower()


def test_patch_diff_requires_exactly_one_input_mode(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")

    result = runner.invoke(app, ["patch-diff", str(audit_path)])

    assert result.exit_code != 0
    assert "exactly one patch input mode" in result.output.lower()


def test_patch_diff_rejects_malformed_audit_json(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text('{"not": "an audit result"}', encoding="utf-8")
    patch_path = tmp_path / "change.patch"
    patch_path.write_text(_patch_text(), encoding="utf-8")

    result = runner.invoke(app, ["patch-diff", str(audit_path), "--patch-file", str(patch_path)])

    assert result.exit_code != 0
    assert "valid invariantos audit_result.json" in result.output.lower()


def test_patch_diff_writes_artifacts_from_patch_file(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")
    patch_path = tmp_path / "change.patch"
    patch_path.write_text(_patch_text(), encoding="utf-8")
    output_dir = tmp_path / "patch-output"

    result = runner.invoke(
        app,
        [
            "patch-diff",
            str(audit_path),
            "--patch-file",
            str(patch_path),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "patch_diff_result.json").exists()
    assert (output_dir / "patch_diff_brief.md").exists()
    assert "InvariantOS patch diff analysis complete" in result.output
    assert "Patch diff JSON:" in result.output
    assert "Patch diff Markdown:" in result.output


def test_patch_diff_writes_artifacts_from_git_diff(monkeypatch, tmp_path):
    import invariant_os.cli as cli_module

    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    output_dir = tmp_path / "patch-output"

    monkeypatch.setattr(cli_module, "collect_git_diff", lambda repo_path, base_ref, head_ref: _patch_text())

    result = runner.invoke(
        app,
        [
            "patch-diff",
            str(audit_path),
            "--repo-path",
            str(repo),
            "--base-ref",
            "main",
            "--head-ref",
            "feature",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "patch_diff_result.json").exists()
    assert (output_dir / "patch_diff_brief.md").exists()


def test_patch_diff_defaults_output_dir_to_input_parent(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")
    patch_path = tmp_path / "change.patch"
    patch_path.write_text(_patch_text(), encoding="utf-8")

    result = runner.invoke(app, ["patch-diff", str(audit_path), "--patch-file", str(patch_path)])

    assert result.exit_code == 0
    assert (tmp_path / "patch_diff_result.json").exists()
    assert (tmp_path / "patch_diff_brief.md").exists()


def test_module_execution_runs_patch_diff_command_and_writes_outputs(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")
    patch_path = tmp_path / "change.patch"
    patch_path.write_text(_patch_text(), encoding="utf-8")
    output_dir = tmp_path / "module-patch-output"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "invariant_os.cli",
            "patch-diff",
            str(audit_path),
            "--patch-file",
            str(patch_path),
            "--output-dir",
            str(output_dir),
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (output_dir / "patch_diff_result.json").exists()
    assert (output_dir / "patch_diff_brief.md").exists()
