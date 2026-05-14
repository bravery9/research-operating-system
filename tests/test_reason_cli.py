from pathlib import Path
import subprocess
import sys

from typer.testing import CliRunner

from invariant_os.cli import app
from invariant_os.core.models import (
    AuditResult,
    AuditSummary,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Evidence,
    EvidenceType,
    PrimitiveCandidate,
    PrimitiveType,
    Project,
)


runner = CliRunner()


def _audit_result_json() -> str:
    evidence = Evidence(
        id="ev_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=12,
        pattern="open(",
        snippet="open(user_path)",
    )
    result = AuditResult(
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
    return result.model_dump_json()


def test_cli_help_shows_reason_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "reason" in result.output


def test_reason_rejects_url_input():
    result = runner.invoke(app, ["reason", "https://example.com/audit_result.json"])

    assert result.exit_code != 0
    assert "local json file" in result.output.lower()


def test_reason_rejects_missing_input(tmp_path):
    result = runner.invoke(app, ["reason", str(tmp_path / "missing.json")])

    assert result.exit_code != 0
    assert "local json file" in result.output.lower()


def test_reason_rejects_malformed_audit_json(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text('{"not": "an audit result"}', encoding="utf-8")

    result = runner.invoke(app, ["reason", str(audit_path)])

    assert result.exit_code != 0
    assert "valid invariantos audit_result.json" in result.output.lower()


def test_reason_writes_artifacts_from_audit_result(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")
    output_dir = tmp_path / "reason-output"

    result = runner.invoke(app, ["reason", str(audit_path), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    assert (output_dir / "reason_result.json").exists()
    assert (output_dir / "reasoning_brief.md").exists()
    assert "InvariantOS reasoning complete" in result.output
    assert "Reasoning JSON:" in result.output
    assert "Reasoning Markdown:" in result.output


def test_reason_defaults_output_dir_to_input_parent(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")

    result = runner.invoke(app, ["reason", str(audit_path)])

    assert result.exit_code == 0
    assert (tmp_path / "reason_result.json").exists()
    assert (tmp_path / "reasoning_brief.md").exists()


def test_module_execution_runs_reason_command_and_writes_outputs(tmp_path):
    audit_path = tmp_path / "audit_result.json"
    audit_path.write_text(_audit_result_json(), encoding="utf-8")
    output_dir = tmp_path / "module-reason-output"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "invariant_os.cli",
            "reason",
            str(audit_path),
            "--output-dir",
            str(output_dir),
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (output_dir / "reason_result.json").exists()
    assert (output_dir / "reasoning_brief.md").exists()
