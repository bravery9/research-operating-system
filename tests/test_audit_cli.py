from pathlib import Path
import subprocess
import sys

from typer.testing import CliRunner

from invariant_os.cli import app
from invariant_os.core.models import AuditResult, BoundaryType, ConsumerType, PrimitiveType


runner = CliRunner()


def test_cli_help_shows_audit_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "audit" in result.output


def test_audit_rejects_url_targets():
    result = runner.invoke(app, ["audit", "https://example.com"])

    assert result.exit_code != 0
    assert "local directory" in result.output.lower()


def test_audit_rejects_nonexistent_path(tmp_path):
    result = runner.invoke(app, ["audit", str(tmp_path / "missing")])

    assert result.exit_code != 0
    assert "local directory" in result.output.lower()


def test_audit_rejects_blank_target():
    result = runner.invoke(app, ["audit", "   "])

    assert result.exit_code != 0
    assert "local directory" in result.output.lower()


def test_audit_writes_json_and_markdown_for_fixture(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(app, ["audit", str(fixture), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    json_path = output_dir / "audit_result.json"
    markdown_path = output_dir / "research_brief.md"
    assert json_path.exists()
    assert markdown_path.exists()

    audit_result = AuditResult.model_validate_json(json_path.read_text(encoding="utf-8"))
    assert audit_result.summary.entrypoints > 0
    assert audit_result.summary.workers > 0
    assert audit_result.summary.boundaries > 0
    assert audit_result.summary.primitive_candidates > 0


def test_audit_writes_java_tomcat_fixture_signals(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_tomcat_app"
    output_dir = tmp_path / "tomcat-audit-output"

    result = runner.invoke(app, ["audit", str(fixture), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    json_path = output_dir / "audit_result.json"
    markdown_path = output_dir / "research_brief.md"
    audit_result = AuditResult.model_validate_json(json_path.read_text(encoding="utf-8"))
    consumer_types = {consumer.type for consumer in audit_result.consumers}
    boundary_types = {boundary.type for boundary in audit_result.boundaries}
    primitive_types = {candidate.primitive for candidate in audit_result.primitive_candidates}

    entrypoint_hints = {entrypoint.framework_hint for entrypoint in audit_result.entrypoints}
    assert "tomcat-web-xml" in entrypoint_hints
    assert "tomcat-security-constraint" in entrypoint_hints
    assert "tomcat-connector" in entrypoint_hints
    assert "zsec-security" in entrypoint_hints
    assert "product-api-xml" in entrypoint_hints
    assert "servlet-forward-config" in entrypoint_hints
    assert "adap-rest-api" in entrypoint_hints
    assert "java-webservlet" in entrypoint_hints
    assert "jax-rs" in entrypoint_hints
    assert "java-soap" in entrypoint_hints
    assert "javascript-url-config" in entrypoint_hints
    assert any(worker.framework_hint == "taskengine" for worker in audit_result.workers)
    assert ConsumerType.CONFIG_OPERATION in consumer_types
    assert ConsumerType.ARCHIVE_OPERATION in consumer_types
    assert ConsumerType.DATABASE_OPERATION in consumer_types
    assert ConsumerType.DIRECTORY_OPERATION in consumer_types
    assert BoundaryType.DATA_TO_DATABASE in boundary_types
    assert BoundaryType.DATA_TO_DIRECTORY in boundary_types
    assert PrimitiveType.FILE_WRITE in primitive_types
    assert PrimitiveType.PATH_CONTROL in primitive_types
    assert PrimitiveType.QUERY_CONTROL in primitive_types
    assert PrimitiveType.DIRECTORY_QUERY_CONTROL in primitive_types

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "authorized local repository analysis" in markdown
    assert "does not prove exploitability" in markdown


def test_module_execution_runs_audit_command_and_writes_outputs(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"
    output_dir = tmp_path / "module-audit-output"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "invariant_os.cli",
            "audit",
            str(fixture),
            "--output-dir",
            str(output_dir),
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (output_dir / "audit_result.json").exists()
    assert (output_dir / "research_brief.md").exists()


def test_audit_rejects_repo_root_as_output_directory(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    result = runner.invoke(app, ["audit", str(repo), "--output-dir", str(repo)])

    assert result.exit_code != 0
    assert "output directory" in result.output.lower()


def test_audit_empty_repo_writes_outputs_without_crashing(tmp_path):
    repo = tmp_path / "empty-repo"
    repo.mkdir()
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert audit_result.summary.files == 0
    assert (output_dir / "research_brief.md").exists()


def test_repeated_audit_ignores_default_output_directory_inside_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    output_dir = repo / "outputs"

    first = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])
    second = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert [record.path for record in audit_result.files] == ["app.py"]


def test_repeated_audit_ignores_custom_output_directory_inside_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    output_dir = repo / "audit-output"

    first = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])
    second = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert [record.path for record in audit_result.files] == ["app.py"]


def test_repeated_audit_ignores_nested_output_without_skipping_source_dir(tmp_path):
    repo = tmp_path / "repo"
    source_dir = repo / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "app.py").write_text("print('hi')\n", encoding="utf-8")
    output_dir = source_dir / "audit-output"

    first = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])
    second = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert [record.path for record in audit_result.files] == ["src/app.py"]
