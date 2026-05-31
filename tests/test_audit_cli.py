from pathlib import Path
import json
import re
import subprocess
import sys

from typer.testing import CliRunner

from invariant_os.cli import app
from invariant_os.core.models import AuditResult, BoundaryType, ConsumerType, FocusMetadata, PrimitiveType


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


def test_audit_writes_artifacts_for_fixture(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(app, ["audit", str(fixture), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    json_path = output_dir / "audit_result.json"
    markdown_path = output_dir / "research_brief.md"
    graph_path = output_dir / "evidence_graph.json"
    html_path = output_dir / "evidence_viewer.html"
    sarif_path = output_dir / "audit_result.sarif.json"
    review_queue_path = output_dir / "audit_review_queue.jsonl"
    assert json_path.exists()
    assert markdown_path.exists()
    assert graph_path.exists()
    assert html_path.exists()
    assert sarif_path.exists()
    assert review_queue_path.exists()
    assert "Evidence viewer:" in result.output
    assert "SARIF:" in result.output
    assert "Review queue:" in result.output

    audit_result = AuditResult.model_validate_json(json_path.read_text(encoding="utf-8"))
    assert audit_result.summary.entrypoints > 0
    assert audit_result.summary.workers > 0
    assert audit_result.summary.boundaries > 0
    assert audit_result.summary.primitive_candidates > 0
    assert audit_result.evidence_graph.nodes
    assert audit_result.evidence_graph.edges
    assert any(edge.type.value == "defined_in" for edge in audit_result.evidence_graph.edges)
    assert audit_result.focus == FocusMetadata(
        mode="all",
        label="All Evidence",
        description="Default lens over all deterministic audit evidence.",
        boundary_matches=len(audit_result.boundaries),
        primitive_matches=len(audit_result.primitive_candidates),
        static_flow_matches=len(audit_result.static_flow_candidates),
        total_matches=(
            len(audit_result.boundaries)
            + len(audit_result.primitive_candidates)
            + len(audit_result.static_flow_candidates)
        ),
    )
    graph_payload = graph_path.read_text(encoding="utf-8")
    assert '"nodes"' in graph_payload
    assert '"edges"' in graph_payload
    review_queue_rows = [
        json.loads(line) for line in review_queue_path.read_text(encoding="utf-8").splitlines()
    ]
    assert review_queue_rows
    assert all(row["queue_type"] == "manual_review_candidate" for row in review_queue_rows)


def test_audit_accepts_focus_option_and_writes_focus_metadata(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"
    output_dir = tmp_path / "focus-output"

    result = runner.invoke(
        app,
        ["audit", str(fixture), "--output-dir", str(output_dir), "--focus", "import-upload"],
    )

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert audit_result.focus.mode == "import-upload"
    assert audit_result.focus.label == "Import / Upload"
    assert audit_result.focus.total_matches >= 0


def test_audit_rejects_unknown_focus_option(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"

    result = runner.invoke(app, ["audit", str(fixture), "--focus", "internet"])

    assert result.exit_code != 0
    assert "focus.mode" in result.output


def test_audit_writes_java_tomcat_fixture_signals(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_tomcat_app"
    output_dir = tmp_path / "tomcat-audit-output"

    result = runner.invoke(app, ["audit", str(fixture), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    json_path = output_dir / "audit_result.json"
    markdown_path = output_dir / "research_brief.md"
    graph_path = output_dir / "evidence_graph.json"
    html_path = output_dir / "evidence_viewer.html"
    sarif_path = output_dir / "audit_result.sarif.json"
    review_queue_path = output_dir / "audit_review_queue.jsonl"
    audit_result = AuditResult.model_validate_json(json_path.read_text(encoding="utf-8"))
    consumer_types = {consumer.type for consumer in audit_result.consumers}
    boundary_types = {boundary.type for boundary in audit_result.boundaries}
    primitive_types = {candidate.primitive for candidate in audit_result.primitive_candidates}

    assert graph_path.exists()
    assert html_path.exists()
    assert sarif_path.exists()
    assert review_queue_path.exists()
    assert audit_result.schema_version == "0.10"
    assert audit_result.static_flow_candidates
    assert audit_result.summary.static_flow_candidates == len(audit_result.static_flow_candidates)
    assert all(candidate.missing_evidence for candidate in audit_result.static_flow_candidates)

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

    graph = audit_result.evidence_graph
    node_labels = {node.label for node in graph.nodes}
    graph_edge_types = {edge.type.value for edge in graph.edges}
    assert any("/reports/export" in label or "/legacy/report.do" in label for label in node_labels)
    assert "defined_in" in graph_edge_types
    assert "boundary_evidence" in graph_edge_types
    assert "primitive_evidence" in graph_edge_types
    assert {
        "route_to_worker_candidate",
        "route_to_consumer_candidate",
    } & graph_edge_types
    assert "static_flow_source" in graph_edge_types
    assert "static_flow_target" in graph_edge_types
    assert len(graph.edges) < 275
    forbidden_claim_terms = re.compile(r"\b(exploit|rce|compromise|confirmed|vulnerable)\b")
    assert all(forbidden_claim_terms.search(edge.reason.lower()) is None for edge in graph.edges)
    assert all(
        forbidden_claim_terms.search(candidate.summary.lower()) is None
        for candidate in audit_result.static_flow_candidates
    )

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "Static Flow/Dataflow Candidates" in markdown
    assert "authorized local repository analysis" in markdown
    assert "does not prove exploitability" in markdown
    assert "confirmed vulnerable" not in markdown.lower()

    html = html_path.read_text(encoding="utf-8")
    assert "InvariantOS Static Evidence Workspace" in html
    assert "Static Flow/Dataflow Candidates" in html


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
    assert (output_dir / "evidence_graph.json").exists()
    assert (output_dir / "evidence_viewer.html").exists()
    assert (output_dir / "audit_result.sarif.json").exists()
    assert (output_dir / "audit_review_queue.jsonl").exists()


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
    assert (output_dir / "evidence_graph.json").exists()
    assert (output_dir / "evidence_viewer.html").exists()
    assert (output_dir / "audit_result.sarif.json").exists()
    assert (output_dir / "audit_review_queue.jsonl").exists()


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


def test_audit_auto_loads_repo_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "invariant-os.yml").write_text("project:\n  name: repo-config\n", encoding="utf-8")
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert audit_result.project.name == "repo-config"


def test_audit_explicit_config_overrides_repo_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "invariant-os.yml").write_text("project:\n  name: repo-config\n", encoding="utf-8")
    explicit_config = tmp_path / "explicit.yml"
    explicit_config.write_text("project:\n  name: explicit-config\n", encoding="utf-8")
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(
        app,
        ["audit", str(repo), "--config", str(explicit_config), "--output-dir", str(output_dir)],
    )

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert audit_result.project.name == "explicit-config"


def test_audit_uses_yaml_max_file_bytes_without_cli_override(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "small.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "large.py").write_text("x" * 20, encoding="utf-8")
    (repo / "invariant-os.yml").write_text("max_file_bytes: 10\n", encoding="utf-8")
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert [record.path for record in audit_result.files] == ["small.py"]


def test_audit_max_file_bytes_overrides_yaml_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "small.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "large.py").write_text("x" * 20, encoding="utf-8")
    (repo / "invariant-os.yml").write_text("max_file_bytes: 100\n", encoding="utf-8")
    output_dir = tmp_path / "audit-output"

    result = runner.invoke(
        app,
        ["audit", str(repo), "--max-file-bytes", "10", "--output-dir", str(output_dir)],
    )

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert [record.path for record in audit_result.files] == ["small.py"]


def test_audit_rejects_explicit_missing_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    result = runner.invoke(app, ["audit", str(repo), "--config", str(tmp_path / "missing.yml")])

    assert result.exit_code != 0
    assert "config" in result.output.lower()


def test_audit_rejects_enabled_llm_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    config_path = repo / "invariant-os.yml"
    config_path.write_text("llm:\n  enabled: true\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(repo)])

    assert result.exit_code != 0
    assert "llm" in result.output.lower()


def test_audit_rejects_enabled_semgrep_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    config_path = repo / "invariant-os.yml"
    config_path.write_text("semgrep:\n  enabled: true\n", encoding="utf-8")

    result = runner.invoke(app, ["audit", str(repo)])

    assert result.exit_code != 0
    assert "semgrep" in result.output.lower()


def test_repeated_audit_ignores_output_directory_with_repo_config(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / "invariant-os.yml").write_text("project:\n  name: repo-config\n", encoding="utf-8")
    output_dir = repo / "outputs"

    first = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])
    second = runner.invoke(app, ["audit", str(repo), "--output-dir", str(output_dir)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert [record.path for record in audit_result.files] == ["app.py", "invariant-os.yml"]
