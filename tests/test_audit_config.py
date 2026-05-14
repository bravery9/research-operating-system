from pathlib import Path

from invariant_os.core.audit import run_audit
from invariant_os.core.config import AuditConfig, FlowConfig, ProjectConfig
from invariant_os.core.models import EntrypointType


FIXTURES = Path(__file__).parent / "fixtures"


def test_run_audit_uses_configured_project_name(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    config = AuditConfig(project=ProjectConfig(name="configured-name"))

    result = run_audit(tmp_path, config)

    assert result.project.name == "configured-name"


def test_run_audit_routes_static_flow_caps_from_config():
    fixture = FIXTURES / "mini_tomcat_app"
    config = AuditConfig(flow=FlowConfig(max_candidates_total=1, max_candidates_per_entrypoint=1))

    result = run_audit(fixture, config)

    assert len(result.static_flow_candidates) <= 1
    assert result.summary.static_flow_candidates == len(result.static_flow_candidates)


def test_run_audit_routes_detector_tuning_from_config(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/preview')\n"
        "def preview():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    config = AuditConfig()
    config.focus.detectors.entrypoints.exclude = {"flask_route"}

    result = run_audit(tmp_path, config)

    assert not any(entrypoint.type == EntrypointType.HTTP_ROUTE for entrypoint in result.entrypoints)


def test_run_audit_with_config_preserves_safety_metadata(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    config = AuditConfig(project=ProjectConfig(name="configured-name"))

    result = run_audit(tmp_path, config)

    limitations = " ".join(result.safety.limitations).lower()
    assert "exploitability" in limitations
    assert "target code execution" in limitations
    assert result.safety.principle == "LLM proposes. Tools prove. Human approves."
