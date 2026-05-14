import pytest

from invariant_os.core.config import AuditConfig, load_audit_config


def test_load_audit_config_returns_defaults_without_repo_config(tmp_path):
    config = load_audit_config(tmp_path, None)

    assert "node_modules" in config.ignore_dirs
    assert config.max_file_bytes == 1_000_000
    assert config.llm.enabled is False
    assert config.semgrep.enabled is False


def test_load_audit_config_rejects_explicit_missing_file(tmp_path):
    with pytest.raises(ValueError, match="config"):
        load_audit_config(tmp_path, tmp_path / "missing.yml")


def test_load_audit_config_merges_yaml_ignore_dirs_and_paths(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text(
        "ignore:\n"
        "  dirs:\n"
        "    - generated\n"
        "  paths:\n"
        "    - fixtures/large\n",
        encoding="utf-8",
    )

    config = load_audit_config(tmp_path, config_path)

    assert "node_modules" in config.ignore_dirs
    assert "generated" in config.ignore_dirs
    assert (tmp_path / "fixtures" / "large").resolve() in config.ignore_paths


def test_load_audit_config_applies_max_file_bytes_override(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text("max_file_bytes: 999\n", encoding="utf-8")

    config = load_audit_config(tmp_path, config_path, max_file_bytes=123)

    assert config.max_file_bytes == 123


@pytest.mark.parametrize(
    "yaml_text",
    [
        "llm:\n  enabled: true\n",
        "semgrep:\n  enabled: true\n",
    ],
)
def test_load_audit_config_rejects_enabled_future_integrations(tmp_path, yaml_text):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text(yaml_text, encoding="utf-8")

    with pytest.raises(ValueError, match="disabled|unsupported|local"):
        load_audit_config(tmp_path, config_path)


@pytest.mark.parametrize(
    "yaml_text",
    [
        "ignore:\n  paths:\n    - /etc\n",
        "ignore:\n  paths:\n    - ../outside\n",
        "focus:\n  files:\n    - /etc\n",
        "focus:\n  files:\n    - ../outside\n",
    ],
)
def test_load_audit_config_rejects_non_local_config_paths(tmp_path, yaml_text):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text(yaml_text, encoding="utf-8")

    with pytest.raises(ValueError, match="local|path"):
        load_audit_config(tmp_path, config_path)


def test_load_audit_config_rejects_non_mapping_yaml_root(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="mapping|config"):
        load_audit_config(tmp_path, config_path)


def test_load_audit_config_rejects_unknown_detector_pattern(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text(
        "focus:\n"
        "  detectors:\n"
        "    entrypoints:\n"
        "      include:\n"
        "        - not_real\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown detector pattern"):
        load_audit_config(tmp_path, config_path)


def test_load_audit_config_accepts_known_detector_patterns(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text(
        "focus:\n"
        "  detectors:\n"
        "    entrypoints:\n"
        "      exclude:\n"
        "        - generic_graphql\n"
        "    consumers:\n"
        "      include:\n"
        "        - file_operation\n"
        "    workers:\n"
        "      exclude:\n"
        "        - taskengine_task\n",
        encoding="utf-8",
    )

    config = load_audit_config(tmp_path, config_path)

    assert config.focus.detectors.entrypoints.exclude == {"generic_graphql"}
    assert config.focus.detectors.consumers.include == {"file_operation"}
    assert config.focus.detectors.workers.exclude == {"taskengine_task"}


def test_audit_config_direct_construction_remains_compatible():
    config = AuditConfig(ignore_dirs={"custom"}, max_file_bytes=10)

    assert config.ignore_dirs == {"custom"}
    assert config.max_file_bytes == 10
