from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import yaml  # type: ignore[import-untyped]

from invariant_os.core.constants import DEFAULT_IGNORE_DIRS

_CONFIG_ERROR = "audit config must be a local YAML file"
_DISABLED_LLM_ERROR = "llm integration is disabled for local deterministic audit config"
_DISABLED_SEMGREP_ERROR = "semgrep integration is disabled for local deterministic audit config"


class ProjectConfig(BaseModel):
    name: str | None = None
    scope: str | None = None


class DetectorSelection(BaseModel):
    include: set[str] = Field(default_factory=set)
    exclude: set[str] = Field(default_factory=set)


class DetectorFocusConfig(BaseModel):
    entrypoints: DetectorSelection = Field(default_factory=DetectorSelection)
    consumers: DetectorSelection = Field(default_factory=DetectorSelection)
    workers: DetectorSelection = Field(default_factory=DetectorSelection)


class FocusConfig(BaseModel):
    files: set[str] = Field(default_factory=set)
    detectors: DetectorFocusConfig = Field(default_factory=DetectorFocusConfig)


class FlowConfig(BaseModel):
    max_candidates_total: int = 500
    max_candidates_per_entrypoint: int = 8


class DisabledIntegrationConfig(BaseModel):
    enabled: bool = False


class AuditConfig(BaseModel):
    ignore_dirs: set[str] = Field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    ignore_paths: set[Path] = Field(default_factory=set)
    max_file_bytes: int = 1_000_000
    snippet_lines: int = 1
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    focus: FocusConfig = Field(default_factory=FocusConfig)
    flow: FlowConfig = Field(default_factory=FlowConfig)
    llm: DisabledIntegrationConfig = Field(default_factory=DisabledIntegrationConfig)
    semgrep: DisabledIntegrationConfig = Field(default_factory=DisabledIntegrationConfig)


def default_config_path(repo: Path) -> Path:
    return Path(repo).resolve() / "invariant-os.yml"


def load_audit_config(
    repo: Path,
    config_path: Path | None,
    *,
    max_file_bytes: int | None = None,
) -> AuditConfig:
    repo_root = Path(repo).resolve()
    path = _resolved_config_path(repo_root, config_path)
    config = AuditConfig()

    if path is not None:
        payload = _load_yaml_mapping(path)
        _apply_payload(config, repo_root, payload)

    if max_file_bytes is not None:
        config.max_file_bytes = max_file_bytes

    _validate_config(config)
    return config


def apply_output_dir_ignore(config: AuditConfig, repo: Path, output_dir: Path) -> AuditConfig:
    repo_root = Path(repo).resolve()
    resolved_output_dir = Path(output_dir).expanduser().resolve()
    try:
        relative_output = resolved_output_dir.relative_to(repo_root)
    except ValueError:
        return config
    if relative_output.parts:
        config.ignore_paths.add(resolved_output_dir)
    return config


def _resolved_config_path(repo: Path, config_path: Path | None) -> Path | None:
    if config_path is None:
        default_path = default_config_path(repo)
        return default_path if default_path.is_file() else None

    raw = str(config_path).strip()
    if not raw or _is_url_like(raw):
        raise ValueError(_CONFIG_ERROR)
    resolved = Path(config_path).expanduser().resolve()
    if not resolved.is_file() or resolved.suffix.lower() not in {".yml", ".yaml"}:
        raise ValueError(_CONFIG_ERROR)
    return resolved


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(_CONFIG_ERROR) from error
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("audit config YAML root must be a mapping")
    return payload


def _apply_payload(config: AuditConfig, repo: Path, payload: dict[str, Any]) -> None:
    project = _mapping(payload.get("project"), "project")
    if project:
        config.project = ProjectConfig(
            name=_optional_string(project.get("name"), "project.name"),
            scope=_optional_string(project.get("scope"), "project.scope"),
        )

    ignore = _mapping(payload.get("ignore"), "ignore")
    if ignore:
        config.ignore_dirs.update(_string_set(ignore.get("dirs"), "ignore.dirs"))
        for value in _string_set(ignore.get("paths"), "ignore.paths"):
            relative = _validate_relative_path(value, "ignore.paths")
            config.ignore_paths.add((repo / relative).resolve())

    focus = _mapping(payload.get("focus"), "focus")
    if focus:
        config.focus.files.update(
            _validate_relative_path(value, "focus.files")
            for value in _string_set(focus.get("files"), "focus.files")
        )
        detectors = _mapping(focus.get("detectors"), "focus.detectors")
        if detectors:
            _apply_detector_selection(config.focus.detectors.entrypoints, detectors.get("entrypoints"), "entrypoints")
            _apply_detector_selection(config.focus.detectors.consumers, detectors.get("consumers"), "consumers")
            _apply_detector_selection(config.focus.detectors.workers, detectors.get("workers"), "workers")

    flow = _mapping(payload.get("flow"), "flow")
    if flow:
        config.flow = FlowConfig(
            max_candidates_total=_optional_int(
                flow.get("max_candidates_total"),
                "flow.max_candidates_total",
                config.flow.max_candidates_total,
            ),
            max_candidates_per_entrypoint=_optional_int(
                flow.get("max_candidates_per_entrypoint"),
                "flow.max_candidates_per_entrypoint",
                config.flow.max_candidates_per_entrypoint,
            ),
        )

    llm = _mapping(payload.get("llm"), "llm")
    if llm:
        config.llm = DisabledIntegrationConfig(
            enabled=_optional_bool(llm.get("enabled"), "llm.enabled", False)
        )

    semgrep = _mapping(payload.get("semgrep"), "semgrep")
    if semgrep:
        config.semgrep = DisabledIntegrationConfig(
            enabled=_optional_bool(semgrep.get("enabled"), "semgrep.enabled", False)
        )

    if "max_file_bytes" in payload:
        config.max_file_bytes = _optional_int(
            payload.get("max_file_bytes"),
            "max_file_bytes",
            config.max_file_bytes,
        )


def _apply_detector_selection(selection: DetectorSelection, value: object, field_name: str) -> None:
    mapping = _mapping(value, f"focus.detectors.{field_name}")
    if not mapping:
        return
    selection.include.update(_string_set(mapping.get("include"), f"focus.detectors.{field_name}.include"))
    selection.exclude.update(_string_set(mapping.get("exclude"), f"focus.detectors.{field_name}.exclude"))


def _validate_config(config: AuditConfig) -> None:
    if config.max_file_bytes < 0:
        raise ValueError("max_file_bytes must be non-negative")
    if config.flow.max_candidates_total < 0:
        raise ValueError("flow.max_candidates_total must be non-negative")
    if config.flow.max_candidates_per_entrypoint < 0:
        raise ValueError("flow.max_candidates_per_entrypoint must be non-negative")
    if config.llm.enabled:
        raise ValueError(_DISABLED_LLM_ERROR)
    if config.semgrep.enabled:
        raise ValueError(_DISABLED_SEMGREP_ERROR)
    _validate_detector_names(config)


def _validate_detector_names(config: AuditConfig) -> None:
    from invariant_os.analysis.detectors import known_detector_patterns

    known = known_detector_patterns()
    configured = {
        "entrypoints": config.focus.detectors.entrypoints,
        "consumers": config.focus.detectors.consumers,
        "workers": config.focus.detectors.workers,
    }
    for detector_type, selection in configured.items():
        unknown = (selection.include | selection.exclude) - known[detector_type]
        if unknown:
            values = ", ".join(sorted(unknown))
            raise ValueError(f"unknown detector pattern for {detector_type}: {values}")


def _mapping(value: object, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a mapping")
    return value


def _string_set(value: object, field_name: str) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        raise ValueError(f"{field_name} must be a string or list of strings")
    result: set[str] = set()
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field_name} must contain non-empty strings")
        result.add(item.strip())
    return result


def _optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value.strip() or None


def _optional_int(value: object, field_name: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    return value


def _optional_bool(value: object, field_name: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _validate_relative_path(value: str, field_name: str) -> str:
    normalized = value.strip().replace("\\", "/")
    if not normalized or _is_url_like(normalized):
        raise ValueError(f"{field_name} must contain local paths")
    if normalized.startswith("/"):
        raise ValueError(f"{field_name} must contain local relative paths")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    parts = [part for part in normalized.split("/") if part]
    if ".." in parts:
        raise ValueError(f"{field_name} must not escape the local repository")
    if value.endswith("/") and not normalized.endswith("/"):
        normalized = f"{normalized}/"
    return normalized


def _is_url_like(value: str) -> bool:
    return value.lower().startswith(("http://", "https://", "http:/", "https:/"))
