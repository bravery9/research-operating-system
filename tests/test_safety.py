import pytest

from invariant_os.core.config import AuditConfig
from invariant_os.core.constants import LANGUAGE_BY_EXTENSION
from invariant_os.core.safety import validate_local_repo_path


REQUIRED_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "coverage",
    "outputs",
}


def test_default_ignores_include_required_directories():
    assert REQUIRED_IGNORE_DIRS.issubset(AuditConfig().ignore_dirs)


@pytest.mark.parametrize(
    ("extension", "language"),
    [
        (".py", "python"),
        (".js", "javascript"),
        (".jsx", "javascript"),
        (".ts", "typescript"),
        (".tsx", "typescript"),
        (".java", "java"),
        (".go", "go"),
        (".rb", "ruby"),
        (".php", "php"),
        (".cs", "csharp"),
        (".yml", "yaml"),
        (".yaml", "yaml"),
        (".json", "json"),
        (".toml", "toml"),
        (".md", "markdown"),
    ],
)
def test_language_by_extension_includes_required_mappings(extension, language):
    assert LANGUAGE_BY_EXTENSION[extension] == language


def test_default_audit_config_limits_file_size_and_snippet_lines():
    config = AuditConfig()

    assert config.max_file_bytes == 1_000_000
    assert config.snippet_lines == 1


def test_audit_config_ignore_dirs_override_defaults():
    assert AuditConfig(ignore_dirs={"custom"}).ignore_dirs == {"custom"}


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "https://example.com",
        "ftp://example.com",
    ],
)
def test_validate_local_repo_rejects_urls(target):
    with pytest.raises(ValueError, match="local directory"):
        validate_local_repo_path(target)


def test_validate_local_repo_rejects_nonexistent_path(tmp_path):
    with pytest.raises(ValueError, match="local directory"):
        validate_local_repo_path(str(tmp_path / "missing"))


def test_validate_local_repo_rejects_file_path(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("content")

    with pytest.raises(ValueError, match="local directory"):
        validate_local_repo_path(str(target))


@pytest.mark.parametrize("target", ["", "   "])
def test_validate_local_repo_rejects_empty_or_blank_target(target):
    with pytest.raises(ValueError, match="local directory"):
        validate_local_repo_path(target)


def test_validate_local_repo_accepts_existing_directory(tmp_path):
    assert validate_local_repo_path(str(tmp_path)) == tmp_path.resolve()
