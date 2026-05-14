"""Constrained local git-diff collection."""

from pathlib import Path
import subprocess

_REMOTE_PREFIXES = ("http://", "https://", "ftp://", "ssh://", "git://")
_FORBIDDEN_REF_CHARS = set("\n\r\t;&|`$<>")
_ERROR_MESSAGE = "git diff input must reference local refs in a local repository"


def collect_git_diff(repo_path: Path, base_ref: str, head_ref: str) -> str:
    repo = Path(repo_path).expanduser().resolve()
    if not repo.is_dir():
        raise ValueError(_ERROR_MESSAGE)
    _validate_ref(base_ref)
    _validate_ref(head_ref)

    command = [
        "git",
        "-C",
        str(repo),
        "diff",
        "--no-ext-diff",
        "--no-color",
        "--no-textconv",
        "--unified=3",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base_ref,
        head_ref,
        "--",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=None,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(_ERROR_MESSAGE) from error
    if result.returncode != 0:
        raise ValueError(_ERROR_MESSAGE)
    return result.stdout


def _validate_ref(value: str) -> None:
    ref = value.strip()
    if not ref or ref.lower().startswith(_REMOTE_PREFIXES) or any(
        char in _FORBIDDEN_REF_CHARS for char in ref
    ):
        raise ValueError(_ERROR_MESSAGE)
