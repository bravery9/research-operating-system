from pathlib import Path

from invariant_os.core.models import Evidence, EvidenceType


def make_evidence_id(index: int) -> str:
    return f"ev_{index:04d}"


def build_pattern_evidence(
    *,
    evidence_id: str,
    repo_root: Path,
    file_path: Path,
    line: int,
    pattern: str,
    snippet: str,
    message: str | None = None,
) -> Evidence:
    root = Path(repo_root)
    path = Path(file_path)

    try:
        relative_file = path.relative_to(root)
    except ValueError:
        relative_file = path

    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file=relative_file.as_posix(),
        line=line,
        pattern=pattern,
        snippet=snippet.strip(),
        message=message,
    )
