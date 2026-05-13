from pathlib import Path


REMOTE_URL_PREFIXES = ("http://", "https://", "ftp://")


def validate_local_repo_path(target: str) -> Path:
    if not target.strip():
        raise ValueError("audit target must be an authorized local directory")

    if target.lower().startswith(REMOTE_URL_PREFIXES):
        raise ValueError("audit target must be an authorized local directory")

    path = Path(target).expanduser()
    if not path.exists() or not path.is_dir():
        raise ValueError("audit target must be an authorized local directory")

    return path.resolve()
