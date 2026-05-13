import hashlib
import os
from pathlib import Path

from invariant_os.core.config import AuditConfig
from invariant_os.core.constants import LANGUAGE_BY_EXTENSION, NOISY_FILE_SUFFIXES
from invariant_os.core.models import FileRecord


def index_repository(repo_root: Path, config: AuditConfig) -> list[FileRecord]:
    records: list[FileRecord] = []
    ignored_paths = {path.resolve() for path in config.ignore_paths}

    for root, dirnames, filenames in os.walk(repo_root):
        current_root = Path(root)
        if _is_ignored_path(current_root.resolve(), ignored_paths):
            dirnames[:] = []
            continue

        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in config.ignore_dirs
            and not _is_ignored_path((current_root / dirname).resolve(), ignored_paths)
        ]

        for filename in filenames:
            path = current_root / filename
            if path.is_symlink() or _is_ignored_path(path.resolve(), ignored_paths):
                continue
            if path.suffix.lower() in NOISY_FILE_SUFFIXES:
                continue

            size_bytes = path.stat().st_size
            if size_bytes > config.max_file_bytes:
                continue

            content = path.read_bytes()
            if _is_binary_content(content):
                continue

            relative_path = path.relative_to(repo_root).as_posix()
            records.append(
                FileRecord(
                    path=relative_path,
                    language=_language_for_path(path),
                    size_bytes=size_bytes,
                    sha256=hashlib.sha256(content).hexdigest(),
                )
            )

    return sorted(records, key=lambda record: record.path)


def _is_ignored_path(path: Path, ignored_paths: set[Path]) -> bool:
    return any(path == ignored_path or path.is_relative_to(ignored_path) for ignored_path in ignored_paths)


def _language_for_path(path: Path) -> str:
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "unknown")


def _is_binary_content(content: bytes) -> bool:
    binary_signatures = (
        b"\x00",
        b"PK\x03\x04",
        b"\xca\xfe\xba\xbe",
        b"\x89PNG\r\n\x1a\n",
        b"%PDF",
        b"GIF87a",
        b"GIF89a",
        b"\xff\xd8\xff",
        b"SQLite format 3\x00",
    )
    return any(signature in content[:64] for signature in binary_signatures)
