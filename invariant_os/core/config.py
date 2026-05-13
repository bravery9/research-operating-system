from pathlib import Path

from pydantic import BaseModel, Field

from invariant_os.core.constants import DEFAULT_IGNORE_DIRS


class AuditConfig(BaseModel):
    ignore_dirs: set[str] = Field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    ignore_paths: set[Path] = Field(default_factory=set)
    max_file_bytes: int = 1_000_000
    snippet_lines: int = 1
