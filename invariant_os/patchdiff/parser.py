"""Deterministic unified-diff parsing for local patch review."""

import re

from invariant_os.core.models import PatchChangedFile, PatchChangeType, PatchHunk

_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?: (?P<context>.*))?$"
)


def parse_unified_diff(diff_text: str) -> list[PatchChangedFile]:
    records: list[_FileRecord] = []
    current: _FileRecord | None = None
    current_hunk: PatchHunk | None = None
    old_line = 0
    new_line = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            current = _FileRecord(index=len(records) + 1)
            records.append(current)
            parts = raw_line.split()
            if len(parts) >= 4:
                current.old_path = _normalize_path(parts[2])
                current.new_path = _normalize_path(parts[3])
            current_hunk = None
            continue
        if current is None:
            continue
        if raw_line.startswith("new file mode"):
            current.change_type_hint = PatchChangeType.ADDED
            continue
        if raw_line.startswith("deleted file mode"):
            current.change_type_hint = PatchChangeType.DELETED
            continue
        if raw_line.startswith("rename from "):
            current.old_path = _normalize_path(raw_line.removeprefix("rename from "))
            current.change_type_hint = PatchChangeType.RENAMED
            continue
        if raw_line.startswith("rename to "):
            current.new_path = _normalize_path(raw_line.removeprefix("rename to "))
            current.change_type_hint = PatchChangeType.RENAMED
            continue
        if raw_line.startswith("--- "):
            current.old_path = _normalize_path(raw_line.removeprefix("--- ").split("\t", 1)[0])
            continue
        if raw_line.startswith("+++ "):
            current.new_path = _normalize_path(raw_line.removeprefix("+++ ").split("\t", 1)[0])
            continue

        match = _HUNK_RE.match(raw_line)
        if match:
            old_start = int(match.group("old_start"))
            old_count = int(match.group("old_count") or "1")
            new_start = int(match.group("new_start"))
            new_count = int(match.group("new_count") or "1")
            current_hunk = PatchHunk(
                id=f"patch_hunk_{current.index:04d}_{len(current.hunks) + 1:04d}",
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                context=match.group("context"),
            )
            current.hunks.append(current_hunk)
            old_line = old_start
            new_line = new_start
            continue

        if current_hunk is None:
            continue
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue
        if raw_line.startswith("+"):
            current_hunk.added_lines.append(new_line)
            new_line += 1
        elif raw_line.startswith("-"):
            current_hunk.removed_lines.append(old_line)
            old_line += 1
        elif raw_line.startswith(" "):
            old_line += 1
            new_line += 1
        elif raw_line == r"\ No newline at end of file":
            continue

    return [_to_changed_file(record) for record in records]


class _FileRecord:
    def __init__(self, index: int) -> None:
        self.index = index
        self.old_path: str | None = None
        self.new_path: str | None = None
        self.change_type_hint: PatchChangeType | None = None
        self.hunks: list[PatchHunk] = []


def _to_changed_file(record: _FileRecord) -> PatchChangedFile:
    return PatchChangedFile(
        id=f"patch_file_{record.index:04d}",
        old_path=record.old_path,
        new_path=record.new_path,
        change_type=_change_type(record),
        hunks=record.hunks,
    )


def _change_type(record: _FileRecord) -> PatchChangeType:
    if record.change_type_hint is not None:
        return record.change_type_hint
    if record.old_path is None:
        return PatchChangeType.ADDED
    if record.new_path is None:
        return PatchChangeType.DELETED
    if record.old_path != record.new_path:
        return PatchChangeType.RENAMED
    return PatchChangeType.MODIFIED


def _normalize_path(value: str) -> str | None:
    path = value.strip().replace("\\", "/")
    if path == "/dev/null":
        return None
    if path.startswith(("a/", "b/")):
        path = path[2:]
    while path.startswith("./"):
        path = path[2:]
    parts = [part for part in path.split("/") if part]
    if path.startswith("/") or ".." in parts:
        raise ValueError("patch contains non-local file paths")
    return "/".join(parts)
