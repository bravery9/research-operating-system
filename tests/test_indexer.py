import hashlib

import pytest

from invariant_os.analysis.indexer import index_repository
from invariant_os.core.config import AuditConfig


def test_indexer_detects_languages_and_ignores_noise(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "route.ts").write_text("export const x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("ignored\n")

    records = index_repository(tmp_path, AuditConfig())

    assert [record.path for record in records] == ["app.py", "src/route.ts"]
    assert [record.language for record in records] == ["python", "typescript"]


def test_indexer_skips_large_files(tmp_path):
    (tmp_path / "small.py").write_text("x = 1\n")
    (tmp_path / "large.py").write_text("x" * 20)

    records = index_repository(tmp_path, AuditConfig(max_file_bytes=10))

    assert [record.path for record in records] == ["small.py"]


def test_indexer_skips_symlinked_files(tmp_path):
    outside_file = tmp_path.parent / "outside.py"
    outside_file.write_text("secret = True\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "normal.py").write_text("print('safe')\n")
    symlink = repo / "linked.py"
    try:
        symlink.symlink_to(outside_file)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    records = index_repository(repo, AuditConfig())

    assert [record.path for record in records] == ["normal.py"]


def test_indexer_returns_deterministic_paths_and_stable_hashes(tmp_path):
    (tmp_path / "z.unknownext").write_bytes(b"z\n")
    (tmp_path / "a.py").write_bytes(b"print('a')\n")

    records = index_repository(tmp_path, AuditConfig())

    assert [record.path for record in records] == ["a.py", "z.unknownext"]
    assert records[0].sha256 == hashlib.sha256(b"print('a')\n").hexdigest()
    assert len(records[0].sha256) == 64
    assert records[1].language == "unknown"
