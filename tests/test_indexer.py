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


def test_indexer_detects_enterprise_java_repository_files(tmp_path):
    files = {
        "WEB-INF/web.xml": "<web-app />\n",
        "conf/adap/rest-api.xml": "<ADAPRestApiMapping URL_PATH=\"/api\" />\n",
        "conf/wrapper.conf": "wrapper.java.command=java\n",
        "bin/run.bat": "echo run\n",
        "db/schema.sql": "select 1;\n",
        "views/index.jsp": "<% out.println(\"hi\"); %>\n",
        "lib/Product.src/com/example/App.java": "class App {}\n",
    }
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    records = index_repository(tmp_path, AuditConfig())

    languages_by_path = {record.path: record.language for record in records}
    assert languages_by_path == {
        "WEB-INF/web.xml": "xml",
        "bin/run.bat": "batch",
        "conf/adap/rest-api.xml": "xml",
        "conf/wrapper.conf": "config",
        "db/schema.sql": "sql",
        "lib/Product.src/com/example/App.java": "java",
        "views/index.jsp": "jsp",
    }


def test_indexer_skips_enterprise_package_and_binary_noise(tmp_path):
    useful_files = {
        "conf/security-common.xml": "<security><url path=\"/api\" /></security>\n",
        "src/com/example/App.java": "class App {}\n",
        "webapps/adap/static/app.js": "const endpoint = '/api/report';\n",
    }
    noisy_text_files = {
        "logs/server.log": "INFO booted\n",
        "logs/wrapper.out": "stdout\n",
        "logs/wrapper.err": "stderr\n",
    }
    noisy_binary_files = {
        "lib/product.jar": b"PK\x03\x04jar bytes",
        "WEB-INF/classes/App.class": b"\xca\xfe\xba\xbeclass bytes",
        "archives/app.war": b"PK\x03\x04war bytes",
        "data/cache.db": b"SQLite format 3\x00cache bytes",
        "images/logo.png": b"\x89PNG\r\n\x1a\nimage bytes",
        "tmp/null-byte.txt": b"text before\x00text after",
    }
    for relative_path, content in useful_files.items() | noisy_text_files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for relative_path, content in noisy_binary_files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    records = index_repository(tmp_path, AuditConfig())

    assert [record.path for record in records] == sorted(useful_files)


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


def test_indexer_focus_files_restrict_indexed_records(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf" / "server.xml").write_text("<Server />\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "readme.md").write_text("docs\n", encoding="utf-8")

    config = AuditConfig()
    config.focus.files = {"src/"}

    records = index_repository(tmp_path, config)

    assert [record.path for record in records] == ["src/app.py"]


def test_indexer_ignore_paths_win_over_focus_files(tmp_path):
    (tmp_path / "src" / "generated").mkdir(parents=True)
    (tmp_path / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "src" / "generated" / "app.py").write_text("print('generated')\n", encoding="utf-8")

    config = AuditConfig(ignore_paths={(tmp_path / "src" / "generated").resolve()})
    config.focus.files = {"src/"}

    records = index_repository(tmp_path, config)

    assert [record.path for record in records] == ["src/app.py"]
