from pathlib import Path

from invariant_os.analysis.boundary import infer_boundaries
from invariant_os.analysis.detectors import detect_consumers, detect_entrypoints, detect_workers
from invariant_os.analysis.indexer import index_repository
from invariant_os.analysis.primitives import classify_primitives
from invariant_os.core.config import AuditConfig
from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Consumer,
    ConsumerType,
    Evidence,
    EvidenceType,
    PrimitiveType,
)

FIXTURES = Path(__file__).parent / "fixtures"
FORBIDDEN_PRIMITIVE_TERMS = (
    "payload",
    "confirmed exploitability",
    "confirmed exploitable",
    "exploit payload",
)


def _full_pipeline(repo_root: Path):
    files = index_repository(repo_root, AuditConfig())
    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)
    boundaries = infer_boundaries(entrypoints, consumers, workers)
    primitives = classify_primitives(boundaries, consumers, workers)
    return boundaries, consumers, workers, primitives


def _primitive_types(primitives):
    return {primitive.primitive for primitive in primitives}


def _indexed_tmp_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def _consumer(consumer_type: ConsumerType, snippet: str, *, line: int = 1) -> Consumer:
    evidence = Evidence(
        id=f"evidence_{consumer_type.value}_{line}",
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=line,
        pattern=consumer_type.value,
        snippet=snippet,
    )
    return Consumer(
        id=f"consumer_{consumer_type.value}_{line}",
        type=consumer_type,
        file="app.py",
        line=line,
        pattern=consumer_type.value,
        evidence=[evidence],
    )


def _file_boundary(snippet: str) -> BoundaryCandidate:
    return BoundaryCandidate(
        id="boundary_file",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="file operation uses data-influenced path",
        evidence=[
            Evidence(
                id="evidence_boundary_file",
                type=EvidenceType.BOUNDARY_RULE,
                file="app.py",
                line=1,
                pattern=BoundaryType.DATA_TO_FILE.value,
                snippet=snippet,
            )
        ],
    )


def _assert_primitive_metadata(primitives):
    ids = [primitive.id for primitive in primitives]
    assert ids == [f"primitive_{index:04d}" for index in range(1, len(primitives) + 1)]
    assert len(ids) == len(set(ids))

    for primitive in primitives:
        assert primitive.evidence
        assert primitive.missing_evidence
        assert primitive.safe_next_steps
        primitive_text = primitive.model_dump_json().lower()
        for forbidden in FORBIDDEN_PRIMITIVE_TERMS:
            assert forbidden not in primitive_text


def test_express_app_suggests_job_control_and_file_or_path_primitive():
    _, _, _, primitives = _full_pipeline(FIXTURES / "mini_express_app")

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.JOB_CONTROL in primitive_types
    assert primitive_types & {PrimitiveType.FILE_WRITE, PrimitiveType.PATH_CONTROL}
    _assert_primitive_metadata(primitives)


def test_fastapi_app_suggests_url_control():
    _, _, _, primitives = _full_pipeline(FIXTURES / "mini_fastapi_app")

    assert PrimitiveType.URL_CONTROL in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_template_app_suggests_template_control():
    _, _, _, primitives = _full_pipeline(FIXTURES / "mini_template_app")

    assert PrimitiveType.TEMPLATE_CONTROL in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_parser_to_consumer_fixture_suggests_parser_differential():
    boundaries, _, _, primitives = _full_pipeline(FIXTURES / "mini_parser_to_consumer")

    assert boundaries
    assert PrimitiveType.PARSER_DIFFERENTIAL in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_read_only_open_does_not_suggest_file_write(tmp_path):
    repo_root = _indexed_tmp_repo(
        tmp_path,
        {"app.py": "def load_user_file(path):\n    with open(path, 'r', encoding='utf-8') as handle:\n        return handle.read()\n"},
    )

    _, _, _, primitives = _full_pipeline(repo_root)

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.FILE_WRITE not in primitive_types
    assert primitive_types & {PrimitiveType.FILE_READ, PrimitiveType.PATH_CONTROL}
    _assert_primitive_metadata(primitives)


def test_default_open_does_not_suggest_file_write(tmp_path):
    repo_root = _indexed_tmp_repo(
        tmp_path,
        {"app.py": "def load_user_file(path):\n    with open(path, encoding='utf-8') as handle:\n        return handle.read()\n"},
    )

    _, _, _, primitives = _full_pipeline(repo_root)

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.FILE_WRITE not in primitive_types
    assert primitive_types & {PrimitiveType.FILE_READ, PrimitiveType.PATH_CONTROL}
    _assert_primitive_metadata(primitives)


def test_explicit_write_open_suggests_file_write(tmp_path):
    repo_root = _indexed_tmp_repo(
        tmp_path,
        {"app.py": "def save_user_file(path, content):\n    with open(path, 'w', encoding='utf-8') as handle:\n        handle.write(content)\n"},
    )

    _, _, _, primitives = _full_pipeline(repo_root)

    assert PrimitiveType.FILE_WRITE in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_nested_path_write_open_suggests_file_write():
    snippet = "open(os.path.join(base_dir, name), 'w', encoding='utf-8')"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    assert PrimitiveType.FILE_WRITE in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_default_open_suggests_file_read_without_file_write():
    snippet = "open(path)"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.FILE_READ in primitive_types
    assert PrimitiveType.FILE_WRITE not in primitive_types
    _assert_primitive_metadata(primitives)


def test_explicit_read_open_suggests_file_read_without_file_write():
    snippet = "open(path, 'r')"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.FILE_READ in primitive_types
    assert PrimitiveType.FILE_WRITE not in primitive_types
    _assert_primitive_metadata(primitives)


def test_method_open_write_mode_suggests_file_write():
    snippet = "output_path.open('w', encoding='utf-8')"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    assert PrimitiveType.FILE_WRITE in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_method_open_read_mode_suggests_file_read_without_file_write():
    snippet = "output_path.open('r')"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.FILE_READ in primitive_types
    assert PrimitiveType.FILE_WRITE not in primitive_types
    _assert_primitive_metadata(primitives)


def test_method_open_default_suggests_file_read_without_file_write():
    snippet = "output_path.open()"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.FILE_READ in primitive_types
    assert PrimitiveType.FILE_WRITE not in primitive_types
    _assert_primitive_metadata(primitives)


def test_method_open_keyword_append_mode_suggests_file_write():
    snippet = "output_path.open(mode='a')"

    primitives = classify_primitives(
        [_file_boundary(snippet)],
        [_consumer(ConsumerType.FILE_OPERATION, snippet)],
        [],
    )

    assert PrimitiveType.FILE_WRITE in _primitive_types(primitives)
    _assert_primitive_metadata(primitives)


def test_deserialization_consumer_suggests_type_control():
    primitives = classify_primitives(
        [],
        [_consumer(ConsumerType.DESERIALIZATION, "value = pickle.loads(blob)")],
        [],
    )

    assert PrimitiveType.TYPE_CONTROL in _primitive_types(primitives)
    type_control = next(primitive for primitive in primitives if primitive.primitive == PrimitiveType.TYPE_CONTROL)
    assert type_control.confidence in {Confidence.LOW, Confidence.MEDIUM}
    _assert_primitive_metadata(primitives)


def test_clear_cache_auth_and_tenant_terms_suggest_conservative_primitives():
    primitives = classify_primitives(
        [],
        [
            _consumer(ConsumerType.CONFIG_OPERATION, "settings = yaml.safe_load(cache_session_config)"),
            _consumer(ConsumerType.CONFIG_OPERATION, "settings = yaml.safe_load(auth_permission_admin_config)", line=2),
            _consumer(ConsumerType.CONFIG_OPERATION, "settings = yaml.safe_load(tenant_workspace_org_config)", line=3),
        ],
        [],
    )

    primitive_types = _primitive_types(primitives)
    assert PrimitiveType.CACHE_POISONING in primitive_types
    assert PrimitiveType.AUTH_CONTEXT_CONFUSION in primitive_types
    assert PrimitiveType.TENANT_CONFUSION in primitive_types
    assert all(primitive.confidence == Confidence.LOW for primitive in primitives)
    _assert_primitive_metadata(primitives)
