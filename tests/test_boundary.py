from pathlib import Path

from invariant_os.analysis.boundary import infer_boundaries
from invariant_os.analysis.detectors import detect_consumers, detect_entrypoints, detect_workers
from invariant_os.analysis.indexer import index_repository
from invariant_os.core.config import AuditConfig
from invariant_os.core.models import BoundaryType, Confidence

FIXTURES = Path(__file__).parent / "fixtures"
FORBIDDEN_BOUNDARY_TERMS = ("RCE", "exploitable")


def _pipeline(repo_root: Path):
    files = index_repository(repo_root, AuditConfig())
    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)
    boundaries = infer_boundaries(entrypoints, consumers, workers)
    return entrypoints, consumers, workers, boundaries


def _indexed_tmp_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def _boundary_types(boundaries):
    return {boundary.type for boundary in boundaries}


def _assert_boundary_metadata(boundaries):
    ids = [boundary.id for boundary in boundaries]
    assert ids == [f"boundary_{index:04d}" for index in range(1, len(boundaries) + 1)]
    assert len(ids) == len(set(ids))

    for boundary in boundaries:
        assert boundary.confidence in {Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH}
        assert boundary.reason
        assert boundary.evidence
        for forbidden in FORBIDDEN_BOUNDARY_TERMS:
            assert forbidden not in boundary.reason
        for evidence in boundary.evidence:
            assert evidence.file
            assert not evidence.file.startswith("/")
            assert evidence.line > 0
            assert evidence.pattern
            assert evidence.snippet or evidence.message


def test_express_app_infers_request_file_and_job_boundaries():
    _, _, _, boundaries = _pipeline(FIXTURES / "mini_express_app")

    assert BoundaryType.REQUEST_TO_WORKER in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_FILE in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_JOB in _boundary_types(boundaries)
    _assert_boundary_metadata(boundaries)


def test_fastapi_app_infers_file_and_url_boundaries():
    _, _, _, boundaries = _pipeline(FIXTURES / "mini_fastapi_app")

    assert BoundaryType.DATA_TO_FILE in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_URL in _boundary_types(boundaries)
    _assert_boundary_metadata(boundaries)


def test_template_app_infers_template_boundary():
    _, _, _, boundaries = _pipeline(FIXTURES / "mini_template_app")

    assert BoundaryType.DATA_TO_TEMPLATE in _boundary_types(boundaries)
    _assert_boundary_metadata(boundaries)


def test_tomcat_app_infers_database_and_directory_boundaries():
    _, _, _, boundaries = _pipeline(FIXTURES / "mini_tomcat_app")

    assert BoundaryType.DATA_TO_DATABASE in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_DIRECTORY in _boundary_types(boundaries)
    _assert_boundary_metadata(boundaries)


def test_parser_to_consumer_boundary_from_archive_parser_and_consumers():
    _, _, _, boundaries = _pipeline(FIXTURES / "mini_parser_to_consumer")

    assert BoundaryType.PARSER_TO_CONSUMER in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_FILE in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_TEMPLATE in _boundary_types(boundaries)
    assert BoundaryType.DATA_TO_CONFIG in _boundary_types(boundaries)
    _assert_boundary_metadata(boundaries)
