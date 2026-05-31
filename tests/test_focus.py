from invariant_os.core.focus import (
    FocusMode,
    focus_sort_key,
    get_focus_profile,
    score_boundary_focus,
    score_primitive_focus,
    summarize_focus_matches,
)
from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    PrimitiveCandidate,
    PrimitiveType,
)


def test_focus_profiles_expose_supported_modes_and_labels():
    assert FocusMode.ALL.value == "all"
    assert FocusMode.IMPORT_UPLOAD.value == "import-upload"
    assert FocusMode.WORKER_QUEUE.value == "worker-queue"
    assert FocusMode.TEMPLATE_WORKFLOW.value == "template-workflow"
    assert FocusMode.URL_INTERNAL_REQUEST.value == "url-internal-request"

    profile = get_focus_profile(FocusMode.IMPORT_UPLOAD)

    assert profile.mode == FocusMode.IMPORT_UPLOAD
    assert profile.label == "Import / Upload"
    assert BoundaryType.DATA_TO_FILE in profile.boundary_types
    assert PrimitiveType.FILE_WRITE in profile.primitive_types


def test_all_focus_scores_every_candidate_as_neutral_match():
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_URL,
        confidence=Confidence.LOW,
        reason="Candidate URL boundary.",
    )

    metadata = score_boundary_focus(boundary, FocusMode.ALL)

    assert metadata.focus_mode == "all"
    assert metadata.focus_match is True
    assert metadata.focus_score == 0
    assert metadata.focus_reasons == ["default all-focus lens"]


def test_import_upload_focus_scores_matching_boundary_and_primitive():
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate request data reaches a file operation.",
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
    )

    boundary_metadata = score_boundary_focus(boundary, FocusMode.IMPORT_UPLOAD)
    primitive_metadata = score_primitive_focus(primitive, FocusMode.IMPORT_UPLOAD)

    assert boundary_metadata.focus_match is True
    assert boundary_metadata.focus_score >= 50
    assert "boundary:data_to_file" in boundary_metadata.focus_reasons
    assert primitive_metadata.focus_match is True
    assert primitive_metadata.focus_score >= 50
    assert "primitive:file_write" in primitive_metadata.focus_reasons


def test_worker_queue_focus_does_not_match_unrelated_primitive():
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.URL_CONTROL,
        confidence=Confidence.MEDIUM,
    )

    metadata = score_primitive_focus(primitive, FocusMode.WORKER_QUEUE)

    assert metadata.focus_mode == "worker-queue"
    assert metadata.focus_match is False
    assert metadata.focus_score == 0
    assert metadata.focus_reasons == []


def test_focus_summary_counts_matches_by_category():
    boundary = score_boundary_focus(
        BoundaryCandidate(
            id="boundary_0001",
            type=BoundaryType.DATA_TO_FILE,
            confidence=Confidence.MEDIUM,
            reason="Candidate request data reaches a file operation.",
        ),
        FocusMode.IMPORT_UPLOAD,
    )
    primitive = score_primitive_focus(
        PrimitiveCandidate(
            id="primitive_0001",
            primitive=PrimitiveType.URL_CONTROL,
            confidence=Confidence.MEDIUM,
        ),
        FocusMode.IMPORT_UPLOAD,
    )

    summary = summarize_focus_matches(
        mode=FocusMode.IMPORT_UPLOAD,
        boundary_metadata=[boundary],
        primitive_metadata=[primitive],
        static_flow_metadata=[],
    )

    assert summary.mode == "import-upload"
    assert summary.label == "Import / Upload"
    assert summary.boundary_matches == 1
    assert summary.primitive_matches == 0
    assert summary.static_flow_matches == 0
    assert summary.total_matches == 1


def test_focus_sort_key_prioritizes_matches_then_score_then_existing_key():
    matched = {"focus_match": True, "focus_score": 75, "category": "primitive", "kind": "file_write", "candidate_id": "b"}
    unmatched = {"focus_match": False, "focus_score": 0, "category": "boundary", "kind": "data_to_url", "candidate_id": "a"}

    assert focus_sort_key(matched, ("primitive", "file_write", "b")) < focus_sort_key(
        unmatched,
        ("boundary", "data_to_url", "a"),
    )
