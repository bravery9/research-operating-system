from invariant_os.core.focus import (
    FocusMode,
    focus_sort_key,
    get_focus_profile,
    parse_focus_mode,
    score_boundary_focus,
    score_primitive_focus,
    score_static_flow_focus,
    summarize_focus_matches,
)
from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    PrimitiveCandidate,
    PrimitiveType,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
)


def test_parse_focus_mode_defaults_none_and_normalizes_strings():
    assert parse_focus_mode(None) == FocusMode.ALL
    assert parse_focus_mode(" Import-Upload ") == FocusMode.IMPORT_UPLOAD


def test_focus_profiles_expose_supported_modes_and_labels():
    assert FocusMode.ALL.value == "all"
    assert FocusMode.IMPORT_UPLOAD.value == "import-upload"
    assert FocusMode.WORKER_QUEUE.value == "worker-queue"
    assert FocusMode.TEMPLATE_WORKFLOW.value == "template-workflow"
    assert FocusMode.URL_INTERNAL_REQUEST.value == "url-internal-request"

    profile = get_focus_profile(FocusMode.IMPORT_UPLOAD)

    all_profile = get_focus_profile(FocusMode.ALL)
    assert all_profile.label == "All Evidence"
    assert all_profile.description == "Default lens over all deterministic audit evidence."

    assert profile.mode == FocusMode.IMPORT_UPLOAD
    assert profile.label == "Import / Upload"
    assert profile.description
    assert BoundaryType.DATA_TO_FILE in profile.boundary_types
    assert PrimitiveType.FILE_WRITE in profile.primitive_types
    assert {"archive", "zip", "path"}.issubset(set(profile.keywords))


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


def test_import_upload_reason_keyword_matches_boundary_without_profile_type():
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_URL,
        confidence=Confidence.MEDIUM,
        reason="Candidate request data reaches an archive extraction path.",
    )

    metadata = score_boundary_focus(boundary, FocusMode.IMPORT_UPLOAD)

    assert metadata.focus_match is True
    assert metadata.focus_score > 0
    assert "keyword:archive" in metadata.focus_reasons
    assert "keyword:path" in metadata.focus_reasons


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


def test_import_upload_evidence_keywords_match_primitive_without_profile_type():
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.URL_CONTROL,
        confidence=Confidence.MEDIUM,
        missing_evidence=["Need archive format validation evidence."],
        safe_next_steps=["Review zip parser handling and path normalization."],
    )

    metadata = score_primitive_focus(primitive, FocusMode.IMPORT_UPLOAD)

    assert metadata.focus_match is True
    assert metadata.focus_score > 0
    assert "keyword:archive" in metadata.focus_reasons
    assert "keyword:zip" in metadata.focus_reasons
    assert "keyword:path" in metadata.focus_reasons


def test_import_upload_keywords_do_not_match_profile_or_important_substrings():
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_URL,
        confidence=Confidence.MEDIUM,
        reason="Candidate profile update has important metadata.",
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.URL_CONTROL,
        confidence=Confidence.MEDIUM,
        missing_evidence=["Profile field evidence is important."],
        safe_next_steps=["Review profile metadata."],
    )
    static_flow = StaticFlowCandidate(
        id="static_flow_0001",
        source_entrypoint_id="entrypoint_0001",
        target_ref_id="consumer_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.MEDIUM,
        score=40,
        summary="Profile update marks important fields.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.ROUTE_TOKEN,
                term="profile_important",
                score=10,
            )
        ],
    )

    boundary_metadata = score_boundary_focus(boundary, FocusMode.IMPORT_UPLOAD)
    primitive_metadata = score_primitive_focus(primitive, FocusMode.IMPORT_UPLOAD)
    static_flow_metadata = score_static_flow_focus(static_flow, FocusMode.IMPORT_UPLOAD)

    assert boundary_metadata.focus_match is False
    assert boundary_metadata.focus_reasons == []
    assert primitive_metadata.focus_match is False
    assert primitive_metadata.focus_reasons == []
    assert static_flow_metadata.focus_match is False
    assert static_flow_metadata.focus_reasons == []


def test_import_upload_focus_does_not_match_consumer_static_flow_without_keywords():
    static_flow = StaticFlowCandidate(
        id="static_flow_0001",
        source_entrypoint_id="entrypoint_0001",
        target_ref_id="consumer_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.MEDIUM,
        score=40,
        summary="Request handler reaches downstream consumer.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.HANDLER_EXACT,
                term="processData",
                score=20,
            )
        ],
    )

    metadata = score_static_flow_focus(static_flow, FocusMode.IMPORT_UPLOAD)

    assert metadata.focus_match is False
    assert metadata.focus_score == 0
    assert metadata.focus_reasons == []


def test_import_upload_focus_scores_consumer_static_flow_with_keywords():
    static_flow = StaticFlowCandidate(
        id="static_flow_0001",
        source_entrypoint_id="entrypoint_0001",
        target_ref_id="consumer_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.MEDIUM,
        score=40,
        summary="Upload handler reaches import parser consumer.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.ROUTE_TOKEN,
                term="file",
                score=10,
            )
        ],
    )

    metadata = score_static_flow_focus(static_flow, FocusMode.IMPORT_UPLOAD)

    assert metadata.focus_match is True
    assert metadata.focus_score >= 50
    assert "static_flow_target:consumer" in metadata.focus_reasons
    assert "keyword:upload" in metadata.focus_reasons
    assert "keyword:import" in metadata.focus_reasons
    assert "keyword:file" in metadata.focus_reasons


def test_url_internal_request_focus_does_not_match_generic_request_parameter_static_flow():
    static_flow = StaticFlowCandidate(
        id="static_flow_0001",
        source_entrypoint_id="entrypoint_0001",
        target_ref_id="consumer_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.MEDIUM,
        score=40,
        summary="Request handler passes request_parameter to consumer.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.ROUTE_TOKEN,
                term="request_parameter",
                score=10,
            )
        ],
    )

    metadata = score_static_flow_focus(static_flow, FocusMode.URL_INTERNAL_REQUEST)

    assert metadata.focus_match is False
    assert metadata.focus_score == 0
    assert metadata.focus_reasons == []


def test_url_internal_request_focus_scores_url_http_internal_fetch_static_flow():
    static_flow = StaticFlowCandidate(
        id="static_flow_0001",
        source_entrypoint_id="entrypoint_0001",
        target_ref_id="consumer_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.MEDIUM,
        score=40,
        summary="URL handler triggers internal HTTP fetch consumer.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.ROUTE_TOKEN,
                term="url_fetch",
                score=10,
            )
        ],
    )

    metadata = score_static_flow_focus(static_flow, FocusMode.URL_INTERNAL_REQUEST)

    assert metadata.focus_match is True
    assert metadata.focus_score >= 50
    assert "static_flow_target:consumer" in metadata.focus_reasons
    assert "keyword:url" in metadata.focus_reasons
    assert "keyword:internal" in metadata.focus_reasons
    assert "keyword:http" in metadata.focus_reasons
    assert "keyword:fetch" in metadata.focus_reasons


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
    assert summary.description
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
