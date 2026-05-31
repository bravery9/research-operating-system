from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any

from invariant_os.core.models import (
    BoundaryCandidate,
    BoundaryType,
    PrimitiveCandidate,
    PrimitiveType,
    StaticFlowCandidate,
    StaticFlowTargetType,
)


class FocusMode(str, Enum):
    ALL = "all"
    IMPORT_UPLOAD = "import-upload"
    WORKER_QUEUE = "worker-queue"
    TEMPLATE_WORKFLOW = "template-workflow"
    URL_INTERNAL_REQUEST = "url-internal-request"


@dataclass(frozen=True)
class FocusProfile:
    mode: FocusMode
    label: str
    description: str
    boundary_types: tuple[BoundaryType, ...]
    primitive_types: tuple[PrimitiveType, ...]
    static_flow_target_types: tuple[StaticFlowTargetType, ...]
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class FocusCandidateMetadata:
    focus_mode: str
    focus_match: bool
    focus_score: int
    focus_reasons: list[str]


@dataclass(frozen=True)
class FocusSummary:
    mode: str
    label: str
    description: str
    boundary_matches: int
    primitive_matches: int
    static_flow_matches: int
    total_matches: int


_FOCUS_PROFILES: dict[FocusMode, FocusProfile] = {
    FocusMode.ALL: FocusProfile(
        mode=FocusMode.ALL,
        label="All Evidence",
        description="Default lens over all deterministic audit evidence.",
        boundary_types=(),
        primitive_types=(),
        static_flow_target_types=(),
        keywords=(),
    ),
    FocusMode.IMPORT_UPLOAD: FocusProfile(
        mode=FocusMode.IMPORT_UPLOAD,
        label="Import / Upload",
        description="Highlights import, upload, parser, file, and directory evidence.",
        boundary_types=(
            BoundaryType.DATA_TO_FILE,
            BoundaryType.DATA_TO_CONFIG,
            BoundaryType.PARSER_TO_CONSUMER,
            BoundaryType.DATA_TO_DIRECTORY,
        ),
        primitive_types=(
            PrimitiveType.PATH_CONTROL,
            PrimitiveType.FILE_WRITE,
            PrimitiveType.FILE_READ,
            PrimitiveType.CONFIG_CONTROL,
            PrimitiveType.PARSER_DIFFERENTIAL,
            PrimitiveType.DIRECTORY_QUERY_CONTROL,
        ),
        static_flow_target_types=(StaticFlowTargetType.CONSUMER,),
        keywords=("import", "upload", "parser", "file", "config", "directory", "archive", "zip", "path"),
    ),
    FocusMode.WORKER_QUEUE: FocusProfile(
        mode=FocusMode.WORKER_QUEUE,
        label="Worker / Queue",
        description="Highlights worker, queue, job, task, and asynchronous handoff evidence.",
        boundary_types=(
            BoundaryType.REQUEST_TO_WORKER,
            BoundaryType.DATA_TO_JOB,
            BoundaryType.LOW_PRIV_TO_PRIVILEGED_CONSUMER,
        ),
        primitive_types=(
            PrimitiveType.JOB_CONTROL,
            PrimitiveType.TYPE_CONTROL,
        ),
        static_flow_target_types=(StaticFlowTargetType.WORKER,),
        keywords=("worker", "queue", "job", "task", "async"),
    ),
    FocusMode.TEMPLATE_WORKFLOW: FocusProfile(
        mode=FocusMode.TEMPLATE_WORKFLOW,
        label="Template / Workflow",
        description="Highlights template, workflow, render, parser, and config evidence.",
        boundary_types=(
            BoundaryType.DATA_TO_TEMPLATE,
            BoundaryType.DATA_TO_CONFIG,
            BoundaryType.PARSER_TO_CONSUMER,
        ),
        primitive_types=(
            PrimitiveType.TEMPLATE_CONTROL,
            PrimitiveType.CONFIG_CONTROL,
            PrimitiveType.PARSER_DIFFERENTIAL,
            PrimitiveType.TYPE_CONTROL,
        ),
        static_flow_target_types=(StaticFlowTargetType.CONSUMER,),
        keywords=("template", "workflow", "render", "parser", "config"),
    ),
    FocusMode.URL_INTERNAL_REQUEST: FocusProfile(
        mode=FocusMode.URL_INTERNAL_REQUEST,
        label="URL / Internal Request",
        description="Highlights URL, internal request, HTTP, redirect, and callback evidence.",
        boundary_types=(
            BoundaryType.DATA_TO_URL,
            BoundaryType.EXTERNAL_TO_INTERNAL,
        ),
        primitive_types=(
            PrimitiveType.URL_CONTROL,
            PrimitiveType.INTERNAL_REQUEST_TRIGGER,
        ),
        static_flow_target_types=(StaticFlowTargetType.CONSUMER,),
        keywords=("url", "internal", "http", "redirect", "callback", "fetch", "webhook", "network", "outbound"),
    ),
}


def parse_focus_mode(value: str | FocusMode | None) -> FocusMode:
    if value is None:
        return FocusMode.ALL
    if isinstance(value, FocusMode):
        return value
    normalized_value = value.strip().lower()
    try:
        return FocusMode(normalized_value)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in FocusMode)
        raise ValueError(f"Invalid focus.mode {value!r}; allowed values: {allowed}") from exc


def get_focus_profile(mode: str | FocusMode | None) -> FocusProfile:
    return _FOCUS_PROFILES[parse_focus_mode(mode)]


def _all_focus_metadata(mode: FocusMode) -> FocusCandidateMetadata:
    return FocusCandidateMetadata(
        focus_mode=mode.value,
        focus_match=True,
        focus_score=0,
        focus_reasons=["default all-focus lens"],
    )


def _keyword_tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _matched_keywords(text: str, keywords: tuple[str, ...]) -> list[str]:
    tokens = _keyword_tokens(text)
    return [keyword for keyword in keywords if keyword.lower() in tokens]


def score_boundary_focus(candidate: BoundaryCandidate, mode: str | FocusMode | None) -> FocusCandidateMetadata:
    focus_mode = parse_focus_mode(mode)
    if focus_mode is FocusMode.ALL:
        return _all_focus_metadata(focus_mode)

    profile = get_focus_profile(focus_mode)
    score = 0
    reasons: list[str] = []

    if candidate.type in profile.boundary_types:
        score += 50
        reasons.append(f"boundary:{candidate.type.value}")

    for keyword in _matched_keywords(candidate.reason, profile.keywords):
        score += 10
        reasons.append(f"keyword:{keyword}")

    return FocusCandidateMetadata(
        focus_mode=focus_mode.value,
        focus_match=score > 0,
        focus_score=score,
        focus_reasons=reasons,
    )


def score_primitive_focus(candidate: PrimitiveCandidate, mode: str | FocusMode | None) -> FocusCandidateMetadata:
    focus_mode = parse_focus_mode(mode)
    if focus_mode is FocusMode.ALL:
        return _all_focus_metadata(focus_mode)

    profile = get_focus_profile(focus_mode)
    score = 0
    reasons: list[str] = []

    if candidate.primitive in profile.primitive_types:
        score += 50
        reasons.append(f"primitive:{candidate.primitive.value}")

    keyword_text = " ".join((*candidate.missing_evidence, *candidate.safe_next_steps))
    for keyword in _matched_keywords(keyword_text, profile.keywords):
        score += 10
        reasons.append(f"keyword:{keyword}")

    return FocusCandidateMetadata(
        focus_mode=focus_mode.value,
        focus_match=score > 0,
        focus_score=score,
        focus_reasons=reasons,
    )


def _static_flow_keyword_text(candidate: StaticFlowCandidate) -> str:
    signal_terms = " ".join(signal.term for signal in candidate.signals)
    signal_types = " ".join(signal.type.value for signal in candidate.signals)
    return " ".join(
        (
            candidate.id,
            candidate.source_entrypoint_id,
            candidate.target_ref_id,
            candidate.summary,
            signal_terms,
            signal_types,
        )
    )


def score_static_flow_focus(candidate: StaticFlowCandidate, mode: str | FocusMode | None) -> FocusCandidateMetadata:
    focus_mode = parse_focus_mode(mode)
    if focus_mode is FocusMode.ALL:
        return _all_focus_metadata(focus_mode)

    profile = get_focus_profile(focus_mode)
    score = 0
    reasons: list[str] = []

    target_type_matches = candidate.target_type in profile.static_flow_target_types
    if target_type_matches:
        score += 50
        reasons.append(f"static_flow_target:{candidate.target_type.value}")

    keyword_match_count = 0
    keyword_text = _static_flow_keyword_text(candidate)
    for keyword in _matched_keywords(keyword_text, profile.keywords):
        keyword_match_count += 1
        score += 10
        reasons.append(f"keyword:{keyword}")

    if focus_mode is not FocusMode.WORKER_QUEUE and target_type_matches and keyword_match_count == 0:
        score = 0
        reasons = []

    return FocusCandidateMetadata(
        focus_mode=focus_mode.value,
        focus_match=score > 0,
        focus_score=score,
        focus_reasons=reasons,
    )


def summarize_focus_matches(
    *,
    mode: str | FocusMode | None,
    boundary_metadata: list[FocusCandidateMetadata],
    primitive_metadata: list[FocusCandidateMetadata],
    static_flow_metadata: list[FocusCandidateMetadata],
) -> FocusSummary:
    focus_mode = parse_focus_mode(mode)
    profile = get_focus_profile(focus_mode)
    boundary_matches = sum(1 for metadata in boundary_metadata if metadata.focus_match)
    primitive_matches = sum(1 for metadata in primitive_metadata if metadata.focus_match)
    static_flow_matches = sum(1 for metadata in static_flow_metadata if metadata.focus_match)

    return FocusSummary(
        mode=focus_mode.value,
        label=profile.label,
        description=profile.description,
        boundary_matches=boundary_matches,
        primitive_matches=primitive_matches,
        static_flow_matches=static_flow_matches,
        total_matches=boundary_matches + primitive_matches + static_flow_matches,
    )


def focus_sort_key(metadata: dict[str, Any], existing_key: tuple[Any, ...]) -> tuple[Any, ...]:
    focus_match = bool(metadata.get("focus_match", False))
    focus_score = int(metadata.get("focus_score", 0))
    return (0 if focus_match else 1, -focus_score, *existing_key)
