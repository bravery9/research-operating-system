from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
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
    boundary_types: tuple[BoundaryType, ...]
    primitive_types: tuple[PrimitiveType, ...]


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
    boundary_matches: int
    primitive_matches: int
    static_flow_matches: int
    total_matches: int


_FOCUS_PROFILES: dict[FocusMode, FocusProfile] = {
    FocusMode.ALL: FocusProfile(
        mode=FocusMode.ALL,
        label="All",
        boundary_types=(),
        primitive_types=(),
    ),
    FocusMode.IMPORT_UPLOAD: FocusProfile(
        mode=FocusMode.IMPORT_UPLOAD,
        label="Import / Upload",
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
    ),
    FocusMode.WORKER_QUEUE: FocusProfile(
        mode=FocusMode.WORKER_QUEUE,
        label="Worker / Queue",
        boundary_types=(
            BoundaryType.REQUEST_TO_WORKER,
            BoundaryType.DATA_TO_JOB,
            BoundaryType.LOW_PRIV_TO_PRIVILEGED_CONSUMER,
        ),
        primitive_types=(
            PrimitiveType.JOB_CONTROL,
            PrimitiveType.TYPE_CONTROL,
        ),
    ),
    FocusMode.TEMPLATE_WORKFLOW: FocusProfile(
        mode=FocusMode.TEMPLATE_WORKFLOW,
        label="Template / Workflow",
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
    ),
    FocusMode.URL_INTERNAL_REQUEST: FocusProfile(
        mode=FocusMode.URL_INTERNAL_REQUEST,
        label="URL / Internal Request",
        boundary_types=(
            BoundaryType.DATA_TO_URL,
            BoundaryType.EXTERNAL_TO_INTERNAL,
        ),
        primitive_types=(
            PrimitiveType.URL_CONTROL,
            PrimitiveType.INTERNAL_REQUEST_TRIGGER,
        ),
    ),
}


def parse_focus_mode(value: str | FocusMode) -> FocusMode:
    if isinstance(value, FocusMode):
        return value
    try:
        return FocusMode(value)
    except ValueError as exc:
        allowed = ", ".join(mode.value for mode in FocusMode)
        raise ValueError(f"Invalid focus.mode {value!r}; allowed values: {allowed}") from exc


def get_focus_profile(mode: str | FocusMode) -> FocusProfile:
    return _FOCUS_PROFILES[parse_focus_mode(mode)]


def _all_focus_metadata(mode: FocusMode) -> FocusCandidateMetadata:
    return FocusCandidateMetadata(
        focus_mode=mode.value,
        focus_match=True,
        focus_score=0,
        focus_reasons=["default all-focus lens"],
    )


def score_boundary_focus(candidate: BoundaryCandidate, mode: str | FocusMode) -> FocusCandidateMetadata:
    focus_mode = parse_focus_mode(mode)
    if focus_mode is FocusMode.ALL:
        return _all_focus_metadata(focus_mode)

    profile = get_focus_profile(focus_mode)
    if candidate.type in profile.boundary_types:
        return FocusCandidateMetadata(
            focus_mode=focus_mode.value,
            focus_match=True,
            focus_score=50,
            focus_reasons=[f"boundary:{candidate.type.value}"],
        )

    return FocusCandidateMetadata(
        focus_mode=focus_mode.value,
        focus_match=False,
        focus_score=0,
        focus_reasons=[],
    )


def score_primitive_focus(candidate: PrimitiveCandidate, mode: str | FocusMode) -> FocusCandidateMetadata:
    focus_mode = parse_focus_mode(mode)
    if focus_mode is FocusMode.ALL:
        return _all_focus_metadata(focus_mode)

    profile = get_focus_profile(focus_mode)
    if candidate.primitive in profile.primitive_types:
        return FocusCandidateMetadata(
            focus_mode=focus_mode.value,
            focus_match=True,
            focus_score=50,
            focus_reasons=[f"primitive:{candidate.primitive.value}"],
        )

    return FocusCandidateMetadata(
        focus_mode=focus_mode.value,
        focus_match=False,
        focus_score=0,
        focus_reasons=[],
    )


def score_static_flow_focus(candidate: StaticFlowCandidate, mode: str | FocusMode) -> FocusCandidateMetadata:
    focus_mode = parse_focus_mode(mode)
    if focus_mode is FocusMode.ALL:
        return _all_focus_metadata(focus_mode)

    if focus_mode is FocusMode.WORKER_QUEUE and candidate.target_type is StaticFlowTargetType.WORKER:
        return FocusCandidateMetadata(
            focus_mode=focus_mode.value,
            focus_match=True,
            focus_score=50,
            focus_reasons=["static_flow:worker"],
        )

    return FocusCandidateMetadata(
        focus_mode=focus_mode.value,
        focus_match=False,
        focus_score=0,
        focus_reasons=[],
    )


def summarize_focus_matches(
    *,
    mode: str | FocusMode,
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
        boundary_matches=boundary_matches,
        primitive_matches=primitive_matches,
        static_flow_matches=static_flow_matches,
        total_matches=boundary_matches + primitive_matches + static_flow_matches,
    )


def focus_sort_key(metadata: dict[str, Any], existing_key: tuple[Any, ...]) -> tuple[Any, ...]:
    focus_match = bool(metadata.get("focus_match", False))
    focus_score = int(metadata.get("focus_score", 0))
    return (0 if focus_match else 1, -focus_score, *existing_key)
