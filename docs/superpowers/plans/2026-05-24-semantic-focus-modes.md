# Semantic Focus Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic `invariant-os audit --focus` lenses that prioritize existing audit evidence for import/upload, worker/queue, template/workflow, and URL/internal-request research.

**Architecture:** Implement focus modes as a small core layer that scores existing candidates after the normal audit pipeline runs. Store selected focus metadata on `AuditResult`, expose it through JSON, Markdown, HTML, and review-queue artifacts, and keep default `all` behavior stable. Do not add new scanners, Semgrep execution, live LLM providers, target execution, exploit automation, auto-fixes, or vulnerability confirmation.

**Tech Stack:** Python 3.11+, Typer, Pydantic, PyYAML, pytest, Ruff, mypy, deterministic JSON/Markdown/HTML rendering.

---

## File Structure

- Create: `invariant_os/core/focus.py`
  - Owns `FocusMode`, `FocusProfile`, profile lookup, candidate scoring, and candidate ordering helpers.
- Modify: `invariant_os/core/models.py`
  - Add `FocusMetadata` model and `AuditResult.focus` field.
- Modify: `invariant_os/core/config.py`
  - Add `focus.mode` config parsing and validation.
  - Add `focus_mode` CLI override parameter to `load_audit_config`.
- Modify: `invariant_os/cli.py`
  - Add `--focus` option to `audit` and pass it into config loading.
- Modify: `invariant_os/core/audit.py`
  - Apply focus metadata after normal candidate generation.
- Modify: `invariant_os/report/review_queue.py`
  - Add focus metadata fields and focus-first deterministic sorting.
- Modify: `invariant_os/report/markdown.py`
  - Add a focus lens summary section.
- Modify: `invariant_os/report/html.py`
  - Add focus summary to the static evidence workspace.
- Modify: `README.md`
  - Document the new `--focus` option and mode values.
- Create: `tests/test_focus.py`
  - Unit tests for profiles, scoring, summaries, and ordering.
- Modify: `tests/test_config.py`
  - Config parsing and CLI override tests.
- Modify: `tests/test_audit_cli.py`
  - CLI acceptance/rejection and artifact metadata tests.
- Modify: `tests/test_models.py`
  - Default focus metadata regression test.
- Modify: `tests/test_review_queue_report.py`
  - Review queue focus fields and ordering tests.
- Modify: `tests/test_report.py`
  - Markdown focus summary test.
- Modify: `tests/test_html_report.py`
  - HTML focus summary test.

---

### Task 1: Add focus profiles and scoring helpers

**Files:**
- Create: `invariant_os/core/focus.py`
- Test: `tests/test_focus.py`

- [ ] **Step 1: Write the failing focus tests**

Create `tests/test_focus.py` with:

```python
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
```

- [ ] **Step 2: Run the focus tests and verify they fail**

Run:

```bash
.venv/bin/pytest tests/test_focus.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'invariant_os.core.focus'`.

- [ ] **Step 3: Create the focus module**

Create `invariant_os/core/focus.py` with:

```python
from dataclasses import dataclass
from enum import Enum
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
    boundary_types: frozenset[BoundaryType]
    primitive_types: frozenset[PrimitiveType]
    static_flow_target_types: frozenset[StaticFlowTargetType]
    keywords: frozenset[str]


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


_PROFILES = {
    FocusMode.ALL: FocusProfile(
        mode=FocusMode.ALL,
        label="All Evidence",
        description="Default lens over all deterministic audit evidence.",
        boundary_types=frozenset(),
        primitive_types=frozenset(),
        static_flow_target_types=frozenset(),
        keywords=frozenset(),
    ),
    FocusMode.IMPORT_UPLOAD: FocusProfile(
        mode=FocusMode.IMPORT_UPLOAD,
        label="Import / Upload",
        description="Prioritizes import, upload, archive, parser, file/path, and config-control surfaces.",
        boundary_types=frozenset(
            {
                BoundaryType.DATA_TO_FILE,
                BoundaryType.DATA_TO_CONFIG,
                BoundaryType.PARSER_TO_CONSUMER,
                BoundaryType.DATA_TO_DIRECTORY,
            }
        ),
        primitive_types=frozenset(
            {
                PrimitiveType.PATH_CONTROL,
                PrimitiveType.FILE_WRITE,
                PrimitiveType.FILE_READ,
                PrimitiveType.CONFIG_CONTROL,
                PrimitiveType.PARSER_DIFFERENTIAL,
                PrimitiveType.DIRECTORY_QUERY_CONTROL,
            }
        ),
        static_flow_target_types=frozenset({StaticFlowTargetType.CONSUMER}),
        keywords=frozenset({"upload", "import", "archive", "zip", "parser", "file", "path", "config"}),
    ),
    FocusMode.WORKER_QUEUE: FocusProfile(
        mode=FocusMode.WORKER_QUEUE,
        label="Worker / Queue",
        description="Prioritizes request-to-worker, queue, job, task, and async consumer surfaces.",
        boundary_types=frozenset(
            {
                BoundaryType.REQUEST_TO_WORKER,
                BoundaryType.DATA_TO_JOB,
                BoundaryType.LOW_PRIV_TO_PRIVILEGED_CONSUMER,
            }
        ),
        primitive_types=frozenset({PrimitiveType.JOB_CONTROL, PrimitiveType.TYPE_CONTROL}),
        static_flow_target_types=frozenset({StaticFlowTargetType.WORKER}),
        keywords=frozenset({"worker", "queue", "job", "task", "async", "event"}),
    ),
    FocusMode.TEMPLATE_WORKFLOW: FocusProfile(
        mode=FocusMode.TEMPLATE_WORKFLOW,
        label="Template / Workflow",
        description="Prioritizes template, workflow, renderer, parser, and config-to-behavior surfaces.",
        boundary_types=frozenset(
            {
                BoundaryType.DATA_TO_TEMPLATE,
                BoundaryType.DATA_TO_CONFIG,
                BoundaryType.PARSER_TO_CONSUMER,
            }
        ),
        primitive_types=frozenset(
            {
                PrimitiveType.TEMPLATE_CONTROL,
                PrimitiveType.CONFIG_CONTROL,
                PrimitiveType.PARSER_DIFFERENTIAL,
                PrimitiveType.TYPE_CONTROL,
            }
        ),
        static_flow_target_types=frozenset({StaticFlowTargetType.CONSUMER}),
        keywords=frozenset({"template", "workflow", "render", "renderer", "config", "rule"}),
    ),
    FocusMode.URL_INTERNAL_REQUEST: FocusProfile(
        mode=FocusMode.URL_INTERNAL_REQUEST,
        label="URL / Internal Request",
        description="Prioritizes URL control, internal request trigger, webhook, and network consumer surfaces.",
        boundary_types=frozenset({BoundaryType.DATA_TO_URL, BoundaryType.EXTERNAL_TO_INTERNAL}),
        primitive_types=frozenset({PrimitiveType.URL_CONTROL, PrimitiveType.INTERNAL_REQUEST_TRIGGER}),
        static_flow_target_types=frozenset({StaticFlowTargetType.CONSUMER}),
        keywords=frozenset({"url", "webhook", "http", "request", "internal", "network", "fetch"}),
    ),
}


def parse_focus_mode(value: str | FocusMode | None) -> FocusMode:
    if isinstance(value, FocusMode):
        return value
    if value is None:
        return FocusMode.ALL
    normalized = value.strip().lower()
    try:
        return FocusMode(normalized)
    except ValueError as error:
        allowed = ", ".join(mode.value for mode in FocusMode)
        raise ValueError(f"focus.mode must be one of: {allowed}") from error


def get_focus_profile(mode: FocusMode) -> FocusProfile:
    return _PROFILES[mode]


def score_boundary_focus(candidate: BoundaryCandidate, mode: FocusMode) -> FocusCandidateMetadata:
    profile = get_focus_profile(mode)
    if mode is FocusMode.ALL:
        return FocusCandidateMetadata(mode.value, True, 0, ["default all-focus lens"])
    reasons: list[str] = []
    score = 0
    if candidate.type in profile.boundary_types:
        score += 60
        reasons.append(f"boundary:{candidate.type.value}")
    score += _keyword_score(candidate.reason, profile, reasons)
    return FocusCandidateMetadata(mode.value, bool(reasons), score, reasons)


def score_primitive_focus(candidate: PrimitiveCandidate, mode: FocusMode) -> FocusCandidateMetadata:
    profile = get_focus_profile(mode)
    if mode is FocusMode.ALL:
        return FocusCandidateMetadata(mode.value, True, 0, ["default all-focus lens"])
    reasons: list[str] = []
    score = 0
    if candidate.primitive in profile.primitive_types:
        score += 60
        reasons.append(f"primitive:{candidate.primitive.value}")
    score += _keyword_score(" ".join(candidate.missing_evidence + candidate.safe_next_steps), profile, reasons)
    return FocusCandidateMetadata(mode.value, bool(reasons), score, reasons)


def score_static_flow_focus(candidate: StaticFlowCandidate, mode: FocusMode) -> FocusCandidateMetadata:
    profile = get_focus_profile(mode)
    if mode is FocusMode.ALL:
        return FocusCandidateMetadata(mode.value, True, 0, ["default all-focus lens"])
    reasons: list[str] = []
    score = 0
    if candidate.target_type in profile.static_flow_target_types:
        score += 20
        reasons.append(f"static_flow_target:{candidate.target_type.value}")
    text = " ".join([candidate.summary, *(signal.term for signal in candidate.signals)])
    score += _keyword_score(text, profile, reasons)
    return FocusCandidateMetadata(mode.value, bool(reasons), score, reasons)


def summarize_focus_matches(*, mode: FocusMode, boundary_metadata: list[FocusCandidateMetadata], primitive_metadata: list[FocusCandidateMetadata], static_flow_metadata: list[FocusCandidateMetadata]) -> FocusSummary:
    profile = get_focus_profile(mode)
    boundary_matches = sum(1 for item in boundary_metadata if item.focus_match)
    primitive_matches = sum(1 for item in primitive_metadata if item.focus_match)
    static_flow_matches = sum(1 for item in static_flow_metadata if item.focus_match)
    return FocusSummary(
        mode=mode.value,
        label=profile.label,
        description=profile.description,
        boundary_matches=boundary_matches,
        primitive_matches=primitive_matches,
        static_flow_matches=static_flow_matches,
        total_matches=boundary_matches + primitive_matches + static_flow_matches,
    )


def focus_sort_key(row: dict[str, object], existing_key: tuple[object, ...]) -> tuple[int, int, tuple[object, ...]]:
    return (
        0 if row.get("focus_match") is True else 1,
        -int(row.get("focus_score") or 0),
        existing_key,
    )


def _keyword_score(text: str, profile: FocusProfile, reasons: list[str]) -> int:
    normalized = text.lower()
    score = 0
    for keyword in sorted(profile.keywords):
        if keyword in normalized:
            score += 10
            reasons.append(f"keyword:{keyword}")
    return score
```

- [ ] **Step 4: Run the focus tests and verify they pass**

Run:

```bash
.venv/bin/pytest tests/test_focus.py -v
```

Expected: PASS for all focus tests.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add invariant_os/core/focus.py tests/test_focus.py
git commit -m "$(cat <<'EOF'
Add deterministic focus profiles

Define supported audit focus lenses and reusable scoring helpers for prioritizing existing evidence.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Store focus metadata on audit results

**Files:**
- Modify: `invariant_os/core/models.py:276-420`
- Modify: `invariant_os/core/audit.py:1-65`
- Test: `tests/test_models.py`
- Test: `tests/test_audit_cli.py`

- [ ] **Step 1: Write failing model and audit artifact tests**

In `tests/test_models.py`, add `FocusMetadata` to the import from `invariant_os.core.models` and add:

```python
def test_audit_result_defaults_to_all_focus_metadata():
    result = AuditResult(
        project=Project(name="example", root="/repo"),
        summary=AuditSummary(
            files=0,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
            static_flow_candidates=0,
        ),
    )

    assert result.focus == FocusMetadata(
        mode="all",
        label="All Evidence",
        description="Default lens over all deterministic audit evidence.",
        boundary_matches=0,
        primitive_matches=0,
        static_flow_matches=0,
        total_matches=0,
    )
```

In `tests/test_audit_cli.py`, update the import from `invariant_os.core.models` to include `FocusMetadata`, and add to `test_audit_writes_artifacts_for_fixture` after `audit_result = ...`:

```python
    assert audit_result.focus == FocusMetadata(
        mode="all",
        label="All Evidence",
        description="Default lens over all deterministic audit evidence.",
        boundary_matches=len(audit_result.boundaries),
        primitive_matches=len(audit_result.primitive_candidates),
        static_flow_matches=len(audit_result.static_flow_candidates),
        total_matches=(
            len(audit_result.boundaries)
            + len(audit_result.primitive_candidates)
            + len(audit_result.static_flow_candidates)
        ),
    )
```

- [ ] **Step 2: Run focused tests and verify they fail**

Run:

```bash
.venv/bin/pytest tests/test_models.py::test_audit_result_defaults_to_all_focus_metadata tests/test_audit_cli.py::test_audit_writes_artifacts_for_fixture -v
```

Expected: FAIL because `FocusMetadata` and `AuditResult.focus` do not exist.

- [ ] **Step 3: Add `FocusMetadata` to models**

In `invariant_os/core/models.py`, add after `AuditSummary`:

```python
class FocusMetadata(BaseModel):
    mode: str = "all"
    label: str = "All Evidence"
    description: str = "Default lens over all deterministic audit evidence."
    boundary_matches: int = 0
    primitive_matches: int = 0
    static_flow_matches: int = 0
    total_matches: int = 0
```

Then add to `AuditResult` before `summary`:

```python
    focus: FocusMetadata = Field(default_factory=FocusMetadata)
```

- [ ] **Step 4: Apply focus metadata in audit orchestration**

In `invariant_os/core/audit.py`, change imports to include `FocusMetadata` and focus helpers:

```python
from invariant_os.core.focus import (
    parse_focus_mode,
    score_boundary_focus,
    score_primitive_focus,
    score_static_flow_focus,
    summarize_focus_matches,
)
from invariant_os.core.models import AuditResult, AuditSummary, FocusMetadata, Project, SafetyMetadata
```

Before returning `AuditResult`, add:

```python
    focus_mode = parse_focus_mode(getattr(config.focus, "mode", "all"))
    boundary_focus = [score_boundary_focus(candidate, focus_mode) for candidate in boundaries]
    primitive_focus = [score_primitive_focus(candidate, focus_mode) for candidate in primitive_candidates]
    static_flow_focus = [
        score_static_flow_focus(candidate, focus_mode) for candidate in static_flow_candidates
    ]
    focus_summary = summarize_focus_matches(
        mode=focus_mode,
        boundary_metadata=boundary_focus,
        primitive_metadata=primitive_focus,
        static_flow_metadata=static_flow_focus,
    )
    focus = FocusMetadata(**focus_summary.__dict__)
```

Then pass `focus=focus` into `AuditResult(...)`.

- [ ] **Step 5: Run focused tests and verify they pass**

Run:

```bash
.venv/bin/pytest tests/test_models.py::test_audit_result_defaults_to_all_focus_metadata tests/test_audit_cli.py::test_audit_writes_artifacts_for_fixture -v
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

Run:

```bash
git add invariant_os/core/models.py invariant_os/core/audit.py tests/test_models.py tests/test_audit_cli.py
git commit -m "$(cat <<'EOF'
Record audit focus metadata

Store deterministic focus summaries on audit results without changing candidate generation.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Parse focus mode from config and CLI

**Files:**
- Modify: `invariant_os/core/config.py:30-78`
- Modify: `invariant_os/cli.py:30-113`
- Test: `tests/test_config.py`
- Test: `tests/test_audit_cli.py`

- [ ] **Step 1: Write failing config and CLI tests**

In `tests/test_config.py`, add:

```python
def test_load_audit_config_accepts_focus_mode(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text("focus:\n  mode: import-upload\n", encoding="utf-8")

    config = load_audit_config(tmp_path, config_path)

    assert config.focus.mode == "import-upload"


def test_load_audit_config_rejects_unknown_focus_mode(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text("focus:\n  mode: internet\n", encoding="utf-8")

    with pytest.raises(ValueError, match="focus.mode"):
        load_audit_config(tmp_path, config_path)


def test_load_audit_config_focus_mode_cli_override_wins(tmp_path):
    config_path = tmp_path / "invariant-os.yml"
    config_path.write_text("focus:\n  mode: import-upload\n", encoding="utf-8")

    config = load_audit_config(tmp_path, config_path, focus_mode="worker-queue")

    assert config.focus.mode == "worker-queue"
```

In `tests/test_audit_cli.py`, add:

```python
def test_audit_accepts_focus_option_and_writes_focus_metadata(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"
    output_dir = tmp_path / "focus-output"

    result = runner.invoke(
        app,
        ["audit", str(fixture), "--output-dir", str(output_dir), "--focus", "import-upload"],
    )

    assert result.exit_code == 0
    audit_result = AuditResult.model_validate_json(
        (output_dir / "audit_result.json").read_text(encoding="utf-8")
    )
    assert audit_result.focus.mode == "import-upload"
    assert audit_result.focus.label == "Import / Upload"
    assert audit_result.focus.total_matches >= 0


def test_audit_rejects_unknown_focus_option(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "mini_express_app"

    result = runner.invoke(app, ["audit", str(fixture), "--focus", "internet"])

    assert result.exit_code != 0
    assert "focus.mode" in result.output
```

- [ ] **Step 2: Run focused config/CLI tests and verify they fail**

Run:

```bash
.venv/bin/pytest tests/test_config.py::test_load_audit_config_accepts_focus_mode tests/test_config.py::test_load_audit_config_rejects_unknown_focus_mode tests/test_config.py::test_load_audit_config_focus_mode_cli_override_wins tests/test_audit_cli.py::test_audit_accepts_focus_option_and_writes_focus_metadata tests/test_audit_cli.py::test_audit_rejects_unknown_focus_option -v
```

Expected: FAIL because config and CLI do not accept focus mode yet.

- [ ] **Step 3: Extend config parsing**

In `invariant_os/core/config.py`, import `parse_focus_mode`:

```python
from invariant_os.core.focus import parse_focus_mode
```

Change `FocusConfig` to:

```python
class FocusConfig(BaseModel):
    mode: str = "all"
    files: set[str] = Field(default_factory=set)
    detectors: DetectorFocusConfig = Field(default_factory=DetectorFocusConfig)
```

Change `load_audit_config` signature to:

```python
def load_audit_config(
    repo: Path,
    config_path: Path | None,
    *,
    max_file_bytes: int | None = None,
    focus_mode: str | None = None,
) -> AuditConfig:
```

After the `max_file_bytes` override, add:

```python
    if focus_mode is not None:
        config.focus.mode = parse_focus_mode(focus_mode).value
```

In `_apply_payload`, inside `if focus:`, before `config.focus.files.update(...)`, add:

```python
        if "mode" in focus:
            config.focus.mode = parse_focus_mode(
                _optional_string(focus.get("mode"), "focus.mode")
            ).value
```

In `_validate_config`, before integration checks, add:

```python
    config.focus.mode = parse_focus_mode(config.focus.mode).value
```

- [ ] **Step 4: Add `--focus` to audit CLI**

In `invariant_os/cli.py`, add a parameter to `audit` after `max_file_bytes`:

```python
    focus: Annotated[
        str,
        typer.Option("--focus", help="Semantic focus lens: all, import-upload, worker-queue, template-workflow, or url-internal-request."),
    ] = "all",
```

Change `_audit_config` signature to accept `focus: str`, and call:

```python
    config = load_audit_config(repo, config_path, max_file_bytes=max_file_bytes, focus_mode=focus)
```

Change the call from `audit` to:

```python
        config = _audit_config(repo, output_dir, max_file_bytes, focus, config_path)
```

- [ ] **Step 5: Run focused config/CLI tests and verify they pass**

Run:

```bash
.venv/bin/pytest tests/test_config.py tests/test_audit_cli.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

Run:

```bash
git add invariant_os/core/config.py invariant_os/cli.py tests/test_config.py tests/test_audit_cli.py
git commit -m "$(cat <<'EOF'
Add audit focus configuration

Allow semantic focus modes through YAML and CLI overrides while preserving deterministic local validation.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Add focus metadata to review queue rows

**Files:**
- Modify: `invariant_os/report/review_queue.py:1-168`
- Test: `tests/test_review_queue_report.py`

- [ ] **Step 1: Write failing review queue tests**

In `tests/test_review_queue_report.py`, add tests:

```python
def test_review_queue_rows_include_focus_metadata():
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[_evidence("ev_primitive_0001")],
    )
    result = _empty_result().model_copy(
        update={
            "focus": {
                "mode": "import-upload",
                "label": "Import / Upload",
                "description": "Prioritizes import and upload surfaces.",
                "boundary_matches": 0,
                "primitive_matches": 1,
                "static_flow_matches": 0,
                "total_matches": 1,
            },
            "primitive_candidates": [primitive],
        }
    )

    row = _rows(result)[0]

    assert row["focus_mode"] == "import-upload"
    assert row["focus_match"] is True
    assert row["focus_score"] >= 50
    assert "primitive:file_write" in row["focus_reasons"]


def test_review_queue_sorts_focus_matches_before_non_matches():
    url_primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.URL_CONTROL,
        confidence=Confidence.MEDIUM,
        evidence=[_evidence("ev_url_0001")],
    )
    file_primitive = PrimitiveCandidate(
        id="primitive_0002",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[_evidence("ev_file_0001")],
    )
    result = _empty_result().model_copy(
        update={
            "focus": {
                "mode": "import-upload",
                "label": "Import / Upload",
                "description": "Prioritizes import and upload surfaces.",
                "boundary_matches": 0,
                "primitive_matches": 1,
                "static_flow_matches": 0,
                "total_matches": 1,
            },
            "primitive_candidates": [url_primitive, file_primitive],
        }
    )

    rows = _rows(result)

    assert [row["candidate_id"] for row in rows] == ["primitive_0002", "primitive_0001"]
    assert rows[0]["focus_match"] is True
    assert rows[1]["focus_match"] is False
```

- [ ] **Step 2: Run review queue tests and verify they fail**

Run:

```bash
.venv/bin/pytest tests/test_review_queue_report.py::test_review_queue_rows_include_focus_metadata tests/test_review_queue_report.py::test_review_queue_sorts_focus_matches_before_non_matches -v
```

Expected: FAIL because rows do not include focus fields.

- [ ] **Step 3: Score rows in review queue renderer**

In `invariant_os/report/review_queue.py`, import:

```python
from invariant_os.core.focus import (
    focus_sort_key,
    parse_focus_mode,
    score_boundary_focus,
    score_primitive_focus,
    score_static_flow_focus,
)
```

Change `render_review_queue_jsonl` to pass `result` into row builders:

```python
def render_review_queue_jsonl(result: AuditResult) -> str:
    focus_mode = parse_focus_mode(result.focus.mode)
    rows = [
        *_boundary_rows(result.boundaries, focus_mode),
        *_primitive_rows(result.primitive_candidates, focus_mode),
        *_static_flow_rows(result.static_flow_candidates, focus_mode),
    ]
    rows.sort(key=_row_sort_key)
    if not rows:
        return ""
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
```

Update row builder signatures to accept `focus_mode` and compute metadata:

```python
def _boundary_rows(candidates: list[BoundaryCandidate], focus_mode) -> list[dict[str, Any]]:
    ...
    focus_metadata = score_boundary_focus(candidate, focus_mode)
    rows.append(_build_row(..., focus_metadata=focus_metadata, ...))
```

Do the same for primitive/static-flow rows using `score_primitive_focus` and `score_static_flow_focus`.

Change `_build_row` signature to include `focus_metadata` and add fields to returned dict:

```python
        "focus_mode": focus_metadata.focus_mode,
        "focus_match": focus_metadata.focus_match,
        "focus_score": focus_metadata.focus_score,
        "focus_reasons": focus_metadata.focus_reasons,
```

Change `_row_sort_key` to:

```python
def _row_sort_key(row: dict[str, Any]) -> tuple[int, int, tuple[str, str, str, str, int]]:
    existing_key = (
        row["category"],
        row["kind"],
        row["candidate_id"],
        row["primary_file"] or "",
        row["primary_line"] or 0,
    )
    return focus_sort_key(row, existing_key)
```

- [ ] **Step 4: Run review queue tests and verify they pass**

Run:

```bash
.venv/bin/pytest tests/test_review_queue_report.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

Run:

```bash
git add invariant_os/report/review_queue.py tests/test_review_queue_report.py
git commit -m "$(cat <<'EOF'
Add focus metadata to review queue

Annotate manual-review rows with deterministic focus scores and sort focused evidence first.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Render focus summaries in Markdown, HTML, and README

**Files:**
- Modify: `invariant_os/report/markdown.py:31-102`
- Modify: `invariant_os/report/html.py:35-135`
- Modify: `README.md:39-49`
- Test: `tests/test_report.py`
- Test: `tests/test_html_report.py`

- [ ] **Step 1: Write failing report tests**

In `tests/test_report.py`, add a test near the research brief tests:

```python
def test_research_brief_renders_focus_lens_summary():
    result = _minimal_result().model_copy(
        update={
            "focus": {
                "mode": "import-upload",
                "label": "Import / Upload",
                "description": "Prioritizes import and upload surfaces.",
                "boundary_matches": 1,
                "primitive_matches": 2,
                "static_flow_matches": 3,
                "total_matches": 6,
            }
        }
    )

    markdown = render_research_brief(result)

    assert "## Focus Lens" in markdown
    assert "Import / Upload" in markdown
    assert "Total focus matches: 6" in markdown
```

In `tests/test_html_report.py`, add:

```python
def test_evidence_viewer_renders_focus_lens_summary():
    result = _minimal_result().model_copy(
        update={
            "focus": {
                "mode": "worker-queue",
                "label": "Worker / Queue",
                "description": "Prioritizes worker and queue surfaces.",
                "boundary_matches": 1,
                "primitive_matches": 0,
                "static_flow_matches": 2,
                "total_matches": 3,
            }
        }
    )

    html = render_evidence_viewer(result)

    assert "Focus Lens" in html
    assert "Worker / Queue" in html
    assert "Total focus matches" in html
    assert "3" in html
```

If the helper is named differently in these files, use the existing minimal `AuditResult` fixture helper in that test file.

- [ ] **Step 2: Run report tests and verify they fail**

Run:

```bash
.venv/bin/pytest tests/test_report.py::test_research_brief_renders_focus_lens_summary tests/test_html_report.py::test_evidence_viewer_renders_focus_lens_summary -v
```

Expected: FAIL because report renderers do not output focus summaries.

- [ ] **Step 3: Add Markdown focus section**

In `invariant_os/report/markdown.py`, add a Focus Lens section after Repository Profile:

```python
        "## Focus Lens",
        "",
        *_render_focus(result),
        "",
```

Add helper:

```python
def _render_focus(result: AuditResult) -> list[str]:
    return [
        f"- Mode: `{result.focus.mode}` ({result.focus.label})",
        f"- Description: {result.focus.description}",
        f"- Boundary focus matches: {result.focus.boundary_matches}",
        f"- Primitive focus matches: {result.focus.primitive_matches}",
        f"- Static flow focus matches: {result.focus.static_flow_matches}",
        f"- Total focus matches: {result.focus.total_matches}",
    ]
```

- [ ] **Step 4: Add HTML focus summary**

In `invariant_os/report/html.py`, add Focus Lens to sections after Summary:

```python
        _section("Focus Lens", _render_focus(result)),
```

Add `"Focus Lens"` to `_render_nav()` after `"Summary"`.

Add helper:

```python
def _render_focus(result: AuditResult) -> str:
    rows = [
        ("Mode", f"{result.focus.mode} ({result.focus.label})"),
        ("Description", result.focus.description),
        ("Boundary focus matches", str(result.focus.boundary_matches)),
        ("Primitive focus matches", str(result.focus.primitive_matches)),
        ("Static flow focus matches", str(result.focus.static_flow_matches)),
        ("Total focus matches", str(result.focus.total_matches)),
    ]
    return _definition_list(rows)
```

- [ ] **Step 5: Document `--focus` in README**

In `README.md`, under audit Options, add:

```markdown
- `--focus`: semantic focus lens for deterministic prioritization. Supported values are `all`, `import-upload`, `worker-queue`, `template-workflow`, and `url-internal-request`. Defaults to `all`.
```

In the Configuration YAML example under `focus:`, add:

```yaml
  mode: all
```

In the paragraph after the YAML block, add one sentence:

```markdown
The `focus.mode` value only changes deterministic prioritization and artifact presentation; it does not disable detectors, execute targets, run Semgrep, call LLM providers, or confirm vulnerabilities.
```

- [ ] **Step 6: Run report and README checks**

Run:

```bash
.venv/bin/pytest tests/test_report.py tests/test_html_report.py -v
.venv/bin/python - <<'PY'
from pathlib import Path
text = Path('README.md').read_text()
assert '--focus' in text
assert 'import-upload' in text
assert 'url-internal-request' in text
assert 'does not disable detectors' in text
assert 'run Semgrep' in text
PY
```

Expected: PASS.

- [ ] **Step 7: Commit Task 5**

Run:

```bash
git add invariant_os/report/markdown.py invariant_os/report/html.py README.md tests/test_report.py tests/test_html_report.py
git commit -m "$(cat <<'EOF'
Render focus summaries in reports

Show selected audit focus lenses in local artifacts while preserving conservative safety wording.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Final verification

**Files:**
- Verify only; no planned source modifications.

- [ ] **Step 1: Run focused semantic focus tests**

Run:

```bash
.venv/bin/pytest tests/test_focus.py tests/test_config.py tests/test_audit_cli.py tests/test_review_queue_report.py tests/test_report.py tests/test_html_report.py -v
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:

```bash
.venv/bin/pytest
```

Expected: all tests pass with zero failures.

- [ ] **Step 3: Run Ruff**

Run:

```bash
.venv/bin/ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 4: Run mypy**

Run:

```bash
.venv/bin/mypy invariant_os
```

Expected: `Success: no issues found`.

- [ ] **Step 5: Run a smoke audit with focus mode**

Run:

```bash
rm -rf outputs/focus-smoke
.venv/bin/invariant-os audit tests/fixtures/mini_express_app --output-dir outputs/focus-smoke --focus import-upload
.venv/bin/python - <<'PY'
import json
from pathlib import Path
root = Path('outputs/focus-smoke')
audit = json.loads((root / 'audit_result.json').read_text())
rows = [json.loads(line) for line in (root / 'audit_review_queue.jsonl').read_text().splitlines()]
brief = (root / 'research_brief.md').read_text()
html = (root / 'evidence_viewer.html').read_text()
assert audit['focus']['mode'] == 'import-upload'
assert all(row['focus_mode'] == 'import-upload' for row in rows)
assert 'Focus Lens' in brief
assert 'Focus Lens' in html
PY
```

Expected: commands exit 0.

- [ ] **Step 6: Confirm git history and status**

Run:

```bash
git status --short --branch && git log --oneline -8
```

Expected: branch is ahead by the new commits and working tree is clean except any intentionally generated ignored output directory.

- [ ] **Step 7: Do not push automatically**

Stop and ask whether the user wants to push after verification.
