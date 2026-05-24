# Release Readiness Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align InvariantOS release/schema metadata and README roadmap with the implemented v0.10 local artifact pipeline.

**Architecture:** This is a release/readiness cleanup, not a new feature. Keep behavior unchanged except for version/schema strings and documentation accuracy. Version constants should be explicit in code so future artifact renderers do not drift independently.

**Tech Stack:** Python 3.11+, Pydantic, Typer, pytest, Ruff, mypy, Markdown docs.

---

## File Structure

- Modify: `invariant_os/core/models.py`
  - Add explicit schema version constants near the model definitions.
  - Change `AuditResult.schema_version` from `"0.5"` to `AUDIT_SCHEMA_VERSION`.
- Modify: `invariant_os/report/review_queue.py`
  - Import and reuse the audit/review queue schema version constant instead of hard-coding `"0.10"`.
- Modify: `pyproject.toml`
  - Change project version from `0.1.0` to `0.10.0`.
- Modify: `README.md`
  - Add concise release status text describing what is complete, partial, deferred, and next.
  - Refresh stale roadmap bullets so already-complete graph/data-flow/SARIF/review-queue items are not listed as future work.
  - Preserve local-only safety language.
- Modify: `tests/test_models.py`
  - Update schema assertions and add constant-level regression checks.
- Modify: `tests/test_review_queue_report.py`
  - Assert review queue schema follows the shared constant.
- Modify: `tests/test_audit_cli.py`
  - Update audit fixture schema expectation from `0.5` to `0.10`.

Do not create runtime LLM providers, Semgrep execution, a web server, or a new CLI command in this plan.

---

### Task 1: Centralize schema versions

**Files:**
- Modify: `invariant_os/core/models.py:1-5`
- Modify: `invariant_os/core/models.py:403-416`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_models.py`, update the import block to include the new constants:

```python
from invariant_os.core.models import (
    AUDIT_SCHEMA_VERSION,
    REVIEW_QUEUE_SCHEMA_VERSION,
    AuditResult,
    AuditSummary,
    BoundaryType,
    Confidence,
    ConsumerType,
    EntrypointType,
    Evidence,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphEdgeType,
    EvidenceGraphNode,
    EvidenceGraphNodeType,
    EvidenceType,
    FileRecord,
    PatchChangedFile,
    PatchChangeType,
    PatchCorrelation,
    PatchCorrelationType,
    PatchDiffInputType,
    PatchDiffResult,
    PatchDiffSummary,
    PatchHunk,
    PatchVariantCandidate,
    PatchVariantSourceType,
    PrimitiveType,
    Project,
    SafetyMetadata,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
    WorkerType,
)
```

Change `test_audit_result_json_dump_includes_schema_tool_and_safety_principle` so the schema assertion is:

```python
    assert dumped["schema_version"] == AUDIT_SCHEMA_VERSION
```

Change the test named `test_audit_result_defaults_to_empty_evidence_graph_and_schema_05` to:

```python
def test_audit_result_defaults_to_empty_evidence_graph_and_schema_010():
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

    assert result.schema_version == "0.10"
    assert result.schema_version == AUDIT_SCHEMA_VERSION
    assert result.evidence_graph.nodes == []
    assert result.evidence_graph.edges == []
```

Add this new test near the schema tests:

```python
def test_schema_version_constants_are_aligned_for_v010_release():
    assert AUDIT_SCHEMA_VERSION == "0.10"
    assert REVIEW_QUEUE_SCHEMA_VERSION == "0.10"
```

- [ ] **Step 2: Run the focused model test and verify it fails**

Run:

```bash
.venv/bin/pytest tests/test_models.py::test_schema_version_constants_are_aligned_for_v010_release -v
```

Expected: FAIL with an import error for `AUDIT_SCHEMA_VERSION` or `REVIEW_QUEUE_SCHEMA_VERSION` because the constants do not exist yet.

- [ ] **Step 3: Add version constants and update `AuditResult`**

In `invariant_os/core/models.py`, add constants after the imports:

```python
from enum import Enum

from pydantic import BaseModel, Field


AUDIT_SCHEMA_VERSION = "0.10"
REVIEW_QUEUE_SCHEMA_VERSION = "0.10"
```

Change the `AuditResult` model tail from:

```python
class AuditResult(BaseModel):
    project: Project
    files: list[FileRecord] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    consumers: list[Consumer] = Field(default_factory=list)
    workers: list[Worker] = Field(default_factory=list)
    boundaries: list[BoundaryCandidate] = Field(default_factory=list)
    primitive_candidates: list[PrimitiveCandidate] = Field(default_factory=list)
    static_flow_candidates: list[StaticFlowCandidate] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    summary: AuditSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = "0.5"
    tool: str = "invariant-os"
```

to:

```python
class AuditResult(BaseModel):
    project: Project
    files: list[FileRecord] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    consumers: list[Consumer] = Field(default_factory=list)
    workers: list[Worker] = Field(default_factory=list)
    boundaries: list[BoundaryCandidate] = Field(default_factory=list)
    primitive_candidates: list[PrimitiveCandidate] = Field(default_factory=list)
    static_flow_candidates: list[StaticFlowCandidate] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    summary: AuditSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = AUDIT_SCHEMA_VERSION
    tool: str = "invariant-os"
```

- [ ] **Step 4: Run the focused model tests and verify they pass**

Run:

```bash
.venv/bin/pytest tests/test_models.py::test_audit_result_json_dump_includes_schema_tool_and_safety_principle tests/test_models.py::test_audit_result_defaults_to_empty_evidence_graph_and_schema_010 tests/test_models.py::test_schema_version_constants_are_aligned_for_v010_release -v
```

Expected: PASS for all three tests.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add invariant_os/core/models.py tests/test_models.py
git commit -m "$(cat <<'EOF'
Align audit schema version constants

Centralize v0.10 schema metadata so audit artifacts and tests share the same release version.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Reuse schema constants in review queue and audit CLI tests

**Files:**
- Modify: `invariant_os/report/review_queue.py:1-10`
- Modify: `invariant_os/report/review_queue.py:121-124`
- Modify: `tests/test_review_queue_report.py:3-20`
- Modify: `tests/test_audit_cli.py:107`

- [ ] **Step 1: Write the failing review queue constant test**

In `tests/test_review_queue_report.py`, add `REVIEW_QUEUE_SCHEMA_VERSION` to the import from `invariant_os.core.models`:

```python
from invariant_os.core.models import (
    REVIEW_QUEUE_SCHEMA_VERSION,
    AuditResult,
    AuditSummary,
    BoundaryCandidate,
    BoundaryType,
    Confidence,
    Evidence,
    EvidenceType,
    PrimitiveCandidate,
    PrimitiveType,
    Project,
    SafetyMetadata,
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
)
```

Change the schema assertion in `test_review_queue_renders_primitive_candidate_row` from:

```python
    assert row["schema_version"] == "0.10"
```

to:

```python
    assert row["schema_version"] == REVIEW_QUEUE_SCHEMA_VERSION
```

In `tests/test_audit_cli.py`, change:

```python
    assert audit_result.schema_version == "0.5"
```

to:

```python
    assert audit_result.schema_version == "0.10"
```

- [ ] **Step 2: Run focused tests and verify current behavior**

Run:

```bash
.venv/bin/pytest tests/test_review_queue_report.py::test_review_queue_renders_primitive_candidate_row tests/test_audit_cli.py::test_audit_writes_java_tomcat_fixture_signals -v
```

Expected: `test_audit_writes_java_tomcat_fixture_signals` passes only after Task 1 is complete. If it fails with schema `0.5`, Task 1 was not implemented correctly.

- [ ] **Step 3: Import the shared constant in review queue renderer**

Change `invariant_os/report/review_queue.py` import block from:

```python
from invariant_os.core.models import (
    AuditResult,
    BoundaryCandidate,
    Evidence,
    PrimitiveCandidate,
    StaticFlowCandidate,
)
```

to:

```python
from invariant_os.core.models import (
    REVIEW_QUEUE_SCHEMA_VERSION,
    AuditResult,
    BoundaryCandidate,
    Evidence,
    PrimitiveCandidate,
    StaticFlowCandidate,
)
```

Change `_build_row` from:

```python
        "schema_version": "0.10",
```

to:

```python
        "schema_version": REVIEW_QUEUE_SCHEMA_VERSION,
```

- [ ] **Step 4: Run focused review queue and audit CLI tests**

Run:

```bash
.venv/bin/pytest tests/test_review_queue_report.py tests/test_audit_cli.py -v
```

Expected: PASS for all tests in both files.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add invariant_os/report/review_queue.py tests/test_review_queue_report.py tests/test_audit_cli.py
git commit -m "$(cat <<'EOF'
Reuse schema constants in review queue output

Keep audit and review-queue artifact metadata aligned with the v0.10 release schema.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Align package version and README release status

**Files:**
- Modify: `pyproject.toml:1-4`
- Modify: `README.md:1-187`

- [ ] **Step 1: Write the failing packaging/version test command**

Run:

```bash
.venv/bin/python - <<'PY'
import tomllib
from pathlib import Path
payload = tomllib.loads(Path('pyproject.toml').read_text())
assert payload['project']['version'] == '0.10.0', payload['project']['version']
PY
```

Expected: FAIL with `AssertionError: 0.1.0`.

- [ ] **Step 2: Update package version**

In `pyproject.toml`, change:

```toml
version = "0.1.0"
```

to:

```toml
version = "0.10.0"
```

- [ ] **Step 3: Verify package version command passes**

Run:

```bash
.venv/bin/python - <<'PY'
import tomllib
from pathlib import Path
payload = tomllib.loads(Path('pyproject.toml').read_text())
assert payload['project']['version'] == '0.10.0', payload['project']['version']
PY
```

Expected: command exits 0 with no output.

- [ ] **Step 4: Add release status section to README**

In `README.md`, after the Quickstart block ending at line 25, insert:

```markdown
## Current Release Status

The current implementation is a deterministic local artifact pipeline. It includes repository indexing, broad static detector coverage, trust-boundary inference, primitive classification, bounded static-flow enrichment, evidence graph generation, SARIF export, review-queue JSONL export, deterministic offline reasoning, and local patch-diff correlation.

Intentionally deferred areas include live/network LLM providers, Semgrep execution, hosted scanning, target execution, exploit automation, a server-backed web UI, team workflow, fix advisors, and regression-test generation. These remain future work behind the local-first safety model.
```

- [ ] **Step 5: Replace stale roadmap**

Replace the existing roadmap block:

```markdown
## Roadmap

- Add richer language and framework detectors.
- Add optional LLM-assisted hypothesis generation behind the existing safety model.
- Add evidence graphing and data-flow enrichment.
- Expand SARIF and additional export formats.
- Expand configuration files for richer per-repository detector tuning.
```

with:

```markdown
## Roadmap

- Add a review-queue CLI for local filtering, summarization, and handoff of `audit_review_queue.jsonl`.
- Add semantic focus modes for import/upload, worker/queue, template/workflow, and URL/internal-request research.
- Modularize detector families as coverage grows, while preserving deterministic output and existing detector tuning.
- Expand configuration for report caps and local artifact selection.
- Design optional LLM-assisted hypothesis generation behind the existing safety model, with deterministic tests and evidence-linked outputs before enabling real providers.
- Evaluate optional Semgrep integration as a disabled-by-default local tool path that never runs unless explicitly configured and available locally.
```

- [ ] **Step 6: Check README contains updated status and no stale roadmap claims**

Run:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
text = Path('README.md').read_text()
assert '## Current Release Status' in text
assert 'review-queue CLI' in text
assert 'Add evidence graphing and data-flow enrichment.' not in text
assert 'Expand SARIF and additional export formats.' not in text
assert 'does not scan public targets' in text
PY
```

Expected: command exits 0 with no output.

- [ ] **Step 7: Commit Task 3**

Run:

```bash
git add pyproject.toml README.md
git commit -m "$(cat <<'EOF'
Refresh v0.10 release metadata and roadmap

Align package metadata and documentation with the implemented local artifact pipeline and deferred future work.

Co-Authored-By: gpt-5.5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Final verification

**Files:**
- Verify only; no planned source modifications.

- [ ] **Step 1: Run focused release-readiness tests**

Run:

```bash
.venv/bin/pytest tests/test_models.py tests/test_review_queue_report.py tests/test_audit_cli.py -v
```

Expected: PASS for all selected tests.

- [ ] **Step 2: Run full test suite**

Run:

```bash
.venv/bin/pytest
```

Expected: `262 passed` or the current full test count with zero failures.

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

Expected: `Success: no issues found in 36 source files` or the current source-file count with zero issues.

- [ ] **Step 5: Confirm git history and status**

Run:

```bash
git status --short --branch && git log --oneline -5
```

Expected: branch is ahead by the new commits and working tree is clean.

- [ ] **Step 6: Do not push automatically**

Stop and ask the user whether they want to push after verification. Pushing changes affects remote shared state and requires explicit confirmation.
