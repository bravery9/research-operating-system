# Semantic Focus Modes Design

## Goal

Add deterministic semantic focus modes to `invariant-os audit` so researchers can view existing audit evidence through a specific research lens without changing the local-first safety model.

## Scope

The feature adds a bounded focus option for the audit pipeline:

- `all` — default behavior, equivalent to current audit output.
- `import-upload` — prioritizes upload, archive, import/export, file/path, parser, and config-related surfaces.
- `worker-queue` — prioritizes request-to-worker, queue, job, task, async consumer, and privilege-boundary surfaces.
- `template-workflow` — prioritizes template, workflow, renderer, config-to-behavior, and parser-to-consumer surfaces.
- `url-internal-request` — prioritizes URL control, internal request trigger, external-to-internal, webhook, and network consumer surfaces.

Focus modes do not add public scanning, exploit automation, target execution, Semgrep execution, live/network LLM calls, auto-fixes, or vulnerability confirmation. They are a deterministic lens over evidence already produced by the local pipeline.

## Architecture

Add a small focus layer rather than separate pipelines.

### `invariant_os/core/focus.py`

Create a focused module that defines:

- `FocusMode` enum for the supported wire values.
- `FocusProfile` model or dataclass containing label, description, relevant boundary types, primitive types, consumer hints, worker hints, and evidence keywords.
- `get_focus_profile(mode: FocusMode) -> FocusProfile`.
- Candidate scoring helpers that return deterministic focus metadata such as `focus_match`, `focus_score`, and `focus_reasons`.

The scoring helpers should inspect existing structured candidates only. They should not read files, run external tools, or create new findings.

### `invariant_os/core/config.py`

Extend audit configuration to accept optional `focus.mode`. The value must be one of the supported modes. Existing config precedence remains:

1. built-in defaults
2. auto-discovered repo config
3. explicit `--config`
4. CLI scalar overrides
5. runtime output-directory ignores

CLI `--focus` should override YAML `focus.mode`.

### `invariant_os/cli.py`

Add `--focus` to `audit`, defaulting to `all`. The CLI should reject unknown focus values through Typer validation or config validation, and pass the selected mode into audit configuration.

### `invariant_os/core/models.py`

Add audit-result focus metadata so artifacts can explain the lens applied:

- selected mode
- human-readable label
- deterministic summary counts for matched boundaries, primitives, and static-flow candidates

This metadata should be optional/defaulted so default `all` remains stable and easy to consume.

### `invariant_os/core/audit.py`

Run the existing audit pipeline unchanged, then apply focus scoring to existing candidates before returning `AuditResult`. The focus layer may annotate summary metadata and provide ordering keys to reports, but it must not suppress candidates from `audit_result.json`.

### Reports

Markdown, HTML, and review-queue reports should use focus metadata to highlight relevant candidates. Review queue rows should include deterministic fields:

- `focus_mode`
- `focus_match`
- `focus_score`
- `focus_reasons`

Focused reports may sort focus-matched rows ahead of non-matches while preserving deterministic tie-breaking by existing row keys.

## Data Flow

```text
CLI/config focus input
→ AuditConfig.focus.mode
→ run_audit builds normal candidates
→ focus profile scores existing candidates
→ audit_result.json records selected focus and deterministic focus summaries
→ Markdown / review queue / HTML highlight focus-matched evidence
```

Focus modes are presentation and prioritization metadata. They are not a new detection engine and not a source of security claims.

## Error Handling

Invalid focus values should fail before the audit runs, with a clear local validation error. Config values should use the same validation path as CLI values so typos behave consistently.

If a focus profile matches no candidates, the audit still succeeds and reports should state that no candidates matched the selected focus lens.

## Testing

Add tests for:

- valid CLI `--focus` values are accepted
- invalid CLI focus values are rejected
- YAML `focus.mode` is loaded
- CLI `--focus` overrides YAML `focus.mode`
- `audit_result.json` records selected focus metadata
- default `all` preserves current behavior
- review queue rows include deterministic focus metadata
- focus-matched review queue rows sort before non-matches with deterministic tie-breaking
- Markdown and/or HTML output includes selected focus label and matched-count summary

## Safety

All outputs must keep candidate/hypothesis/missing-evidence language. Focus mode labels must not imply confirmed exploitability or vulnerability presence. The feature must preserve these constraints:

- no public target scanning
- no hosted scanning
- no target execution
- no exploit payload generation
- no exploit automation
- no Semgrep execution
- no live/network LLM provider calls
- no auto-fixes
- no vulnerability or exploitability confirmation
