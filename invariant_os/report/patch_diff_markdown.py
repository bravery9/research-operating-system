"""Markdown rendering for patch-diff artifacts."""

from invariant_os.core.models import PatchChangedFile, PatchCorrelation, PatchDiffResult, PatchVariantCandidate


def render_patch_diff_brief(result: PatchDiffResult) -> str:
    lines = [
        "# InvariantOS Patch Diff Brief",
        "",
        "## Scope and Safety",
        "",
        "This brief is limited to authorized local repository analysis. It summarizes deterministic patch-adjacent candidates and hypotheses only; it does not prove vulnerability or exploitability.",
        f"Core principle: {result.safety.principle}",
        "",
        "## Source Audit",
        "",
        f"- Project: `{result.source_project.name}`",
        f"- Root: `{result.source_project.root}`",
        f"- Source audit file: `{result.source_audit_file}`",
        f"- Source schema version: `{result.source_schema_version}`",
        f"- Patch diff schema version: `{result.schema_version}`",
        "",
        "## Diff Input",
        "",
        f"- Input type: `{result.input_type.value}`",
        f"- Patch file: {_value_or_none(result.patch_file)}",
        f"- Repo path: {_value_or_none(result.repo_path)}",
        f"- Base ref: {_value_or_none(result.base_ref)}",
        f"- Head ref: {_value_or_none(result.head_ref)}",
        "",
        "## Summary",
        "",
        f"- Changed files: {result.summary.changed_files}",
        f"- Hunks: {result.summary.hunks}",
        f"- Correlations: {result.summary.correlations}",
        f"- Variant candidates: {result.summary.variant_candidates}",
        f"- Files with audit context: {result.summary.files_with_audit_context}",
        "",
        "## Changed Files",
        "",
        *_render_changed_files(result.changed_files),
        "",
        "## Correlations",
        "",
        *_render_correlations(result.correlations),
        "",
        "## Variant Candidates",
        "",
        *_render_variants(result.variant_candidates),
        "",
        "## Missing Evidence",
        "",
        *_render_missing_evidence(result),
        "",
        "## Safe Next Steps",
        "",
        *_render_safe_next_steps(result.variant_candidates),
        "",
    ]
    return "\n".join(lines)


def _render_changed_files(files: list[PatchChangedFile]) -> list[str]:
    if not files:
        return ["No changed files were parsed."]
    lines: list[str] = []
    for changed_file in files:
        path = changed_file.new_path or changed_file.old_path or "none recorded"
        lines.append(
            f"- `{changed_file.id}` `{path}` {changed_file.change_type.value}, hunks: {len(changed_file.hunks)}"
        )
        for hunk in changed_file.hunks:
            lines.append(
                f"  - `{hunk.id}` old `{hunk.old_start},{hunk.old_count}` new `{hunk.new_start},{hunk.new_count}` added {_join_numbers(hunk.added_lines)} removed {_join_numbers(hunk.removed_lines)}"
            )
    return lines


def _render_correlations(correlations: list[PatchCorrelation]) -> list[str]:
    if not correlations:
        return ["No patch correlations were generated."]
    return [
        (
            f"- `{correlation.id}` {correlation.type.value} ({correlation.confidence.value} confidence) "
            f"for `{correlation.changed_file_id}` hunk {_value_or_none(correlation.hunk_id)}. "
            f"Related {correlation.related_type.value}: `{correlation.related_id}`. "
            f"Location: `{correlation.file}`:{correlation.line if correlation.line is not None else 'none recorded'}. "
            f"Evidence: {_join_or_none(correlation.evidence_ids)}. "
            f"Missing evidence: {_join_or_none(correlation.missing_evidence)}. {correlation.reason}"
        )
        for correlation in correlations
    ]


def _render_variants(variants: list[PatchVariantCandidate]) -> list[str]:
    if not variants:
        return ["No patch variant candidates were generated."]
    return [
        (
            f"- `{variant.id}` {variant.title} ({variant.confidence.value} confidence). "
            f"Source {variant.source_type.value}: `{variant.source_id}`. "
            f"Changed file: `{variant.changed_file_id}`. Hunk: {_value_or_none(variant.hunk_id)}. "
            f"{variant.summary} Related IDs: {_join_or_none(variant.related_ids)}. "
            f"Evidence: {_join_or_none(variant.evidence_ids)}. "
            f"Missing evidence: {_join_or_none(variant.missing_evidence)}. "
            f"Safe next steps: {_join_or_none(variant.safe_next_steps)}"
        )
        for variant in variants
    ]


def _render_missing_evidence(result: PatchDiffResult) -> list[str]:
    values: list[str] = []
    for correlation in result.correlations:
        values.extend(correlation.missing_evidence)
    for variant in result.variant_candidates:
        values.extend(variant.missing_evidence)
    if not values:
        return ["No missing evidence notes were generated."]
    return [f"- {value}" for value in dict.fromkeys(values)]


def _render_safe_next_steps(variants: list[PatchVariantCandidate]) -> list[str]:
    values: list[str] = []
    for variant in variants:
        values.extend(variant.safe_next_steps)
    if not values:
        return ["No safe next steps were generated."]
    return [f"- {value}" for value in dict.fromkeys(values)]


def _value_or_none(value: str | None) -> str:
    return f"`{value}`" if value else "none recorded"


def _join_or_none(values: list[str]) -> str:
    return "; ".join(f"`{value}`" for value in values) if values else "none recorded"


def _join_numbers(values: list[int]) -> str:
    return ", ".join(str(value) for value in values) if values else "none recorded"
