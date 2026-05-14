"""Markdown rendering for deterministic reasoning artifacts."""

from invariant_os.core.models import ReasoningCategory, ReasoningItem, ReasoningResult

_CATEGORY_TITLES = {
    ReasoningCategory.HIGH_VALUE_SURFACE: "High-Value Surfaces",
    ReasoningCategory.SECURITY_INVARIANT_HYPOTHESIS: "Security Invariant Hypotheses",
    ReasoningCategory.PRIMITIVE_TRIAGE: "Primitive Triage",
    ReasoningCategory.MISSING_EVIDENCE: "Missing Evidence",
    ReasoningCategory.SAFE_NEXT_STEP: "Safe Next Steps",
}
_CATEGORY_ORDER = [
    ReasoningCategory.HIGH_VALUE_SURFACE,
    ReasoningCategory.SECURITY_INVARIANT_HYPOTHESIS,
    ReasoningCategory.PRIMITIVE_TRIAGE,
    ReasoningCategory.MISSING_EVIDENCE,
    ReasoningCategory.SAFE_NEXT_STEP,
]


def render_reasoning_brief(result: ReasoningResult) -> str:
    lines = [
        "# InvariantOS Reasoning Brief",
        "",
        "## Scope and Safety",
        "",
        "This brief is limited to authorized local repository analysis. It summarizes deterministic reasoning candidates and hypotheses only; it does not prove exploitability.",
        f"Core principle: {result.safety.principle}",
        "",
        "## Source Audit",
        "",
        f"- Project: `{result.source_project.name}`",
        f"- Root: `{result.source_project.root}`",
        f"- Source audit file: `{result.source_audit_file}`",
        f"- Source schema version: `{result.source_schema_version}`",
        f"- Reasoning schema version: `{result.schema_version}`",
        "",
        "## Summary",
        "",
        f"- High-value surfaces: {result.summary.high_value_surfaces}",
        f"- Security invariant hypotheses: {result.summary.invariant_hypotheses}",
        f"- Primitive triage items: {result.summary.primitive_triage_items}",
        f"- Missing evidence items: {result.summary.missing_evidence_items}",
        f"- Safe next steps: {result.summary.safe_next_steps}",
        "",
        *_render_category_sections(result.items),
        "## Appendix: Reasoning Items",
        "",
        *_render_all_items(result.items),
        "",
    ]
    return "\n".join(lines)


def _render_category_sections(items: list[ReasoningItem]) -> list[str]:
    lines: list[str] = []
    for category in _CATEGORY_ORDER:
        lines.extend(
            [
                f"## {_CATEGORY_TITLES[category]}",
                "",
                *_render_items([item for item in items if item.category == category]),
                "",
            ]
        )
    return lines


def _render_all_items(items: list[ReasoningItem]) -> list[str]:
    if not items:
        return ["No reasoning items were generated."]
    return [_render_item(item) for item in items]


def _render_items(items: list[ReasoningItem]) -> list[str]:
    if not items:
        return ["No reasoning items were generated for this category."]
    return [_render_item(item) for item in items]


def _render_item(item: ReasoningItem) -> str:
    return (
        f"- `{item.id}` {item.title} ({item.confidence.value} confidence). "
        f"{item.summary} Related IDs: {_join_or_none(item.related_ids)}. "
        f"Evidence: {_join_or_none(item.evidence_ids)}. "
        f"Missing evidence: {_join_or_none(item.missing_evidence)}. "
        f"Safe next steps: {_join_or_none(item.safe_next_steps)}"
    )


def _join_or_none(values: list[str]) -> str:
    return "; ".join(f"`{value}`" for value in values) if values else "none recorded"
