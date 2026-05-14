"""Output writers for reasoning artifacts."""

import json
from pathlib import Path

from invariant_os.core.models import ReasoningResult
from invariant_os.report.reasoning_markdown import render_reasoning_brief


def write_reasoning_outputs(result: ReasoningResult, output_dir: Path) -> tuple[Path, Path]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    json_path = target_dir / "reason_result.json"
    markdown_path = target_dir / "reasoning_brief.md"

    json_payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    json_path.write_text(f"{json_payload}\n", encoding="utf-8")
    markdown_path.write_text(render_reasoning_brief(result), encoding="utf-8")

    return json_path, markdown_path
