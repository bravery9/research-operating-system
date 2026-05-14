"""Output writers for patch-diff artifacts."""

import json
from pathlib import Path

from invariant_os.core.models import PatchDiffResult
from invariant_os.report.patch_diff_markdown import render_patch_diff_brief


def write_patch_diff_outputs(result: PatchDiffResult, output_dir: Path) -> tuple[Path, Path]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    json_path = target_dir / "patch_diff_result.json"
    markdown_path = target_dir / "patch_diff_brief.md"

    json_payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    json_path.write_text(f"{json_payload}\n", encoding="utf-8")
    markdown_path.write_text(render_patch_diff_brief(result), encoding="utf-8")

    return json_path, markdown_path
