from pathlib import Path
from typing import Annotated

from pydantic import ValidationError
import typer
from rich.console import Console

from invariant_os.core.audit import run_audit
from invariant_os.core.config import AuditConfig, apply_output_dir_ignore, load_audit_config
from invariant_os.core.models import AuditResult, PatchDiffInputType
from invariant_os.core.output import write_audit_outputs
from invariant_os.core.safety import validate_local_repo_path
from invariant_os.patchdiff.engine import build_patch_diff_result
from invariant_os.patchdiff.gitdiff import collect_git_diff
from invariant_os.patchdiff.output import write_patch_diff_outputs
from invariant_os.patchdiff.parser import parse_unified_diff
from invariant_os.reasoning import build_reasoning_result
from invariant_os.reasoning.output import write_reasoning_outputs


app = typer.Typer(help="InvariantOS local-first security research workbench.")
console = Console()


@app.callback()
def main() -> None:
    """InvariantOS local-first security research workbench."""


def _audit_config(
    repo: Path,
    output_dir: Path,
    max_file_bytes: int | None,
    config_path: Path | None,
) -> AuditConfig:
    config = load_audit_config(repo, config_path, max_file_bytes=max_file_bytes)
    return apply_output_dir_ignore(config, repo, output_dir)


def _validate_local_json_file(path_value: str) -> Path:
    raw = path_value.strip()
    if not raw or _is_url_like(raw):
        raise ValueError("reason input must be a local JSON file")
    resolved = Path(raw).expanduser().resolve()
    if not resolved.is_file() or resolved.suffix.lower() != ".json":
        raise ValueError("reason input must be a local JSON file")
    return resolved


def _validate_local_patch_file(path_value: Path | None) -> Path:
    if path_value is None:
        raise ValueError("patch input must be a local patch file")
    raw = str(path_value).strip()
    if not raw or _is_url_like(raw):
        raise ValueError("patch input must be a local patch file")
    resolved = path_value.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError("patch input must be a local patch file")
    return resolved


def _validate_local_repo_dir(path_value: Path | None) -> Path:
    if path_value is None:
        raise ValueError("git diff input must reference local refs in a local repository")
    raw = str(path_value).strip()
    if not raw or _is_url_like(raw):
        raise ValueError("git diff input must reference local refs in a local repository")
    resolved = path_value.expanduser().resolve()
    if not resolved.is_dir():
        raise ValueError("git diff input must reference local refs in a local repository")
    return resolved


def _is_url_like(value: str) -> bool:
    return value.lower().startswith(("http://", "https://", "http:/", "https:/"))


def _is_git_diff_mode(repo_path: Path | None, base_ref: str | None, head_ref: str | None) -> bool:
    return repo_path is not None and base_ref is not None and head_ref is not None


@app.command()
def audit(
    repo_path: str,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="Directory for generated audit artifacts."),
    ] = Path("outputs"),
    max_file_bytes: Annotated[
        int | None,
        typer.Option("--max-file-bytes", help="Skip files larger than this many bytes."),
    ] = None,
    config_path: Annotated[
        Path | None,
        typer.Option("--config", help="Path to invariant-os YAML config file."),
    ] = None,
) -> None:
    """Run an audit against an authorized local directory."""
    try:
        repo = validate_local_repo_path(repo_path)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    if output_dir.resolve() == repo:
        raise typer.BadParameter("output directory must not be the audited repository root")

    try:
        config = _audit_config(repo, output_dir, max_file_bytes, config_path)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    result = run_audit(repo, config)
    json_path, markdown_path, graph_path, html_path, sarif_path = write_audit_outputs(result, output_dir)

    console.print("InvariantOS audit complete")
    console.print(f"Files indexed: {result.summary.files}")
    console.print(f"Entrypoints: {result.summary.entrypoints}")
    console.print(f"Workers: {result.summary.workers}")
    console.print(f"Boundaries: {result.summary.boundaries}")
    console.print(f"Primitive candidates: {result.summary.primitive_candidates}")
    console.print(f"JSON: {json_path}")
    console.print(f"Markdown: {markdown_path}")
    console.print(f"Evidence graph: {graph_path}")
    console.print(f"Evidence viewer: {html_path}")
    console.print(f"SARIF: {sarif_path}")


@app.command()
def reason(
    audit_result_path: str,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory for generated reasoning artifacts."),
    ] = None,
) -> None:
    """Run offline reasoning over an existing audit_result.json artifact."""
    try:
        audit_path = _validate_local_json_file(audit_result_path)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    try:
        audit_result = AuditResult.model_validate_json(audit_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as error:
        raise typer.BadParameter("input must be a valid InvariantOS audit_result.json") from error

    target_dir = output_dir or audit_path.parent
    reasoning_result = build_reasoning_result(audit_result, str(audit_path))
    json_path, markdown_path = write_reasoning_outputs(reasoning_result, target_dir)

    console.print("InvariantOS reasoning complete")
    console.print(f"Reasoning items: {len(reasoning_result.items)}")
    console.print(f"Reasoning JSON: {json_path}")
    console.print(f"Reasoning Markdown: {markdown_path}")


@app.command("patch-diff")
def patch_diff(
    audit_result_path: str,
    patch_file: Annotated[
        Path | None,
        typer.Option("--patch-file", help="Local unified patch file to analyze."),
    ] = None,
    repo_path: Annotated[
        Path | None,
        typer.Option("--repo-path", help="Local git repository for git diff input."),
    ] = None,
    base_ref: Annotated[
        str | None,
        typer.Option("--base-ref", help="Local base ref for git diff input."),
    ] = None,
    head_ref: Annotated[
        str | None,
        typer.Option("--head-ref", help="Local head ref for git diff input."),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory for generated patch-diff artifacts."),
    ] = None,
) -> None:
    """Run local patch-diff analysis over an existing audit_result.json artifact."""
    try:
        audit_path = _validate_local_json_file(audit_result_path)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    try:
        audit_result = AuditResult.model_validate_json(audit_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as error:
        raise typer.BadParameter("input must be a valid InvariantOS audit_result.json") from error

    patch_file_mode = patch_file is not None
    git_diff_mode = _is_git_diff_mode(repo_path, base_ref, head_ref)
    if patch_file_mode == git_diff_mode:
        raise typer.BadParameter(
            "patch-diff requires exactly one patch input mode: --patch-file or --repo-path with --base-ref and --head-ref"
        )

    try:
        if patch_file_mode:
            resolved_patch_file = _validate_local_patch_file(patch_file)
            diff_text = resolved_patch_file.read_text(encoding="utf-8")
            changed_files = parse_unified_diff(diff_text)
            patch_result = build_patch_diff_result(
                audit_result,
                str(audit_path),
                changed_files,
                input_type=PatchDiffInputType.PATCH_FILE,
                patch_file=str(resolved_patch_file),
            )
        else:
            resolved_repo = _validate_local_repo_dir(repo_path)
            diff_text = collect_git_diff(resolved_repo, base_ref or "", head_ref or "")
            changed_files = parse_unified_diff(diff_text)
            patch_result = build_patch_diff_result(
                audit_result,
                str(audit_path),
                changed_files,
                input_type=PatchDiffInputType.GIT_DIFF,
                repo_path=str(resolved_repo),
                base_ref=base_ref,
                head_ref=head_ref,
            )
    except (OSError, ValueError) as error:
        raise typer.BadParameter(str(error)) from error

    json_path, markdown_path = write_patch_diff_outputs(patch_result, output_dir or audit_path.parent)

    console.print("InvariantOS patch diff analysis complete")
    console.print(f"Changed files: {patch_result.summary.changed_files}")
    console.print(f"Hunks: {patch_result.summary.hunks}")
    console.print(f"Correlations: {patch_result.summary.correlations}")
    console.print(f"Variant candidates: {patch_result.summary.variant_candidates}")
    console.print(f"Patch diff JSON: {json_path}")
    console.print(f"Patch diff Markdown: {markdown_path}")


if __name__ == "__main__":
    app()
