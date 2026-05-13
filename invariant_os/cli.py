from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from invariant_os.core.audit import run_audit
from invariant_os.core.config import AuditConfig
from invariant_os.core.output import write_audit_outputs
from invariant_os.core.safety import validate_local_repo_path


app = typer.Typer(help="InvariantOS local-first security research workbench.")
console = Console()


@app.callback()
def main() -> None:
    """InvariantOS local-first security research workbench."""


def _audit_config(repo: Path, output_dir: Path, max_file_bytes: int) -> AuditConfig:
    config = AuditConfig(max_file_bytes=max_file_bytes)
    resolved_output_dir = output_dir.resolve()
    try:
        relative_output = resolved_output_dir.relative_to(repo)
    except ValueError:
        return config
    if relative_output.parts:
        config.ignore_paths.add(resolved_output_dir)
    return config


@app.command()
def audit(
    repo_path: str,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="Directory for audit_result.json and research_brief.md."),
    ] = Path("outputs"),
    max_file_bytes: Annotated[
        int,
        typer.Option("--max-file-bytes", help="Skip files larger than this many bytes."),
    ] = 1_000_000,
) -> None:
    """Run an audit against an authorized local directory."""
    try:
        repo = validate_local_repo_path(repo_path)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    if output_dir.resolve() == repo:
        raise typer.BadParameter("output directory must not be the audited repository root")

    result = run_audit(repo, _audit_config(repo, output_dir, max_file_bytes))
    json_path, markdown_path = write_audit_outputs(result, output_dir)

    console.print("InvariantOS audit complete")
    console.print(f"Files indexed: {result.summary.files}")
    console.print(f"Entrypoints: {result.summary.entrypoints}")
    console.print(f"Workers: {result.summary.workers}")
    console.print(f"Boundaries: {result.summary.boundaries}")
    console.print(f"Primitive candidates: {result.summary.primitive_candidates}")
    console.print(f"JSON: {json_path}")
    console.print(f"Markdown: {markdown_path}")


if __name__ == "__main__":
    app()
