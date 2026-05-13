"""Core audit orchestration for local repository analysis."""

from pathlib import Path

from invariant_os.analysis.boundary import infer_boundaries
from invariant_os.analysis.detectors import detect_consumers, detect_entrypoints, detect_workers
from invariant_os.analysis.graph import build_evidence_graph
from invariant_os.analysis.indexer import index_repository
from invariant_os.analysis.primitives import classify_primitives
from invariant_os.core.config import AuditConfig
from invariant_os.core.models import AuditResult, AuditSummary, Project, SafetyMetadata


def run_audit(repo_path: Path, config: AuditConfig) -> AuditResult:
    """Run the deterministic local audit pipeline without invoking an LLM."""
    repo_root = Path(repo_path).resolve()
    files = index_repository(repo_root, config)
    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)
    boundaries = infer_boundaries(entrypoints, consumers, workers)
    primitive_candidates = classify_primitives(boundaries, consumers, workers)
    evidence_graph = build_evidence_graph(
        files=files,
        entrypoints=entrypoints,
        consumers=consumers,
        workers=workers,
        boundaries=boundaries,
        primitive_candidates=primitive_candidates,
    )

    summary = AuditSummary(
        files=len(files),
        entrypoints=len(entrypoints),
        consumers=len(consumers),
        workers=len(workers),
        boundaries=len(boundaries),
        primitive_candidates=len(primitive_candidates),
    )

    return AuditResult(
        project=Project(name=repo_root.name, root=repo_root.as_posix()),
        files=files,
        entrypoints=entrypoints,
        consumers=consumers,
        workers=workers,
        boundaries=boundaries,
        primitive_candidates=primitive_candidates,
        evidence_graph=evidence_graph,
        summary=summary,
        safety=SafetyMetadata(),
    )
