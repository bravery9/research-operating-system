"""Core audit orchestration for local repository analysis."""

from pathlib import Path

from invariant_os.analysis.boundary import infer_boundaries
from invariant_os.analysis.detectors import detect_consumers, detect_entrypoints, detect_workers
from invariant_os.analysis.flow import enrich_static_flows
from invariant_os.analysis.graph import build_evidence_graph
from invariant_os.analysis.indexer import index_repository
from invariant_os.analysis.primitives import classify_primitives
from invariant_os.core.config import AuditConfig
from invariant_os.core.focus import (
    parse_focus_mode,
    score_boundary_focus,
    score_primitive_focus,
    score_static_flow_focus,
    summarize_focus_matches,
)
from invariant_os.core.models import AuditResult, AuditSummary, FocusMetadata, Project, SafetyMetadata


def run_audit(repo_path: Path, config: AuditConfig) -> AuditResult:
    """Run the deterministic local audit pipeline without invoking an LLM."""
    repo_root = Path(repo_path).resolve()
    files = index_repository(repo_root, config)
    entrypoints = detect_entrypoints(repo_root, files, config)
    consumers = detect_consumers(repo_root, files, config)
    workers = detect_workers(repo_root, files, config)
    boundaries = infer_boundaries(entrypoints, consumers, workers)
    primitive_candidates = classify_primitives(boundaries, consumers, workers)
    static_flow_candidates = enrich_static_flows(
        repo_root=repo_root,
        files=files,
        entrypoints=entrypoints,
        consumers=consumers,
        workers=workers,
        max_candidates_total=config.flow.max_candidates_total,
        max_candidates_per_entrypoint=config.flow.max_candidates_per_entrypoint,
    )
    evidence_graph = build_evidence_graph(
        files=files,
        entrypoints=entrypoints,
        consumers=consumers,
        workers=workers,
        boundaries=boundaries,
        primitive_candidates=primitive_candidates,
        static_flow_candidates=static_flow_candidates,
    )

    summary = AuditSummary(
        files=len(files),
        entrypoints=len(entrypoints),
        consumers=len(consumers),
        workers=len(workers),
        boundaries=len(boundaries),
        primitive_candidates=len(primitive_candidates),
        static_flow_candidates=len(static_flow_candidates),
    )
    focus_mode = parse_focus_mode(getattr(config.focus, "mode", "all"))
    boundary_focus_metadata = [score_boundary_focus(boundary, focus_mode) for boundary in boundaries]
    primitive_focus_metadata = [
        score_primitive_focus(candidate, focus_mode) for candidate in primitive_candidates
    ]
    static_flow_focus_metadata = [
        score_static_flow_focus(candidate, focus_mode) for candidate in static_flow_candidates
    ]
    focus_summary = summarize_focus_matches(
        mode=focus_mode,
        boundary_metadata=boundary_focus_metadata,
        primitive_metadata=primitive_focus_metadata,
        static_flow_metadata=static_flow_focus_metadata,
    )
    focus = FocusMetadata(**focus_summary.__dict__)

    return AuditResult(
        project=Project(name=config.project.name or repo_root.name, root=repo_root.as_posix()),
        files=files,
        entrypoints=entrypoints,
        consumers=consumers,
        workers=workers,
        boundaries=boundaries,
        primitive_candidates=primitive_candidates,
        static_flow_candidates=static_flow_candidates,
        evidence_graph=evidence_graph,
        focus=focus,
        summary=summary,
        safety=SafetyMetadata(),
    )
