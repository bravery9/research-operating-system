from invariant_os.core.models import (
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
)
from invariant_os.report.markdown import render_research_brief


REQUIRED_SECTIONS = [
    "# InvariantOS Research Brief",
    "## Scope and Safety",
    "## Summary",
    "## Repository Profile",
    "## Entrypoints",
    "## Worker and Background Job Candidates",
    "## Dangerous Consumer Inventory",
    "## Trust Boundary Candidates",
    "## Primitive Candidates To Investigate",
    "## Suggested Security Invariants",
    "## Missing Evidence",
    "## Safe Manual Review Plan",
    "## Appendix: Evidence Index",
]


def _empty_result() -> AuditResult:
    return AuditResult(
        project=Project(name="empty", root="/tmp/empty"),
        summary=AuditSummary(
            files=0,
            entrypoints=0,
            consumers=0,
            workers=0,
            boundaries=0,
            primitive_candidates=0,
        ),
        safety=SafetyMetadata(),
    )


def test_research_brief_contains_required_sections_and_safety_statement():
    markdown = render_research_brief(_empty_result())

    for section in REQUIRED_SECTIONS:
        assert section in markdown
    assert "authorized local repository analysis" in markdown
    assert "does not prove exploitability" in markdown


def test_research_brief_references_evidence_ids_and_missing_evidence():
    evidence = Evidence(
        id="ev_test_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=12,
        pattern="open(",
        snippet="open(user_path, 'w')",
    )
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where data reaches file-system operations.",
        evidence=[evidence],
    )
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.MEDIUM,
        evidence=[evidence],
        missing_evidence=["confirm whether the file path is data-influenced"],
        safe_next_steps=["Trace a benign sample path through the write call."],
    )
    result = _empty_result().model_copy(
        update={
            "boundaries": [boundary],
            "primitive_candidates": [primitive],
            "summary": AuditSummary(
                files=1,
                entrypoints=0,
                consumers=0,
                workers=0,
                boundaries=1,
                primitive_candidates=1,
            ),
        }
    )

    markdown = render_research_brief(result)

    assert "ev_test_0001" in markdown
    assert "confirm whether the file path is data-influenced" in markdown
    assert "boundary_0001" in markdown
    assert "primitive_0001" in markdown


def test_research_brief_uses_candidate_language_without_confirmed_exploitability_claims():
    markdown = render_research_brief(_empty_result()).lower()

    assert "candidate" in markdown or "hypothesis" in markdown
    assert "confirmed exploitability" not in markdown
    assert "confirmed exploitable" not in markdown
    assert "exploit payload" not in markdown
