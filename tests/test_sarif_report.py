import json

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
    StaticFlowCandidate,
    StaticFlowSignal,
    StaticFlowSignalType,
    StaticFlowTargetType,
)
from invariant_os.report.sarif import render_sarif


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
            static_flow_candidates=0,
        ),
        safety=SafetyMetadata(),
    )


def _evidence(evidence_id: str = "ev_sarif_0001") -> Evidence:
    return Evidence(
        id=evidence_id,
        type=EvidenceType.PATTERN_MATCH,
        file="app.py",
        line=12,
        pattern="open(",
        snippet="open(user_path, 'w')",
        message="Candidate file operation evidence",
    )


def test_sarif_empty_audit_has_required_shape():
    sarif = render_sarif(_empty_result())

    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "InvariantOS"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["properties"] == {
        "deterministic": True,
        "localOnly": True,
        "noLlmProviders": True,
        "noNetwork": True,
        "noSemgrepExecution": True,
        "noTargetExecution": True,
    }


def test_sarif_renders_primitive_candidate_with_evidence_location():
    evidence = _evidence()
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.FILE_WRITE,
        confidence=Confidence.HIGH,
        evidence=[evidence],
        missing_evidence=["confirm whether request data controls the path"],
        safe_next_steps=["Trace a benign sample path through the write call."],
    )
    result = _empty_result().model_copy(
        update={
            "primitive_candidates": [primitive],
            "summary": AuditSummary(
                files=1,
                entrypoints=0,
                consumers=0,
                workers=0,
                boundaries=0,
                primitive_candidates=1,
                static_flow_candidates=0,
            ),
        }
    )

    sarif = render_sarif(result)
    run = sarif["runs"][0]

    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "invariant-os.primitive.file_write"
    ]
    assert len(run["results"]) == 1
    sarif_result = run["results"][0]
    assert sarif_result["ruleId"] == "invariant-os.primitive.file_write"
    assert sarif_result["level"] == "warning"
    assert "Manual review candidate" in sarif_result["message"]["text"]
    assert "confirmation" in sarif_result["message"]["text"]
    assert sarif_result["properties"]["candidateId"] == "primitive_0001"
    assert sarif_result["properties"]["evidenceIds"] == ["ev_sarif_0001"]
    assert sarif_result["properties"]["missingEvidence"] == [
        "confirm whether request data controls the path"
    ]
    assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_sarif_renders_boundary_and_static_flow_candidates_conservatively():
    boundary_evidence = _evidence("ev_boundary_0001")
    flow_evidence = Evidence(
        id="ev_flow_0001",
        type=EvidenceType.PATTERN_MATCH,
        file="routes.xml",
        line=4,
        pattern="product_api_xml",
        snippet="SERVLET_CLASS_NAME=com.example.ReportServlet",
    )
    boundary = BoundaryCandidate(
        id="boundary_0001",
        type=BoundaryType.DATA_TO_FILE,
        confidence=Confidence.MEDIUM,
        reason="Candidate boundary where data reaches file-system operations.",
        evidence=[boundary_evidence],
    )
    flow = StaticFlowCandidate(
        id="flow_0001",
        source_entrypoint_id="ep_0001",
        target_ref_id="cons_0001",
        target_type=StaticFlowTargetType.CONSUMER,
        confidence=Confidence.HIGH,
        score=110,
        summary="Candidate static flow from `ep_0001` to `cons_0001` based on handler overlap.",
        signals=[
            StaticFlowSignal(
                type=StaticFlowSignalType.HANDLER_CLASS,
                term="ReportServlet",
                score=60,
                evidence_ids=["ev_flow_0001"],
            )
        ],
        evidence=[flow_evidence],
        missing_evidence=["confirm runtime dispatch"],
    )
    result = _empty_result().model_copy(
        update={
            "boundaries": [boundary],
            "static_flow_candidates": [flow],
            "summary": AuditSummary(
                files=2,
                entrypoints=1,
                consumers=1,
                workers=0,
                boundaries=1,
                primitive_candidates=0,
                static_flow_candidates=1,
            ),
        }
    )

    sarif = render_sarif(result)
    results = sarif["runs"][0]["results"]

    assert [item["ruleId"] for item in results] == [
        "invariant-os.boundary.data_to_file",
        "invariant-os.static-flow.consumer",
    ]
    boundary_result, flow_result = results
    assert boundary_result["level"] == "note"
    assert boundary_result["properties"]["candidateId"] == "boundary_0001"
    assert "manual review" in boundary_result["message"]["text"].lower()
    assert flow_result["level"] == "warning"
    assert flow_result["properties"]["candidateId"] == "flow_0001"
    assert flow_result["properties"]["sourceEntrypointId"] == "ep_0001"
    assert flow_result["properties"]["targetRefId"] == "cons_0001"
    assert flow_result["properties"]["score"] == 110
    assert flow_result["properties"]["signals"] == [
        {
            "evidenceIds": ["ev_flow_0001"],
            "score": 60,
            "term": "ReportServlet",
            "type": "handler_class",
        }
    ]
    assert flow_result["properties"]["missingEvidence"] == ["confirm runtime dispatch"]


def test_sarif_output_is_deterministic_and_uses_safe_language():
    evidence = _evidence()
    primitive = PrimitiveCandidate(
        id="primitive_0001",
        primitive=PrimitiveType.PATH_CONTROL,
        confidence=Confidence.MEDIUM,
        evidence=[evidence],
    )
    result = _empty_result().model_copy(update={"primitive_candidates": [primitive]})

    first = json.dumps(render_sarif(result), sort_keys=True)
    second = json.dumps(render_sarif(result), sort_keys=True)

    assert first == second
    lowered = first.lower()
    assert "candidate" in lowered or "manual review" in lowered
    assert "confirmed vulnerable" not in lowered
    assert "confirmed exploitable" not in lowered
    assert "confirmed exploitability" not in lowered
    assert "exploitability proved" not in lowered
    assert "exploit payload" not in lowered
    assert "payload to exploit" not in lowered
