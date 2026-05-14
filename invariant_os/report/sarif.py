from typing import Any

from invariant_os.core.models import (
    AuditResult,
    BoundaryCandidate,
    Confidence,
    Evidence,
    PrimitiveCandidate,
    StaticFlowCandidate,
)


def render_sarif(result: AuditResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = [
        *_boundary_results(result.boundaries, rules),
        *_primitive_results(result.primitive_candidates, rules),
        *_static_flow_results(result.static_flow_candidates, rules),
    ]
    results.sort(key=_result_sort_key)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "InvariantOS",
                        "rules": [rules[rule_id] for rule_id in sorted(rules)],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "deterministic": True,
                            "localOnly": True,
                            "noLlmProviders": True,
                            "noNetwork": True,
                            "noSemgrepExecution": True,
                            "noTargetExecution": True,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def _primitive_results(
    candidates: list[PrimitiveCandidate], rules: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        rule_id = f"invariant-os.primitive.{candidate.primitive.value}"
        _add_rule(
            rules,
            rule_id,
            f"Primitive candidate: {candidate.primitive.value}",
            "Manual review candidate identified from local static evidence.",
        )
        results.append(
            _build_result(
                rule_id=rule_id,
                level=_level(candidate.confidence),
                message=(
                    f"Manual review candidate: {candidate.primitive.value} signal observed. "
                    "This is not a security-impact confirmation."
                ),
                candidate_id=candidate.id,
                evidence=candidate.evidence,
                properties={
                    "category": "primitive",
                    "confidence": candidate.confidence.value,
                    "primitive": candidate.primitive.value,
                    "missingEvidence": candidate.missing_evidence,
                    "safeNextSteps": candidate.safe_next_steps,
                },
            )
        )
    return results


def _boundary_results(
    candidates: list[BoundaryCandidate], rules: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        if not candidate.evidence:
            continue
        rule_id = f"invariant-os.boundary.{candidate.type.value}"
        _add_rule(
            rules,
            rule_id,
            f"Trust-boundary candidate: {candidate.type.value}",
            "Manual review candidate for a local static trust-boundary signal.",
        )
        results.append(
            _build_result(
                rule_id=rule_id,
                level="note",
                message="Trust-boundary candidate for manual review based on static evidence.",
                candidate_id=candidate.id,
                evidence=candidate.evidence,
                properties={
                    "category": "boundary",
                    "boundaryType": candidate.type.value,
                    "confidence": candidate.confidence.value,
                    "reason": candidate.reason,
                },
            )
        )
    return results


def _static_flow_results(
    candidates: list[StaticFlowCandidate], rules: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for candidate in sorted(candidates, key=lambda item: item.id):
        rule_id = f"invariant-os.static-flow.{candidate.target_type.value}"
        _add_rule(
            rules,
            rule_id,
            f"Static flow candidate: {candidate.target_type.value}",
            "Manual review candidate for a bounded local static flow signal.",
        )
        results.append(
            _build_result(
                rule_id=rule_id,
                level=_level(candidate.confidence),
                message="Static flow candidate for manual review; missing evidence is preserved in properties.",
                candidate_id=candidate.id,
                evidence=candidate.evidence,
                properties={
                    "category": "static-flow",
                    "confidence": candidate.confidence.value,
                    "missingEvidence": candidate.missing_evidence,
                    "score": candidate.score,
                    "signals": [
                        {
                            "evidenceIds": signal.evidence_ids,
                            "score": signal.score,
                            "term": signal.term,
                            "type": signal.type.value,
                        }
                        for signal in candidate.signals
                    ],
                    "sourceEntrypointId": candidate.source_entrypoint_id,
                    "summary": candidate.summary,
                    "targetRefId": candidate.target_ref_id,
                    "targetType": candidate.target_type.value,
                },
            )
        )
    return results


def _add_rule(rules: dict[str, dict[str, Any]], rule_id: str, name: str, description: str) -> None:
    if rule_id in rules:
        return
    rules[rule_id] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": description},
        "properties": {
            "precision": "informational",
            "security-severity": "0.0",
        },
    }


def _build_result(
    *,
    rule_id: str,
    level: str,
    message: str,
    candidate_id: str,
    evidence: list[Evidence],
    properties: dict[str, Any],
) -> dict[str, Any]:
    evidence_ids = [item.id for item in evidence]
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "properties": {
            **properties,
            "candidateId": candidate_id,
            "evidenceIds": evidence_ids,
        },
        "partialFingerprints": {
            "invariantOsCandidate": _fingerprint(candidate_id, rule_id, evidence),
        },
    }

    locations = _locations(evidence)
    if locations:
        result["locations"] = [locations[0]]
    if len(locations) > 1:
        result["relatedLocations"] = [
            {"id": index, **location} for index, location in enumerate(locations[1:], start=1)
        ]
    return result


def _locations(evidence: list[Evidence]) -> list[dict[str, Any]]:
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": item.file},
                "region": {"startLine": item.line},
            },
            "properties": {"evidenceId": item.id, "evidenceType": item.type.value},
        }
        for item in evidence
        if item.file and item.line > 0
    ]


def _fingerprint(candidate_id: str, rule_id: str, evidence: list[Evidence]) -> str:
    location = evidence[0] if evidence else None
    if location is None:
        return f"{rule_id}:{candidate_id}"
    return f"{rule_id}:{candidate_id}:{location.file}:{location.line}"


def _level(confidence: Confidence) -> str:
    if confidence == Confidence.HIGH:
        return "warning"
    return "note"


def _result_sort_key(result: dict[str, Any]) -> tuple[str, str, str, str, int]:
    properties = result["properties"]
    location = result.get("locations", [{}])[0].get("physicalLocation", {})
    artifact = location.get("artifactLocation", {}).get("uri", "")
    line = location.get("region", {}).get("startLine", 0)
    return (
        properties.get("category", ""),
        result.get("ruleId", ""),
        properties.get("candidateId", ""),
        artifact,
        line,
    )
