# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
.venv/bin/pytest

# Run focused suites
.venv/bin/pytest tests/test_models.py -v
.venv/bin/pytest tests/test_config.py -v
.venv/bin/pytest tests/test_audit_config.py -v
.venv/bin/pytest tests/test_sarif_report.py -v
.venv/bin/pytest tests/test_html_report.py -v
.venv/bin/pytest tests/test_audit_cli.py -v
.venv/bin/pytest tests/test_reasoning_models.py -v
.venv/bin/pytest tests/test_reasoning_engine.py -v
.venv/bin/pytest tests/test_reasoning_report.py -v
.venv/bin/pytest tests/test_reasoning_output.py -v
.venv/bin/pytest tests/test_reason_cli.py -v
.venv/bin/pytest tests/test_patchdiff_parser.py -v
.venv/bin/pytest tests/test_patchdiff_gitdiff.py -v
.venv/bin/pytest tests/test_patchdiff_engine.py -v
.venv/bin/pytest tests/test_patchdiff_report.py -v
.venv/bin/pytest tests/test_patchdiff_output.py -v
.venv/bin/pytest tests/test_patchdiff_cli.py -v

# Run one test
.venv/bin/pytest tests/test_flow.py::test_static_flow_links_exact_handler_to_taskengine_worker -v

# Quality gates
.venv/bin/ruff check .
.venv/bin/mypy invariant_os

# Smoke audit, reasoning, and patch-diff workflow
.venv/bin/invariant-os audit tests/fixtures/mini_tomcat_app --output-dir outputs/mini-tomcat-v07
.venv/bin/invariant-os audit tests/fixtures/mini_tomcat_app --config <local-invariant-os.yml> --output-dir outputs/config-smoke
.venv/bin/invariant-os reason outputs/mini-tomcat-v07/audit_result.json --output-dir outputs/mini-tomcat-v07
.venv/bin/invariant-os patch-diff outputs/mini-tomcat-v07/audit_result.json --patch-file <local-benign.patch> --output-dir outputs/mini-tomcat-v07
```

## Project intent and safety boundaries

InvariantOS is a local-first security research workbench for authorized repository analysis. Preserve the core principle:

```text
LLM proposes. Tools prove. Human approves.
```

Allowed work: local repo analysis, static analysis, threat modeling, trust-boundary mapping, primitive classification, static candidate generation, deterministic offline reasoning over audit artifacts, local patch-diff correlation against audit evidence, safe manual review planning, defensive fixes, regression tests, and report writing.

Out of scope: public target scanning, exploit automation, weaponized payload generation, credential theft, persistence/evasion, destructive payloads, mass targeting, target code execution, hosted scanning, network LLM reasoning providers, or vulnerability/exploitability confirmations.

## High-level architecture

The implemented CLI workflow is:

```text
local authorized repo
→ optional local invariant-os.yml config loading
→ deterministic indexing
→ entrypoint / consumer / worker detectors
→ trust-boundary inference
→ primitive candidate classification
→ bounded static flow/dataflow enrichment
→ evidence graph projection
→ local audit artifacts including SARIF export
→ optional deterministic offline reasoning over audit_result.json
→ optional deterministic local patch-diff correlation against audit_result.json
→ local reasoning and patch-diff artifacts for human review
```

Key components:

- `invariant_os/cli.py`: Typer CLI entrypoint for `invariant-os audit`, `invariant-os reason`, and `invariant-os patch-diff`.
- `invariant_os/core/`: audit orchestration, local YAML config loading/tuning, safety checks, output writing, and Pydantic domain models.
- `invariant_os/detectors/`: deterministic detectors for entrypoints, consumers, workers, enterprise Java/Tomcat/ManageEngine XML, and related patterns.
- `invariant_os/analysis/`: boundary inference, primitive classification, enterprise route correlation, graph building, and static flow enrichment.
- `invariant_os/reasoning/`: deterministic offline reasoning engine and output writer for `reason_result.json` and `reasoning_brief.md`.
- `invariant_os/patchdiff/`: deterministic local unified-diff parsing, constrained git-diff collection, patch-to-audit correlation, and output writing.
- `invariant_os/report/`: Markdown research brief, static HTML evidence workspace, reasoning brief, and patch-diff brief renderers.
- `tests/fixtures/`: compact apps used to verify Express, Tomcat, enterprise XML, workers, consumers, graph, flow, reasoning, and patch-diff behavior.

Generated audit artifacts:

```text
outputs/audit_result.json
outputs/audit_result.sarif.json
outputs/research_brief.md
outputs/evidence_graph.json
outputs/evidence_viewer.html
```

Generated reasoning artifacts:

```text
outputs/reason_result.json
outputs/reasoning_brief.md
```

Generated patch-diff artifacts:

```text
outputs/patch_diff_result.json
outputs/patch_diff_brief.md
```

## Reporting guidance

All outputs must remain local, evidence-oriented, and conservative. Use candidate/hypothesis/missing-evidence language. Every substantive claim should point to evidence IDs or explicitly describe missing evidence. The static evidence viewer is a self-contained local HTML file. SARIF output is a deterministic local projection of existing audit evidence for manual review; it is not Semgrep output, must not run Semgrep, and must not imply confirmed vulnerability or exploitability. The `audit` command may load local YAML config for indexing, detector tuning, and static-flow caps, but config files must not execute code, fetch network resources, enable LLM providers, or run Semgrep in the current implementation. The `reason` command reads structured audit JSON only and uses deterministic offline reasoning. The `patch-diff` command consumes local audit JSON plus local patch or git-diff input only; it must not apply patches, check out refs, fetch network resources, or execute target code. Do not add a server, remote assets, browser automation, live/network LLM calls, public scanning, target execution, exploit steps, exploit payload generation, or vulnerability/exploitability confirmations.
