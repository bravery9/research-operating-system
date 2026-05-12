# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current repository state

This repository currently contains Markdown planning documents for a local-first authorized security research workbench, referred to as `InvariantOS` / Security Research OS. There is no implemented application source tree, package manifest, README, Cursor rules, or GitHub Copilot instructions yet.

Because the repository is documentation-only at the moment, there are no current build, lint, test, install, or development-server commands to run.

## Commands

Current useful repository commands:

```bash
# Inspect tracked/planned files
git status
find . -maxdepth 2 -type f | sort
```

Planned commands from `plan.md` once the Python CLI implementation exists:

```bash
# Install the planned CLI in editable mode with dev dependencies
pip install -e ".[dev]"

# Run the planned CLI
invariant-os --help
invariant-os audit ./some-authorized-repo
invariant-os reason outputs/audit_result.json
invariant-os report outputs/audit_result.json

# Planned quality gates
ruff check .
mypy invariant_os
pytest

# Planned single-test pattern
pytest tests/test_indexer.py::test_specific_case
```

Treat the planned commands above as design intent, not as runnable commands, until `pyproject.toml`, `invariant_os/`, and `tests/` exist.

## Project intent and safety boundaries

The documents define a tool for authorized local codebase analysis and defensive security research. The repeated product boundary is:

- Allowed: local repo analysis, static analysis, threat modeling, trust-boundary mapping, invariant generation, primitive classification, safe lab validation planning, defensive fixes, regression tests, and report writing.
- Out of scope: public target scanning, exploit automation, weaponized payload generation, credential theft, persistence/evasion, destructive payloads, or mass targeting.

Preserve the core principle used throughout the docs:

```text
LLM proposes. Tools prove. Human approves.
```

## High-level architecture

The planned product is a research workflow, not an auto-exploit scanner. The core pipeline across the docs is:

```text
local authorized repo
→ deterministic analyzers / indexers
→ evidence objects with file/line/symbol references
→ attack surface and trust-boundary model
→ invariant and primitive candidate generation
→ safe manual validation plan
→ report, fix advice, and regression test suggestions
```

Key architectural components described in the planning docs:

- **Repo ingestion/indexing**: Walk a local repository, ignore generated/vendor directories, detect languages/framework hints, and emit stable JSON facts.
- **Entrypoint detection**: Identify HTTP routes, CLI commands, webhooks, GraphQL/RPC handlers, and other places external or user-controlled input enters.
- **Dangerous consumer inventory**: Catalog file, network, process, template, deserialization, config, queue, archive, and parser operations without claiming exploitability.
- **Worker/background-job detection**: Prioritize request-to-worker flows because the docs treat async privileged consumers as high-value research surfaces.
- **Boundary inference**: Infer candidates such as `request_to_worker`, `data_to_file`, `data_to_url`, `data_to_template`, `data_to_config`, `data_to_job`, and `parser_to_consumer` from evidence.
- **Invariant engine**: Generate security invariants like “persisted request data must be revalidated by privileged workers” and “validated URLs must be identical to URLs later requested.”
- **Primitive classifier**: Prefer primitive candidates (`path_control`, `job_control`, `config_control`, `template_control`, `parser_differential`, etc.) over unsupported vulnerability claims.
- **Evidence model**: Every claim or candidate should point to evidence such as code references, pattern matches, boundary rules, static-analysis hits, manual notes, or test results.
- **LLM reasoning layer**: LLMs summarize, hypothesize, rank, explain, plan safe validation, suggest fixes, and draft reports; deterministic tools and tests provide proof.
- **Future UI/graph layer**: The longer-term design includes graph export, a dashboard, trust-boundary graph, finding workspace, evidence viewer, and report exporter.

## Document roles

- `brainstorm.md`: Research mindset and methodology: assumptions, trust boundaries, primitives, chains, and authorized/lab-focused validation.
- `software-architecture.md`: Product architecture for turning the methodology into a Security Research Copilot / Attack Surface Modeling Platform.
- `with-llm.md`: How LLMs fit into the system as a reasoning/orchestration layer with tool-backed evidence and safety controls.
- `plan.md`: A concrete A-to-Z implementation plan for a Python 3.11+ CLI MVP using Typer, Rich, Pydantic, pytest, ruff, mypy, optional Semgrep, and later LLM providers.

## Implementation guidance when code is added

Follow `plan.md` for the initial implementation order: `pyproject.toml`, CLI skeleton, domain models, repo indexer, detectors, boundary inference, report generation, fixtures/tests, then LLM abstractions. Do not start with the web UI, graph database, multi-agent orchestration, browser automation, public scanning, or exploit functionality.

For early code, keep outputs local and evidence-oriented:

```text
outputs/audit_result.json
outputs/research_brief.md
outputs/invariants.json
outputs/primitive_candidates.json
```

When adding LLM support, avoid sending entire repositories by default. Send structured facts from deterministic analysis, require JSON output where appropriate, distinguish fact from hypothesis, and require evidence IDs or missing-evidence notes for every substantive claim.
