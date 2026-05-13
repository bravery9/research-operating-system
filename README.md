# InvariantOS

InvariantOS is a local-first security research workbench for authorized repository analysis. It indexes source files, detects entrypoints and dangerous consumers, infers candidate trust boundaries, and produces conservative research artifacts for human review.

Core principle: LLM proposes. Tools prove. Human approves.

## Safety Model

InvariantOS v0.1 only analyzes local directories that the operator is authorized to review. Reports use candidate, hypothesis, and missing-evidence language. The tool does not scan public targets, generate exploit payloads, or claim exploitability.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## Quickstart

```bash
invariant-os audit /path/to/local/repo --output-dir outputs
```

For development from this repository:

```bash
.venv/bin/python -m invariant_os.cli audit tests/fixtures/mini_express_app --output-dir outputs
```

## Commands

### `audit`

Run a deterministic local audit pipeline against an authorized local directory.

Options:

- `--output-dir`: directory for generated artifacts. Defaults to `outputs`.
- `--max-file-bytes`: skip files larger than this value. Defaults to `1000000`.

## Output Files

- `audit_result.json`: stable structured audit output containing indexed files, detections, boundary candidates, primitive candidates, summary counts, and safety metadata.
- `research_brief.md`: Markdown research brief with scope, summary, candidates, missing evidence, safe manual review steps, and an evidence index.

## Supported Detection Areas

- HTTP routes, webhooks, GraphQL-like handlers, and framework route patterns.
- Worker, queue, event-consumer, background-task, and cron-like candidates.
- File, network, process, template, deserialization, configuration, queue, archive, and parser consumers.
- Trust boundary candidates such as request-to-worker, data-to-file, data-to-url, data-to-template, data-to-config, data-to-job, external-to-internal, low-privilege-to-privileged-consumer, and parser-to-consumer.
- Primitive candidates such as file/path control, URL control, internal request trigger, template control, type control, job control, configuration control, cache/session concerns, auth-context confusion, tenant confusion, and parser differentials.

## Limitations

- Static heuristics can miss code paths and can produce false positives.
- Findings are candidates for review, not vulnerability confirmations.
- The audit pipeline does not execute application code.
- The audit pipeline does not call an LLM in v0.1.
- Human review is required before security conclusions or code changes.

## Roadmap

- Add richer language and framework detectors.
- Add optional LLM-assisted hypothesis generation behind the existing safety model.
- Add evidence graphing and data-flow enrichment.
- Add SARIF and additional export formats.
- Add configuration files for per-repository detector tuning.
