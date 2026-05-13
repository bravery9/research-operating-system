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

- `audit_result.json`: stable structured audit output containing indexed files, detections, boundary candidates, primitive candidates, evidence graph, summary counts, and safety metadata.
- `evidence_graph.json`: deterministic graph of candidate relationships between files, entrypoints, workers, consumers, boundaries, primitives, and supporting evidence IDs.
- `research_brief.md`: Markdown research brief with scope, summary, candidates, evidence graph summary, missing evidence, safe manual review steps, and an evidence index.

## Supported Detection Areas

- HTTP routes, webhooks, GraphQL-like handlers, and framework route patterns.
- Enterprise Java/Tomcat descriptors including `WEB-INF/web.xml`, `conf/web.xml`, servlet mappings, security constraints, filters, listeners, and `server.xml` connector candidates.
- ManageEngine/ZSec-style `security-*.xml` URL rules and security controls such as auth/csrf/throttle metadata, headers, cookies, content types, URL validators, XSS patterns, and zip sanitizers.
- Product API XML mappings such as `ADSProductAPIs`, `RMPProductAPIs`, `API_URL`, `MTCALL_*`, `SERVLET_CLASS_NAME`, and servlet-forward XML mappings.
- Java endpoint candidates from `@WebServlet`, JAX-RS `@Path`/HTTP method annotations, SOAP `@WebService`/`@WebMethod`, and conservative legacy handler class names.
- JavaScript and `.cc` URL configuration candidates when route-like strings appear in URL/mapping/action context.
- Worker, queue, event-consumer, background-task, cron-like, and TaskEngine candidates.
- File, network, process, template, deserialization, configuration, queue, archive, parser, database, and directory consumers.
- Trust boundary candidates such as request-to-worker, data-to-file, data-to-url, data-to-template, data-to-config, data-to-job, data-to-database, data-to-directory, external-to-internal, low-privilege-to-privileged-consumer, and parser-to-consumer.
- Primitive candidates such as file/path control, URL control, internal request trigger, template control, type control, job control, query control, directory query control, configuration control, cache/session concerns, auth-context confusion, tenant confusion, and parser differentials.
- Evidence graph generation for candidate same-file, handler-name, Java/Enterprise route-to-worker, Java/Enterprise route-to-consumer, boundary-evidence, and primitive-evidence correlations, with deterministic pruning/ranking to reduce noisy graph output.

## Limitations

- Static heuristics can miss code paths and can produce false positives.
- Enterprise XML and legacy endpoint detections are heuristic inventory candidates and require human review.
- Evidence graph edges are conservative static correlations, not confirmed runtime dataflows.
- Java/Enterprise resolver edges are static candidates based on route, handler, metadata, and evidence-token correlation; they do not prove runtime dispatch or dataflow.
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
