# InvariantOS

InvariantOS is a local-first security research workbench for authorized repository analysis. It indexes source files, detects entrypoints and dangerous consumers, infers candidate trust boundaries, and produces conservative research artifacts for human review.

Core principle: LLM proposes. Tools prove. Human approves.

## Safety Model

InvariantOS analyzes only local directories that the operator is authorized to review. Reports use candidate, hypothesis, and missing-evidence language. The tool does not scan public targets, generate exploit payloads, execute target code, or claim exploitability. The static evidence viewer is a local file artifact; it does not start a server, fetch remote resources, scan targets, execute target code, or generate exploit payloads. SARIF export and review-queue JSONL are generated locally from existing audit evidence as manual-review candidates; they are not Semgrep output and do not run Semgrep. The `reason` command reads structured audit JSON only and runs deterministic offline reasoning without a network LLM provider. The `patch-diff` command consumes only local audit artifacts plus local patch or git-diff data, and does not apply patches, check out refs, fetch network resources, or execute target code.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .[dev]
```

## Quickstart

```bash
invariant-os audit /path/to/local/repo --output-dir outputs
invariant-os reason outputs/audit_result.json --output-dir outputs
invariant-os patch-diff outputs/audit_result.json --patch-file change.patch --output-dir outputs
```

## Current Release Status

The current implementation is a deterministic local artifact pipeline. It includes repository indexing, broad static detector coverage, trust-boundary inference, primitive classification, bounded static-flow enrichment, evidence graph generation, SARIF export, review-queue JSONL export, deterministic offline reasoning, and local patch-diff correlation.

Deferred local-product areas include static evidence-workspace UX improvements, team handoff workflow, fix advisors, and regression-test generation. Live/network LLM providers, Semgrep execution, hosted scanning, target execution, and exploit automation remain outside the current local-first safety model.

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
- `--config`: local `invariant-os.yml` config file for per-repository tuning. If omitted, `<repo>/invariant-os.yml` is loaded when present.

### Configuration

`audit` can load a local YAML config file to tune indexing, detector selection, and bounded static-flow output without changing the safety model:

```yaml
project:
  name: acme-app
  scope: local_authorized_repo

ignore:
  dirs:
    - generated
  paths:
    - fixtures/large

focus:
  files:
    - src/
    - conf/
  detectors:
    entrypoints:
      include: []
      exclude:
        - generic_graphql
    consumers:
      include: []
      exclude: []
    workers:
      include: []
      exclude: []

flow:
  max_candidates_total: 250
  max_candidates_per_entrypoint: 5

llm:
  enabled: false

semgrep:
  enabled: false
```

Precedence is built-in defaults, auto-discovered `<repo>/invariant-os.yml`, explicit `--config`, CLI scalar overrides such as `--max-file-bytes`, then runtime output-directory ignores. Config paths must be local repository-relative paths and detector names must be known built-in pattern names. `llm.enabled` and `semgrep.enabled` must currently remain `false`; config files do not enable network calls, external tool execution, target code execution, exploit payload generation, or vulnerability confirmation.

### `reason`

Run deterministic offline reasoning over an existing InvariantOS `audit_result.json` artifact.

Options:

- `--output-dir`: directory for generated reasoning artifacts. Defaults to the input JSON parent directory.

The v0.6 reasoning layer reads structured audit JSON only. It does not inspect raw source, execute target code, scan public targets, fetch network resources, call a network LLM provider, generate exploit payloads, or confirm vulnerabilities.

### `patch-diff`

Run deterministic local patch-diff analysis against an existing InvariantOS `audit_result.json` artifact.

Analyze a local unified patch file:

```bash
invariant-os patch-diff outputs/audit_result.json --patch-file change.patch --output-dir outputs
```

Analyze a local git diff without checkout or fetch:

```bash
invariant-os patch-diff outputs/audit_result.json --repo-path /path/to/repo --base-ref main --head-ref feature --output-dir outputs
```

Options:

- `--patch-file`: local unified patch file to analyze.
- `--repo-path`: local git repository for git-diff input.
- `--base-ref`: local base ref for git-diff input.
- `--head-ref`: local head ref for git-diff input.
- `--output-dir`: directory for generated patch-diff artifacts. Defaults to the input JSON parent directory.

The v0.7 patch-diff layer parses changed files and hunks, links them to existing audit evidence by local file path and line proximity, and emits conservative patch-adjacent candidates. It does not apply patches, check out refs, fetch network resources, execute target code, use network LLM providers, perform public scanning, generate exploit payloads, or confirm vulnerability/exploitability.

## Output Files

- `audit_result.json`: stable structured audit output containing indexed files, detections, boundary candidates, primitive candidates, static flow/dataflow candidates, evidence graph, summary counts, and safety metadata.
- `audit_result.sarif.json`: deterministic SARIF 2.1.0 export generated from existing audit evidence as conservative manual-review candidates; it is not Semgrep output and does not run Semgrep.
- `audit_review_queue.jsonl`: deterministic line-delimited JSON review queue generated from existing boundary, primitive, and static-flow candidates for local manual triage workflows.
- `evidence_graph.json`: deterministic graph of candidate relationships between files, entrypoints, workers, consumers, boundaries, primitives, static-flow source/target edges, and supporting evidence IDs.
- `research_brief.md`: Markdown research brief with scope, summary, candidates, Static Flow/Dataflow Candidates, evidence graph summary, missing evidence, safe manual review steps, and an evidence index.
- `evidence_viewer.html`: self-contained local Static Evidence Workspace for browsing candidates, static flows, graph links, evidence records, missing evidence, and safe manual review steps without a server or external assets.
- `reason_result.json`: v0.6 structured reasoning output with conservative evidence-linked review hypotheses derived from `audit_result.json`.
- `reasoning_brief.md`: Markdown reasoning brief summarizing high-value surfaces, invariant hypotheses, primitive triage, missing evidence, and safe next steps.
- `patch_diff_result.json`: v0.7 structured patch-diff output with changed files, hunks, audit correlations, and patch-adjacent variant candidates.
- `patch_diff_brief.md`: Markdown patch-diff brief summarizing diff input, changed files, correlations, missing evidence, and safe next steps.

## Supported Detection Areas

- HTTP routes, webhooks, GraphQL-like handlers, and framework route patterns, including bounded Express handler names from same-line simple identifiers, dotted symbols, and named inline functions; Go `GET`/`Post`-style router calls and `Handle`/`HandleFunc` registrations with static route strings and simple handlers; Rails route declarations with static route strings and controller-action handlers; Sinatra route declarations in Sinatra sources with static route strings, HTTP methods, and simple `method(:handler)` references; Laravel `Route::` declarations with static route strings and simple handlers; ASP.NET Core class `[Route]` plus method `[Http*]` attributes with static templates and handler names; Rust Axum `.route(...)` calls and Actix-style route attributes with static templates and simple handlers; Kotlin Ktor route calls and Spring-style Kotlin mapping annotations with static templates and simple handler names; Scala Play `conf/routes` declarations with static route strings and controller handlers; Elixir Phoenix router scopes and static route declarations with scoped prefixes and controller-action handlers; Clojure Ring/Compojure route declarations with static route strings and simple handler symbols; Haskell Servant type-level routes with static path segments, captures, and HTTP method metadata; Python Bottle route decorators with static route strings, optional literal methods, and following handler names; Pyramid `config.add_route(...)` declarations correlated with simple `@view_config` handlers and static request methods; Starlette `Route(...)` and `add_route(...)` calls with static route strings, simple handlers, and single static method metadata; aiohttp route table decorators and `app.router.add_*` calls with static route strings and simple handlers; Tornado `Application` route tuples with static route strings and `RequestHandler` method metadata; Sanic decorators and `add_route` calls with static route strings and simple handlers; FastAPI/Flask handler names from following `def`/`async def`; Flask methods when exactly one static `methods=[...]` literal is present; and Django `path`/`re_path` handlers for simple dotted symbols or `ClassView.as_view()`.
- Enterprise Java/Tomcat descriptors including `WEB-INF/web.xml`, `conf/web.xml`, servlet mappings, security constraints, filters, listeners, and `server.xml` connector candidates.
- ManageEngine/ZSec-style `security-*.xml` URL rules and security controls such as auth/csrf/throttle metadata, headers, cookies, content types, URL validators, XSS patterns, and zip sanitizers.
- Product API XML mappings such as `ADSProductAPIs`, `RMPProductAPIs`, `API_URL`, `MTCALL_*`, `SERVLET_CLASS_NAME`, and servlet-forward XML mappings.
- Java endpoint candidates from Spring static string-literal mappings with class-level prefixes and method handler names, Spark Java static route calls with simple method-reference handlers, `@WebServlet`, JAX-RS `@Path`/HTTP method annotations, SOAP `@WebService`/`@WebMethod`, and conservative legacy handler class names.
- JavaScript and `.cc` URL configuration candidates when route-like strings appear in URL/mapping/action context, Hapi `server.route({ ... })` candidates with static method/path strings and simple handlers, NestJS controller/method decorators with static route strings and method handler names, plus enriched Next.js API route metadata for `pages/api` and `app/api/.../route.*` files derived from local paths and static HTTP verb exports.
- Worker, queue, event-consumer, background-task, cron-like, and TaskEngine candidates.
- File, network, process, template, deserialization, configuration, queue, archive, parser, database, and directory consumers.
- Trust boundary candidates such as request-to-worker, data-to-file, data-to-url, data-to-template, data-to-config, data-to-job, data-to-database, data-to-directory, external-to-internal, low-privilege-to-privileged-consumer, and parser-to-consumer.
- Primitive candidates such as file/path control, URL control, internal request trigger, template control, type control, job control, query control, directory query control, configuration control, cache/session concerns, auth-context confusion, tenant confusion, and parser differentials.
- Static flow/dataflow enrichment that conservatively links entrypoints to likely consumers or workers using handler metadata, declared parameters, request parameter names, route tokens, and bounded same-file proximity.
- Evidence graph generation for candidate same-file, handler-name, Java/Enterprise route-to-worker, Java/Enterprise route-to-consumer, static-flow source/target, boundary-evidence, and primitive-evidence correlations, with deterministic pruning/ranking to reduce noisy graph output.
- Static Evidence Workspace browsing via `evidence_viewer.html` for local review of summary counts, safety scope, candidates, static flows, graph preview, missing evidence, safe next steps, and evidence records.
- Deterministic SARIF 2.1.0 export via `audit_result.sarif.json` for local manual-review candidate import into SARIF-aware tools without Semgrep execution, target execution, network access, LLM providers, exploit steps, or vulnerability confirmation.
- Deterministic review-queue export via `audit_review_queue.jsonl` for local line-delimited manual triage of existing boundary, primitive, and static-flow candidates without auto-fixes, Semgrep execution, target execution, network access, LLM providers, exploit steps, or vulnerability confirmation.
- Deterministic offline reasoning via `reason_result.json` and `reasoning_brief.md` for high-value surfaces, security invariant hypotheses, primitive triage, missing evidence, and safe next steps derived from existing audit evidence.
- Deterministic local patch-diff analysis via `patch_diff_result.json` and `patch_diff_brief.md` for linking changed hunks to existing audit evidence and patch-adjacent review hypotheses.

## Limitations

- Static heuristics can miss code paths and can produce false positives.
- Enterprise XML and legacy endpoint detections are heuristic inventory candidates and require human review.
- Evidence graph edges are conservative static correlations, not confirmed runtime dataflows.
- Java/Spark/Enterprise resolver edges are static candidates based on route, handler, metadata, and evidence-token correlation; they do not prove runtime dispatch or dataflow.
- JavaScript route metadata is derived from bounded source patterns, local file paths, and static export declarations; it does not prove runtime dispatch, reachability, authorization behavior, exploitability, or vulnerability presence.
- Go, Rails, Sinatra, Laravel, ASP.NET, Rust, Kotlin, Scala Play, Elixir Phoenix, Clojure, Haskell, Python Bottle, Pyramid, Starlette, aiohttp, Tornado, and Sanic route metadata is derived from bounded static source patterns; it is candidate inventory only and does not prove runtime dispatch, reachability, authorization behavior, exploitability, or vulnerability presence.
- Python and Spring route metadata is derived from bounded static source patterns; it is candidate inventory only and does not prove runtime dispatch, reachability, authorization behavior, exploitability, or vulnerability presence.
- Static flow/dataflow candidates are heuristic links for review; they do not prove runtime reachability, exploitability, authorization bypass, or request-controlled influence.
- The static evidence viewer is a browsing aid for static candidates; it does not prove runtime reachability, dataflow, exploitability, or vulnerability presence.
- SARIF export is a local candidate-evidence projection for manual review; it is not Semgrep output and does not execute Semgrep, inspect public targets, prove exploitability, or confirm vulnerability presence.
- Review-queue JSONL is a local triage projection for manual review; it does not auto-fix code, run Semgrep, execute target code, prove exploitability, or confirm vulnerability presence.
- The `reason` command is deterministic offline reasoning over structured audit JSON only; it does not inspect raw source, call a network LLM provider, prove exploitability, or confirm vulnerability presence.
- The `patch-diff` command performs deterministic local diff parsing only; it links changed hunks to existing audit evidence by file and line proximity, not confirmed semantic reachability.
- The `patch-diff` command does not apply patches, check out refs, fetch network resources, execute target code, call a network LLM provider, generate payloads, produce exploit steps, or confirm vulnerability/exploitability.
- The flow enrichment is intentionally bounded and token/metadata-based; it is not a broad AST, call-graph, or interprocedural dataflow engine.
- Findings are candidates for review, not vulnerability confirmations.
- The audit pipeline does not execute application code.
- The current audit and reasoning pipeline does not call a network LLM provider.
- Human review is required before security conclusions or code changes.

## Roadmap

- Add a review-queue CLI for local filtering, summarization, and handoff of `audit_review_queue.jsonl`.
- Add semantic focus modes for import/upload, worker/queue, template/workflow, and URL/internal-request research.
- Modularize detector families as coverage grows, while preserving deterministic output and existing detector tuning.
- Expand configuration for report caps and local artifact selection.
- Design optional LLM-assisted hypothesis generation behind the existing safety model, limited to deterministic tests and evidence-linked output contracts without enabling live providers.
- Evaluate optional Semgrep-shaped local import/export contracts without executing Semgrep or treating SARIF/review-queue artifacts as Semgrep output.
