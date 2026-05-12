# final plan

đề xuất plan hoàn chỉnh từ đầu đến cuối, từ a đến z đi để bắt đầu code

---

Dưới đây là **plan hoàn chỉnh từ A → Z** để bắt đầu code `InvariantOS` — một local Security Research OS cho authorized code audit.

Mục tiêu ban đầu không phải là “AI tìm RCE”, mà là:

```
repo local
→ index source code
→ detect entrypoints / workers / consumers
→ infer trust boundaries
→ generate invariants
→ suggest primitive candidates
→ produce research brief
```

---

# 0. Nguyên tắc sản phẩm

Trước khi code, chốt 5 nguyên tắc:

```
1. Chỉ phân tích repo/local target được phép audit.
2. Không auto exploit, không mass scan, không weaponize payload.
3. LLM chỉ suy luận và gợi ý; bằng chứng phải đến từ code/static analysis/test.
4. Mọi finding phải có evidence: file, line, symbol, dataflow hoặc rule hit.
5. Sản phẩm ưu tiên researcher workflow hơn là “scanner báo đỏ”.
```

Một câu định hướng:

```
LLM proposes. Tools prove. Human approves.
```

---

# 1. Vision tổng thể

Tên sản phẩm:

```
InvariantOS
```

Mô tả:

```
A local-first security research workbench that maps attack surface,
trust boundaries, security invariants, and primitive candidates from
authorized source code repositories.
```

Input:

```
- Git repo local
- optional: OpenAPI/Swagger
- optional: runtime traces
- optional: git diff / patch
```

Output:

```
- repo_index.json
- entrypoints.json
- consumers.json
- workers.json
- boundaries.json
- primitive_candidates.json
- research_brief.md
```

---

# 2. MVP roadmap tổng quát

## v0.1 — Deterministic Local CLI

Không LLM hoặc LLM optional.

```
- Repo indexer
- Entrypoint detector
- Worker detector
- Dangerous consumer detector
- Boundary heuristic
- Markdown report
```

## v0.2 — LLM Reasoning Layer

```
- Invariant generator
- Primitive classifier
- Missing evidence analyzer
- Safe next-step planner
- LLM research brief
```

## v0.3 — Static Analysis Integration

```
- Semgrep integration
- Custom rules
- Query generator
- Finding triage
```

## v0.4 — Graph Model

```
- Component graph
- Entrypoint → service → storage → worker → consumer
- Trust boundary graph
```

## v0.5 — Web UI

```
- Project dashboard
- Attack surface list
- Boundary graph
- Finding workspace
- Evidence viewer
```

## v1.0 — Research OS

```
- Multi-agent LLM workflow
- Patch diff analyzer
- Regression test generator
- Fix advisor
- Report exporter
- Team workflow
```

---

# 3. Chọn stack

Cho bản đầu tiên, chọn stack đơn giản:

```
Language: Python 3.11+
CLI: Typer
Output: JSON + Markdown
Validation: Pydantic
Console UI: Rich
Search: Python regex trước, ripgrep optional
Static analyzer: Semgrep ở v0.3
LLM: provider adapter ở v0.2
Graph DB: chưa cần ở v0.1
Frontend: chưa cần ở v0.1
```

Lý do:

```
- Python dễ viết scanner/static tooling.
- CLI dễ test và ship nhanh.
- JSON output dễ dùng lại cho LLM/UI sau này.
- Markdown report hữu ích ngay.
```

---

# 4. Repo structure cuối cùng

Tạo repo như sau:

```
invariant-os/
  invariant_os/
    __init__.py
    cli.py

    core/
      __init__.py
      models.py
      indexer.py
      detectors.py
      boundary.py
      report.py
      config.py
      utils.py

    analyzers/
      __init__.py
      generic.py
      python.py
      javascript.py
      typescript.py
      java.py
      go.py

    llm/
      __init__.py
      base.py
      openai_provider.py
      anthropic_provider.py
      reasoner.py

    prompts/
      repo_summary.md
      invariant_generator.md
      primitive_classifier.md
      report_writer.md

    rules/
      route_patterns.yml
      worker_patterns.yml
      consumer_patterns.yml
      boundary_rules.yml

    outputs/
      .gitkeep

  tests/
    fixtures/
      mini_express_app/
      mini_fastapi_app/
      mini_worker_app/
    test_indexer.py
    test_detectors.py
    test_boundary.py
    test_report.py

  pyproject.toml
  README.md
  .gitignore
  LICENSE
```

---

# 5. Domain model cần có

Đây là xương sống. Đừng code analyzer trước khi có model.

## Project

```
Project
- id
- repo_path
- language summary
- frameworks
- files
```

## FileRecord

```
FileRecord
- path
- language
- size
- hash
```

## Entrypoint

```
Entrypoint
- id
- type: http_route | cli_command | webhook | graphql_resolver | rpc_handler
- file
- line
- framework_hint
- method
- route_path
- handler
- evidence
```

## Consumer

```
Consumer
- id
- type:
  - file_operation
  - network_operation
  - process_operation
  - template_operation
  - deserialization
  - config_operation
  - queue_operation
  - archive_operation
  - parser_operation
- file
- line
- symbol
- pattern
- evidence
```

## Worker

```
Worker
- id
- type:
  - queue_worker
  - cron_job
  - background_task
  - event_consumer
- file
- line
- framework_hint
- pattern
- evidence
```

## BoundaryCandidate

```
BoundaryCandidate
- id
- type:
  - request_to_worker
  - data_to_file
  - data_to_url
  - data_to_template
  - data_to_config
  - data_to_job
  - external_to_internal
  - low_priv_to_privileged_consumer
  - parser_to_consumer
- confidence
- reason
- evidence
```

## PrimitiveCandidate

```
PrimitiveCandidate
- id
- primitive:
  - path_control
  - file_write
  - file_read
  - url_control
  - internal_request_trigger
  - template_control
  - type_control
  - job_control
  - config_control
  - cache_poisoning
  - auth_context_confusion
  - tenant_confusion
  - parser_differential
- confidence
- evidence
- missing_evidence
- safe_next_steps
```

---

# 6. CLI commands cuối cùng

Ngay từ đầu thiết kế CLI như sau:

```
invariant-os audit ./repo
```

Chạy full deterministic audit.

```
invariant-os audit ./repo--focus import
```

Ưu tiên surface có chữ `import`.

```
invariant-os audit ./repo--focus worker
```

Ưu tiên worker/job/queue.

```
invariant-os reason outputs/audit_result.json
```

Gọi LLM để generate invariant + primitive candidates.

```
invariant-os report outputs/audit_result.json
```

Generate lại Markdown report.

```
invariant-osdiff ./repo--base main--head HEAD
```

Dành cho patch diff analyzer ở v0.4+.

---

# 7. Phase A — Khởi tạo project

## Deliverable

```
CLI install được và chạy được lệnh help.
```

## Tasks

```
mkdir invariant-os
cd invariant-os
git init

mkdir-p invariant_os/{core,analyzers,llm,prompts,rules,outputs}
mkdir-p tests/fixtures
touch invariant_os/__init__.py
touch invariant_os/cli.py
touch pyproject.toml
touch README.md
touch .gitignore
```

## `pyproject.toml`

```
[project]
name = "invariant-os"
version = "0.1.0"
description = "Local-first authorized security research mapper"
requires-python = ">=3.11"
dependencies = [
  "typer>=0.12.0",
  "rich>=13.0.0",
  "pydantic>=2.0.0",
  "pyyaml>=6.0.0"
]

[project.optional-dependencies]
dev = [
  "pytest>=8.0.0",
  "ruff>=0.5.0",
  "mypy>=1.0.0"
]

[project.scripts]
invariant-os = "invariant_os.cli:app"

[tool.setuptools.packages.find]
include = ["invariant_os*"]
```

## Test

```
pip install-e".[dev]"
invariant-os--help
```

---

# 8. Phase B — Repo indexer

## Goal

Đi qua repo local, lấy danh sách file đáng phân tích.

## Input

```
/path/to/repo
```

## Output

```
repo_index.json
```

## Ignore

```
.git
node_modules
vendor
dist
build
.next
target
__pycache__
.venv
venv
coverage
```

## Detect language by extension

```
.py  → python
.js  → javascript
.ts  → typescript
.tsx → typescript
.java → java
.go → go
.rb → ruby
.php → php
.cs → csharp
.yml/.yaml → yaml
.json → json
.toml → toml
```

## Definition of done

```
- Index được repo thật.
- Không scan thư mục rác.
- Không đọc file quá lớn.
- Output JSON ổn định.
```

---

# 9. Phase C — Entrypoint detector

## Goal

Tìm nơi user/request đi vào hệ thống.

## Detect trước

```
Express:
- app.get(
- app.post(
- router.get(
- router.post(

FastAPI:
- @app.get
- @app.post
- @router.get
- @router.post

Spring:
- @GetMapping
- @PostMapping
- @RequestMapping

Next.js:
- pages/api/*
- app/api/*/route.ts

Django:
- urlpatterns

Flask:
- @app.route

GraphQL:
- resolver
- Query:
- Mutation:
```

## Output

```
entrypoints.json
```

## Definition of done

```
- Detect được ít nhất Express + FastAPI + generic route.
- Có file, line, pattern, evidence.
- Không cần parse route hoàn hảo ở v0.1.
```

---

# 10. Phase D — Dangerous consumer detector

## Goal

Không tìm bug. Chỉ inventory các consumer nguy hiểm.

## Consumer taxonomy

```
file_operation
network_operation
process_operation
template_operation
deserialization
config_operation
queue_operation
archive_operation
parser_operation
```

## Pattern ban đầu

```
File:
- readFile
- writeFile
- path.join
- path.resolve
- open(
- os.path.join

Network:
- fetch(
- axios.
- requests.
- urllib
- http.Client
- net/http

Process:
- exec(
- spawn(
- subprocess.
- ProcessBuilder

Template:
- render(
- renderTemplate
- compileTemplate
- handlebars
- jinja
- ejs

Deserialization:
- deserialize
- pickle.loads
- yaml.load
- ObjectInputStream
- unserialize

Archive:
- extract
- extractall
- ZipFile
- tarfile

Queue:
- queue.add
- process(
- consume(
- subscribe(
```

## Output

```
consumers.json
```

## Definition of done

```
- Có danh sách consumer theo type.
- Có evidence line.
- Có count theo consumer type.
```

---

# 11. Phase E — Worker detector

## Goal

Tìm async/background consumer.

Đây là module quan trọng vì nhiều chain nghiêm trọng có dạng:

```
request → DB/queue → worker → privileged consumer
```

## Detect path hints

```
worker
workers
job
jobs
task
tasks
consumer
consumers
queue
cron
```

## Detect code patterns

```
queue.process
process(
consume(
subscribe(
on_message
@shared_task
Celery
BullMQ
Sidekiq
cron
```

## Output

```
workers.json
```

## Definition of done

```
- Detect được worker folder.
- Detect được queue consumer.
- Giảm noise bằng dedupe.
```

---

# 12. Phase F — Boundary inference

## Goal

Từ facts thô, infer trust boundary candidates.

Không cần full dataflow ở v0.1. Dùng heuristic trước.

## Rules đầu tiên

```
Nếu có entrypoints + workers
→ request_to_worker

Nếu có file operations
→ data_to_file

Nếu có network operations
→ data_to_url

Nếu có template operations
→ data_to_template

Nếu có config operations
→ data_to_config

Nếu có queue operations hoặc workers
→ data_to_job

Nếu có parser/archive operations + file/template/config consumer
→ parser_to_consumer
```

## Output

```
boundaries.json
```

## Definition of done

```
- Mỗi boundary có reason.
- Mỗi boundary có evidence.
- Không claim vulnerability.
```

Ví dụ đúng:

```
Potential request_to_worker boundary exists because HTTP entrypoints
and worker candidates are both present.
```

Ví dụ sai:

```
This is exploitable RCE.
```

---

# 13. Phase G — Deterministic research brief

## Goal

Generate Markdown hữu ích cho researcher.

## File

```
research_brief.md
```

## Sections

```
# InvariantOS Research Brief

## Summary
## High-Value Surfaces
## Entrypoints
## Worker Candidates
## Dangerous Consumers
## Trust Boundary Candidates
## Suggested Security Invariants
## Primitive Candidates To Investigate
## Missing Evidence
## Safe Manual Review Plan
```

## Suggested invariants mặc định

```
- User-controlled data must not select worker job type, class, module, provider, or template.
- Persisted request data must be revalidated by privileged workers before use.
- Uploaded or imported files must remain inside a canonical sandbox path.
- Validated URLs must be identical to URLs later requested by HTTP clients.
- Template names, config keys, and runtime behavior must not be selected from untrusted input.
- Archive extraction must not write outside the intended directory.
- Imported metadata must not affect privileged runtime configuration.
```

## Definition of done

```
- Chạy audit repo bất kỳ và có report đọc được.
- Report giúp chọn subsystem để audit tiếp.
```

---

# 14. Phase H — Fixture test repos

Trước khi thêm LLM, tạo fixture nhỏ để test.

## `mini_express_app`

```
- route POST /import
- queue.add(...)
- worker xử lý job
- fs.writeFile(...)
```

Expected:

```
entrypoints > 0
workers > 0
consumers include file_operation + queue_operation
boundaries include request_to_worker + data_to_file + data_to_job
```

## `mini_fastapi_app`

```
- @app.post("/upload")
- open(...)
- requests.get(...)
```

Expected:

```
entrypoints > 0
consumers include file_operation + network_operation
boundaries include data_to_file + data_to_url
```

## `mini_template_app`

```
- renderTemplate(...)
```

Expected:

```
consumers include template_operation
boundaries include data_to_template
```

## Definition of done

```
pytest pass
```

---

# 15. Phase I — LLM provider abstraction

Chỉ làm sau khi deterministic output ổn.

## Goal

Không hard-code OpenAI/Anthropic trong logic chính.

## Interface

```
classLLMProvider:
defcomplete_json(self,system_prompt:str,user_payload:dict) ->dict:
        ...
```

## Providers

```
OpenAIProvider
AnthropicProvider
MockProvider
```

`MockProvider` rất quan trọng để test không tốn tiền.

## Environment variables

```
INVARIANT_OS_LLM_PROVIDER=openai | anthropic | mock
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
```

## Definition of done

```
- reason command chạy được với mock provider.
- Không cần key vẫn test được.
```

---

# 16. Phase J — LLM invariant generator

## Command

```
invariant-os reason outputs/audit_result.json
```

## Input

Không gửi toàn bộ source code. Gửi facts:

```
{
  "entrypoints": [],
  "workers": [],
  "consumers": [],
  "boundaries": []
}
```

## Prompt output

```
{
  "high_value_surfaces": [],
  "trust_boundaries": [],
  "security_invariants": [],
  "primitive_candidates": [],
  "missing_evidence": [],
  "safe_next_steps": []
}
```

## Rules trong prompt

```
- Do not generate exploits.
- Do not claim RCE without evidence.
- Distinguish fact vs hypothesis.
- Every claim must reference evidence.
- Prefer primitive names over vulnerability names.
- Output JSON only.
```

## Definition of done

```
- LLM tạo được invariants.
- LLM tạo được primitive candidates.
- Có missing evidence rõ ràng.
```

---

# 17. Phase K — Primitive classifier

## Input

```
boundary candidates + consumers + workers + entrypoints
```

## Output primitive taxonomy

```
path_control
file_write
file_read
url_control
internal_request_trigger
template_control
type_control
job_control
config_control
cache_poisoning
auth_context_confusion
tenant_confusion
parser_differential
```

## Example output

```
{
  "primitive":"job_control",
  "confidence":"medium",
  "evidence": [
"queue_operation_count=4",
"workers=2",
"request_to_worker boundary exists"
  ],
  "missing_evidence": [
"Need confirm whether job type is user-controlled",
"Need inspect worker-side schema validation"
  ],
  "safe_next_steps": [
"Trace job payload from route to worker",
"Check allowlist for job type dispatch"
  ]
}
```

---

# 18. Phase L — Evidence model

Trước khi build UI, chuẩn hóa evidence.

## Evidence types

```
code_reference
pattern_match
boundary_rule
llm_hypothesis
static_analysis_hit
manual_note
test_result
```

## Evidence object

```
{
  "id":"ev_001",
  "type":"code_reference",
  "file":"src/workers/importWorker.ts",
  "line":42,
  "symbol":"processImport",
  "snippet":"queue.process('import', async job => ...)"
}
```

## Definition of done

```
- Mỗi candidate có evidence IDs.
- LLM output không dùng evidence text rời rạc nữa.
```

---

# 19. Phase M — Semgrep integration

Làm sau v0.2.

## Goal

Cho phép chạy rule thật.

## Command

```
invariant-os semgrep ./repo
```

Hoặc trong audit:

```
invariant-os audit ./repo--semgrep
```

## Rule groups

```
dynamic_template_selection
path_join_user_input
network_fetch_user_input
worker_dynamic_dispatch
unsafe_yaml_load
archive_extraction
subprocess_invocation
```

## Output

```
semgrep_findings.json
```

## Definition of done

```
- Tool chạy được nếu máy có semgrep.
- Nếu không có semgrep thì skip graceful.
```

---

# 20. Phase N — Focus modes

Thêm mode chuyên sâu.

## `-focus import`

Ưu tiên:

```
import
upload
archive
extract
parse
metadata
preview
convert
```

## `-focus worker`

Ưu tiên:

```
worker
job
queue
task
consume
dispatch
retry
dead-letter
```

## `-focus template`

Ưu tiên:

```
template
render
compile
helper
include
partial
theme
email
report
```

## `-focus url`

Ưu tiên:

```
fetch
webhook
callback
avatar
import remote
integration test
preview url
```

## Output

Report sẽ có section:

```
Focus-specific high-value surfaces
```

---

# 21. Phase O — Graph export

Chưa cần Neo4j. Export graph JSON trước.

## Nodes

```
entrypoint
worker
consumer
boundary
file
```

## Edges

```
contains
matches
suggests_boundary
related_to
```

## File

```
graph.json
```

## Definition of done

```
- Có thể render bằng frontend sau này.
- Có thể import vào Neo4j sau này.
```

---

# 22. Phase P — Web UI

Chỉ bắt đầu khi CLI hữu ích.

## Stack

```
Frontend: Next.js
Graph: React Flow
Backend: FastAPI
Storage: SQLite/PostgreSQL
```

## Màn đầu tiên

```
1. Project list
2. Audit result summary
3. Entrypoints table
4. Consumers table
5. Boundary cards
6. Research brief viewer
```

## Màn thứ hai

```
Trust boundary graph
```

## Màn thứ ba

```
Finding workspace
- Candidate
- Evidence
- Missing evidence
- Manual notes
- Status
```

---

# 23. Phase Q — Patch diff analyzer

## Command

```
invariant-osdiff ./repo--base main--head HEAD
```

## Detect

```
- validation changes
- auth changes
- path/url/template/config handling changes
- parser changes
- worker/job changes
```

## LLM questions

```
- Patch fixes symptom or root cause?
- Are there similar paths?
- Are worker/import/API variants still present?
- Does fix happen at producer or consumer?
```

## Output

```
patch_research_brief.md
variant_candidates.json
```

---

# 24. Phase R — Fix advisor

Input:

```
Primitive candidate + evidence + missing evidence
```

Output:

```
- root cause hypothesis
- defensive fix
- regression tests
- hardening recommendation
```

Example:

```
Root cause:
Worker trusts persisted job metadata from request layer.

Fix:
- Define canonical schema for job payload.
- Validate at producer and consumer.
- Make job type server-assigned.
- Replace dynamic dispatch with allowlisted mapping.
```

---

# 25. Phase S — Regression test generator

LLM có thể generate test skeleton.

Không generate exploit payload. Generate benign negative tests.

Example:

```
- Unknown job_type should be rejected.
- Worker should reject payload missing server_signature.
- Archive entry resolving outside sandbox should fail validation.
- URL after redirect to private range should be blocked.
```

Output:

```
regression_tests.md
```

Hoặc code skeleton theo framework.

---

# 26. Phase T — Safety Governor

Cần module kiểm soát hành vi.

## Block

```
- public target scanning
- exploit generation
- credential theft
- persistence/evasion
- destructive payloads
- stealth
- malware behavior
```

## Allow

```
- local repo analysis
- static analysis
- authorized test planning
- defensive fix
- regression test
- report writing
```

## Implementation ban đầu

Một function đơn giản:

```
defvalidate_task_scope(task:str) ->bool:
    ...
```

Sau này nâng cấp thành policy engine.

---

# 27. Phase U — Config file

Cho phép user cấu hình project.

File:

```
invariant-os.yml
```

Example:

```
project:
  name: acme-app
  scope: local_authorized_repo

ignore:
  - node_modules
  - vendor
  - dist
  - build

focus:
  - import
  - worker
  - template

llm:
  provider: openai
  enabled: false

semgrep:
  enabled: false
```

---

# 28. Phase V — Quality gates

Mỗi PR phải pass:

```
ruff check .
mypy invariant_os
pytest
```

Definition:

```
- Không crash khi repo rỗng.
- Không crash khi file không đọc được.
- Không crash khi không có LLM key.
- Output JSON luôn valid.
- Report Markdown luôn generate được.
```

---

# 29. Phase W — README

README đầu tiên phải cực rõ.

## Sections

```
What is InvariantOS?
Safety model
Install
Quickstart
Commands
Output files
Supported frameworks
Limitations
Roadmap
```

## Safety statement

```
InvariantOS is designed for authorized local codebase analysis and
defensive security research. It does not perform public target scanning
or exploit automation.
```

---

# 30. Phase X — First real dogfooding

Sau khi v0.1 xong, test trên 3 repo được phép:

```
1. Một repo Express/Node nhỏ
2. Một repo FastAPI/Python nhỏ
3. Một repo có worker/queue
```

Câu hỏi cần trả lời:

```
- Report có giúp chọn subsystem đáng audit không?
- Boundary candidates có noise quá không?
- Consumer inventory có quá nhiều false positive không?
- Worker detector có hữu ích không?
- Missing evidence có rõ không?
```

Fix noise trước khi thêm feature mới.

---

# 31. Phase Y — Milestone timeline

## Tuần 1 — CLI deterministic

```
Day 1: project skeleton + CLI
Day 2: repo indexer
Day 3: entrypoint detector
Day 4: consumer detector
Day 5: worker detector
Day 6: boundary inference
Day 7: markdown report + fixture tests
```

## Tuần 2 — LLM reasoning

```
Day 8: LLM provider abstraction
Day 9: prompt templates
Day 10: reason command
Day 11: invariant generator
Day 12: primitive classifier
Day 13: evidence model
Day 14: LLM research brief
```

## Tuần 3 — Static rules + focus modes

```
Day 15: rules YAML
Day 16: focus import
Day 17: focus worker
Day 18: focus template
Day 19: focus url
Day 20: semgrep optional integration
Day 21: polish output
```

## Tuần 4 — Graph + UI planning

```
Day 22: graph export
Day 23: finding model
Day 24: manual notes
Day 25: web UI skeleton
Day 26: dashboard
Day 27: graph view
Day 28: release v0.2/v0.3
```

---

# 32. Phase Z — Final target architecture

Khi trưởng thành, kiến trúc sẽ như này:

```
                 ┌─────────────────────┐
                 │        CLI/UI        │
                 └──────────┬──────────┘
                            │
                 ┌──────────▼──────────┐
                 │    Audit Engine      │
                 └──────────┬──────────┘
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
┌──────▼──────┐     ┌───────▼───────┐    ┌──────▼──────┐
│ Repo Index  │     │ Static Rules  │    │ Graph Model │
└──────┬──────┘     └───────┬───────┘    └──────┬──────┘
       │                    │                   │
       └────────────────────┼───────────────────┘
                            │
                 ┌──────────▼──────────┐
                 │    Evidence Store    │
                 └──────────┬──────────┘
                            │
                 ┌──────────▼──────────┐
                 │    LLM Reasoning     │
                 │ invariant/primitive  │
                 └──────────┬──────────┘
                            │
                 ┌──────────▼──────────┐
                 │ Reports/Fixes/Tests  │
                 └─────────────────────┘
```

---

# 33. Backlog ưu tiên để bắt đầu code ngay

Thứ tự code cụ thể:

```
1. pyproject.toml
2. cli.py với command audit
3. models.py
4. indexer.py
5. detectors.py
6. boundary.py
7. report.py
8. outputs/audit_result.json
9. outputs/research_brief.md
10. tests/fixtures
11. pytest
12. reason command
13. llm/base.py
14. prompts/primitive_classifier.md
15. primitive_candidates.json
```

Không nhảy sang UI trước bước 12.

---

# 34. Definition of Done cho v0.1

v0.1 được coi là xong khi command này chạy ổn:

```
invariant-os audit ./some-authorized-repo
```

Và tạo ra:

```
outputs/audit_result.json
outputs/research_brief.md
```

Trong report phải trả lời được:

```
1. Repo có bao nhiêu entrypoints?
2. Có worker/background job không?
3. Có dangerous consumers nào?
4. Có trust boundary candidates nào?
5. Surface nào đáng audit trước?
6. Primitive nào nên investigate?
7. Evidence nằm ở file/line nào?
8. Cần manual review gì tiếp?
```

---

# 35. Definition of Done cho v0.2

v0.2 xong khi command này chạy được:

```
invariant-os reason outputs/audit_result.json
```

Và tạo ra:

```
outputs/invariants.json
outputs/primitive_candidates.json
outputs/llm_research_brief.md
```

Trong đó mỗi primitive candidate có:

```
- primitive name
- confidence
- evidence
- missing evidence
- safe next steps
```

---

# 36. Điều cần tránh

Đừng bắt đầu bằng:

```
- Auto exploit
- Browser automation
- Public target scanner
- Full SaaS
- Complex taint engine
- Neo4j ngay từ đầu
- Multi-agent orchestration quá sớm
- 50 framework detectors cùng lúc
```

Bắt đầu bằng thứ nhỏ nhưng chạy chắc:

```
repo → facts → boundaries → invariants → primitive candidates → report
```

---

# 37. Câu lệnh mục tiêu đầu tiên

Mọi thứ trong tuần đầu chỉ phục vụ một câu lệnh:

```
invariant-os audit ./repo
```

Và một output hữu ích:

```
This repo has a likely request_to_worker boundary.
It has file/template/network consumers.
The import/upload/worker subsystem is worth reviewing first.
Potential primitives: path_control, job_control, config_control.
Missing evidence: confirm worker-side validation and user control.
```

Khi tool làm được điều này, bạn đã có lõi của `InvariantOS`.

---

[v0.1](https://www.notion.so/v0-1-35e1f962eaf28005a9f8d4b41f60dad0?pvs=21)