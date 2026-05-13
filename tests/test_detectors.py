from pathlib import Path

from invariant_os.analysis.detectors import detect_consumers, detect_entrypoints, detect_workers
from invariant_os.analysis.indexer import index_repository
from invariant_os.core.config import AuditConfig
from invariant_os.core.models import ConsumerType, EntrypointType, WorkerType

FIXTURES = Path(__file__).parent / "fixtures"


def _indexed_fixture(name: str):
    repo_root = FIXTURES / name
    return repo_root, index_repository(repo_root, AuditConfig())


def _indexed_tmp_repo(tmp_path: Path, files: dict[str, str]):
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path, index_repository(tmp_path, AuditConfig())


def _assert_all_detections_have_evidence(detections):
    for detection in detections:
        assert detection.evidence
        for evidence in detection.evidence:
            assert evidence.file
            assert not evidence.file.startswith("/")
            assert evidence.line > 0
            assert evidence.pattern
            assert evidence.snippet


def _assert_unique_ids(detections):
    ids = [detection.id for detection in detections]
    assert len(ids) == len(set(ids))
    evidence_ids = [evidence.id for detection in detections for evidence in detection.evidence]
    assert len(evidence_ids) == len(set(evidence_ids))


def _has_evidence(detection, *, pattern: str, file: str | None = None):
    return any(
        evidence.pattern == pattern and (file is None or evidence.file == file)
        for evidence in detection.evidence
    )


def test_detects_express_route_queue_file_and_worker():
    repo_root, files = _indexed_fixture("mini_express_app")

    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)

    assert any(
        entrypoint.file == "app.js"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/import"
        and _has_evidence(entrypoint, pattern="express_route", file="app.js")
        for entrypoint in entrypoints
    )
    assert any(
        consumer.file == "app.js"
        and consumer.type == ConsumerType.QUEUE_OPERATION
        and consumer.pattern == "queue_operation"
        and _has_evidence(consumer, pattern="queue_operation", file="app.js")
        and "queue.add" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        consumer.file == "app.js"
        and consumer.type == ConsumerType.FILE_OPERATION
        and consumer.pattern == "file_operation"
        and _has_evidence(consumer, pattern="file_operation", file="app.js")
        and "fs.writeFile" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        worker.file == "worker.js"
        and worker.pattern == "queue_process"
        and _has_evidence(worker, pattern="queue_process", file="worker.js")
        and "queue.process" in worker.evidence[0].snippet
        for worker in workers
    )
    worker_file_pattern_pairs = [(worker.file, worker.pattern) for worker in workers]
    assert len(worker_file_pattern_pairs) == len(set(worker_file_pattern_pairs))
    combined_detections = [*entrypoints, *consumers, *workers]
    _assert_all_detections_have_evidence(combined_detections)
    _assert_unique_ids(entrypoints)
    _assert_unique_ids(consumers)
    _assert_unique_ids(workers)
    combined_evidence_ids = [
        evidence.id for detection in combined_detections for evidence in detection.evidence
    ]
    assert len(combined_evidence_ids) == len(set(combined_evidence_ids))


def test_detects_fastapi_file_and_network_consumers():
    repo_root, files = _indexed_fixture("mini_fastapi_app")

    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)

    assert any(
        entrypoint.file == "main.py"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/upload"
        and _has_evidence(entrypoint, pattern="fastapi_route", file="main.py")
        for entrypoint in entrypoints
    )
    assert any(
        consumer.file == "main.py"
        and consumer.type == ConsumerType.NETWORK_OPERATION
        and consumer.pattern == "network_operation"
        and "requests.get" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        consumer.file == "main.py"
        and consumer.type == ConsumerType.FILE_OPERATION
        and consumer.pattern == "file_operation"
        and "open(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    _assert_all_detections_have_evidence([*entrypoints, *consumers])
    _assert_unique_ids(entrypoints)
    _assert_unique_ids(consumers)


def test_detects_template_consumer_and_route():
    repo_root, files = _indexed_fixture("mini_template_app")

    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)

    assert any(
        entrypoint.file == "app.py"
        and entrypoint.route_path == "/preview"
        and _has_evidence(entrypoint, pattern="flask_route", file="app.py")
        for entrypoint in entrypoints
    )
    assert any(
        consumer.file == "app.py"
        and consumer.type == ConsumerType.TEMPLATE_OPERATION
        and consumer.pattern == "template_operation"
        and "render_template" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    _assert_all_detections_have_evidence([*entrypoints, *consumers])
    _assert_unique_ids(entrypoints)
    _assert_unique_ids(consumers)


def test_detects_nextjs_pages_and_app_api_routes(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "pages/api/import.ts": "export default function handler(req, res) { res.status(200).end(); }\n",
            "app/api/import/route.ts": "export async function POST(request: Request) { return Response.json({ ok: true }); }\n",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    for expected_file in ["pages/api/import.ts", "app/api/import/route.ts"]:
        match = next(
            entrypoint for entrypoint in entrypoints if entrypoint.file == expected_file
        )
        assert match.type == EntrypointType.HTTP_ROUTE
        assert match.line == 1
        assert match.evidence[0].file == expected_file
        assert match.evidence[0].line == 1
        assert match.evidence[0].pattern == "next_api_route"
        assert match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_generic_webhook_entrypoint(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"handlers/webhook.py": "def webhook(request):\n    return Response(status=204)\n"},
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "handlers/webhook.py" and entrypoint.type == EntrypointType.WEBHOOK
    )
    assert match.line == 1
    assert match.evidence[0].file == "handlers/webhook.py"
    assert match.evidence[0].line == 1
    assert match.evidence[0].pattern == "generic_webhook"
    assert "webhook" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_generic_graphql_resolver_mutation_and_query(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "schema.ts": "const resolver = {};\nexport const Mutation = {};\nexport const Query = {};\n"
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    expected = [
        ("resolver", 1, "resolver"),
        ("Mutation", 2, "Mutation"),
        ("Query", 3, "Query"),
    ]
    for _, line, snippet_part in expected:
        match = next(
            entrypoint
            for entrypoint in entrypoints
            if entrypoint.file == "schema.ts"
            and entrypoint.type == EntrypointType.GRAPHQL_RESOLVER
            and entrypoint.line == line
        )
        assert match.evidence[0].file == "schema.ts"
        assert match.evidence[0].line == line
        assert match.evidence[0].pattern == "generic_graphql"
        assert snippet_part in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_required_consumer_categories(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "ops.py": "subprocess.run(['convert', filename])\njson.loads(payload)\nsettings = yaml.safe_load(raw_config)\narchive.extractall(target_dir)\nparsed = parse(user_supplied_text)\n",
        },
    )

    consumers = detect_consumers(repo_root, files)

    expected = [
        (ConsumerType.PROCESS_OPERATION, "process_operation", 1, "subprocess.run"),
        (ConsumerType.DESERIALIZATION, "deserialization", 2, "json.loads"),
        (ConsumerType.CONFIG_OPERATION, "config_operation", 3, "settings"),
        (ConsumerType.ARCHIVE_OPERATION, "archive_operation", 4, "extractall"),
        (ConsumerType.PARSER_OPERATION, "parser_operation", 5, "parse("),
    ]
    for consumer_type, pattern, line, snippet_part in expected:
        match = next(
            consumer
            for consumer in consumers
            if consumer.file == "ops.py"
            and consumer.type == consumer_type
            and consumer.pattern == pattern
            and consumer.line == line
        )
        assert match.evidence[0].file == "ops.py"
        assert match.evidence[0].line == line
        assert match.evidence[0].pattern == pattern
        assert snippet_part in match.evidence[0].snippet
    _assert_all_detections_have_evidence(consumers)



def test_detects_spring_get_mapping(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/main/java/example/ImportController.java": """
@RestController
class ImportController {
    @GetMapping(\"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.file == "src/main/java/example/ImportController.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/imports"
        and _has_evidence(entrypoint, pattern="spring_mapping")
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_get_mapping_value_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @GetMapping(value = \"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "@GetMapping" in match.evidence[0].snippet
    assert "value" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_post_mapping_path_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @PostMapping(path = \"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "@PostMapping" in match.evidence[0].snippet
    assert "path" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_request_mapping_path_and_method_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @RequestMapping(path = \"/imports\", method = RequestMethod.POST)
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "RequestMethod.POST" in match.evidence[0].snippet
    assert "path" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_request_mapping_method_before_value_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @RequestMapping(method = RequestMethod.POST, value = \"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "RequestMethod.POST" in match.evidence[0].snippet
    assert "value" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_django_urlpatterns(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "urls.py": """
from django.urls import path
from . import views

urlpatterns = [
    path(\"preview/\", views.preview),
]
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "preview/"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "urls.py"
    assert match.evidence[0].line == 6
    assert match.evidence[0].pattern == "django_urlpatterns"
    assert "path(" in match.evidence[0].snippet
    assert "preview/" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_django_multiline_urlpatterns(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "urls.py": """
from django.urls import path
from . import views

urlpatterns = [
    path(
        \"preview/\",
        views.preview,
    ),
]
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "preview/"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "urls.py"
    assert match.evidence[0].line in {6, 7}
    assert match.evidence[0].pattern == "django_urlpatterns"
    assert "path(" in match.evidence[0].snippet or "preview/" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_bare_process_worker(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"jobs/import.js": "const queue = require('./queue'); process('import', async job => job.data);\n"},
    )

    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)

    assert any(
        consumer.file == "jobs/import.js"
        and consumer.type == ConsumerType.QUEUE_OPERATION
        and consumer.pattern == "queue_operation"
        and _has_evidence(consumer, pattern="queue_operation", file="jobs/import.js")
        and "process(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        worker.file == "jobs/import.js"
        and worker.pattern == "queue_process"
        and _has_evidence(worker, pattern="queue_process")
        and "process(" in worker.evidence[0].snippet
        for worker in workers
    )
    worker_file_pattern_pairs = [(worker.file, worker.pattern) for worker in workers]
    assert len(worker_file_pattern_pairs) == len(set(worker_file_pattern_pairs))
    _assert_all_detections_have_evidence([*consumers, *workers])


def test_does_not_treat_bare_process_as_queue_without_worker_context(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"src/service.js": "function run() { process(input); }\n"},
    )

    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)

    assert not any(
        consumer.file == "src/service.js"
        and consumer.type == ConsumerType.QUEUE_OPERATION
        and consumer.pattern == "queue_operation"
        and "process(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert not any(
        worker.file == "src/service.js"
        and worker.type == WorkerType.QUEUE_WORKER
        and worker.pattern == "queue_process"
        and "process(" in worker.evidence[0].snippet
        for worker in workers
    )
    _assert_all_detections_have_evidence([*consumers, *workers])


def test_detects_generic_render_template_consumer(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"views.py": "def preview(request):\n    return render(request, 'preview.html')\n"},
    )

    consumers = detect_consumers(repo_root, files)

    assert any(
        consumer.file == "views.py"
        and consumer.type == ConsumerType.TEMPLATE_OPERATION
        and consumer.pattern == "template_operation"
        and "render(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    _assert_all_detections_have_evidence(consumers)
