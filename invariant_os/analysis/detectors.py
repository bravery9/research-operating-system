"""Heuristic static detectors for indexed repository files."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import re

from invariant_os.core.models import (
    Consumer,
    ConsumerType,
    Entrypoint,
    EntrypointType,
    Evidence,
    EvidenceType,
    FileRecord,
    Worker,
    WorkerType,
)


HTTP_METHODS = "get|post|put|patch|delete"


@dataclass(frozen=True)
class LineMatch:
    file: str
    line: int
    pattern: str
    snippet: str
    groups: dict[str, str]


@dataclass(frozen=True)
class EntrypointPattern:
    regex: re.Pattern[str]
    pattern: str
    framework_hint: str
    type: EntrypointType = EntrypointType.HTTP_ROUTE


@dataclass(frozen=True)
class ConsumerPattern:
    regex: re.Pattern[str]
    pattern: str
    type: ConsumerType


@dataclass(frozen=True)
class WorkerPattern:
    regex: re.Pattern[str]
    pattern: str
    type: WorkerType
    framework_hint: str | None = None


ENTRYPOINT_PATTERNS = [
    EntrypointPattern(
        re.compile(
            rf"\b(?:app|router)\.(?P<method>{HTTP_METHODS})\s*\(\s*['\"](?P<route>[^'\"]+)",
            re.IGNORECASE,
        ),
        "express_route",
        "express",
    ),
    EntrypointPattern(
        re.compile(
            rf"@(?:app|router)\.(?P<method>{HTTP_METHODS})\s*\(\s*['\"](?P<route>[^'\"]+)",
            re.IGNORECASE,
        ),
        "fastapi_route",
        "fastapi",
    ),
    EntrypointPattern(
        re.compile(r"@app\.route\s*\(\s*['\"](?P<route>[^'\"]+)", re.IGNORECASE),
        "flask_route",
        "flask",
    ),
    EntrypointPattern(
        re.compile(
            r"@RequestMapping\s*\([^)]*\bvalue\s*=\s*['\"](?P<route>[^'\"]+)['\"][^)]*\bmethod\s*=\s*RequestMethod\.(?P<method>GET|POST|PUT|PATCH|DELETE)",
            re.IGNORECASE,
        ),
        "spring_mapping",
        "spring",
    ),
    EntrypointPattern(
        re.compile(
            r"@(?P<method>Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*['\"](?P<route>[^'\"]+)",
            re.IGNORECASE,
        ),
        "spring_mapping",
        "spring",
    ),
    EntrypointPattern(
        re.compile(r"\b(?:path|re_path)\s*\(\s*['\"](?P<route>[^'\"]+)", re.IGNORECASE),
        "django_urlpatterns",
        "django",
    ),
    EntrypointPattern(
        re.compile(r"\bwebhook\b", re.IGNORECASE),
        "generic_webhook",
        "generic",
        EntrypointType.WEBHOOK,
    ),
    EntrypointPattern(
        re.compile(r"\b(?:resolver|Mutation|Query)\b"),
        "generic_graphql",
        "graphql",
        EntrypointType.GRAPHQL_RESOLVER,
    ),
]

CONSUMER_PATTERNS = [
    ConsumerPattern(
        re.compile(r"\b(?:readFile|writeFile)\s*\(|\bpath\.(?:join|resolve)\s*\(|\bopen\s*\(|\bos\.path\.join\s*\(|\bPath\s*\("),
        "file_operation",
        ConsumerType.FILE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(
            r"\b(?:new\s+File|FileInputStream|FileOutputStream)\b|"
            r"\b(?:Paths\.get|Path\.of|Files\.(?:readAllBytes|readString|write|copy|move|delete|newInputStream|newOutputStream))\s*\(",
            re.IGNORECASE,
        ),
        "file_operation",
        ConsumerType.FILE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bfetch\s*\(|\baxios\.|\brequests\.|\burllib\b|\bhttpx\.|\bnet/http\b|\bhttp\.Client\b"),
        "network_operation",
        ConsumerType.NETWORK_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bexec\s*\(|\bspawn\s*\(|\bsubprocess\.|\bProcessBuilder\b|Runtime\.getRuntime\(\)\.exec\s*\("),
        "process_operation",
        ConsumerType.PROCESS_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\brender_template\s*\(|\brender\s*\(|\brenderTemplate\s*\(|\bcompileTemplate\s*\(|\bjinja\b|\bhandlebars\b|\bejs\b", re.IGNORECASE),
        "template_operation",
        ConsumerType.TEMPLATE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bpickle\.loads\s*\(|\byaml\.load\s*\(|\bdeserialize\b|\bObjectInputStream\b|\breadObject\s*\(|\bunserialize\b|\bjson\.loads\s*\("),
        "deserialization",
        ConsumerType.DESERIALIZATION,
    ),
    ConsumerPattern(
        re.compile(r"\bconfig\b|\bsettings\b|\byaml\.safe_load\s*\(|\btoml\b|\bProperties\b|\.load\s*\(|\.getProperty\s*\(", re.IGNORECASE),
        "config_operation",
        ConsumerType.CONFIG_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\b(?:RelationalAPI|executeQuery|DriverManager\.getConnection|PreparedStatement)\b"),
        "database_operation",
        ConsumerType.DATABASE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\b(?:InitialDirContext|DirContext\.search|javax\.naming\.directory)\b|ldap://|\.search\s*\(", re.IGNORECASE),
        "directory_operation",
        ConsumerType.DIRECTORY_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bqueue\.add\s*\(|\.process\s*\(|\bconsume\s*\(|\bsubscribe\s*\(|\bsend_task\s*\(|\.delay\s*\("),
        "queue_operation",
        ConsumerType.QUEUE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bextract\s*\(|\bextractall\s*\(|\bZipFile\b|\btarfile\b"),
        "archive_operation",
        ConsumerType.ARCHIVE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\b|\bparser\b|\bparse\s*\(", re.IGNORECASE),
        "parser_operation",
        ConsumerType.PARSER_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\.getParameter\s*\(\s*['\"]req['\"]\s*\)", re.IGNORECASE),
        "request_parameter",
        ConsumerType.PARSER_OPERATION,
    ),
]

WORKER_PATTERNS = [
    WorkerPattern(re.compile(r"\bqueue\.process\s*\(|\.process\s*\("), "queue_process", WorkerType.QUEUE_WORKER, "queue"),
    WorkerPattern(re.compile(r"\bconsume\s*\("), "consume", WorkerType.EVENT_CONSUMER),
    WorkerPattern(re.compile(r"\bsubscribe\s*\("), "subscribe", WorkerType.EVENT_CONSUMER),
    WorkerPattern(re.compile(r"\bon_message\b"), "on_message", WorkerType.EVENT_CONSUMER),
    WorkerPattern(re.compile(r"@shared_task\b|\bCelery\b"), "celery_task", WorkerType.BACKGROUND_TASK, "celery"),
    WorkerPattern(re.compile(r"\bBullMQ\b"), "bullmq", WorkerType.QUEUE_WORKER, "bullmq"),
    WorkerPattern(re.compile(r"\bSidekiq\b"), "sidekiq", WorkerType.QUEUE_WORKER, "sidekiq"),
    WorkerPattern(re.compile(r"\bcron\b", re.IGNORECASE), "cron", WorkerType.CRON_JOB, "cron"),
]

WORKER_PATH_HINTS = {"worker", "workers", "job", "jobs", "task", "tasks", "consumer", "consumers", "queue", "cron"}
QUEUE_LIBRARY_HINT = re.compile(r"\b(?:bull|bullmq|bee-queue|kue|celery|sidekiq|rq|dramatiq|resque|queue)\b", re.IGNORECASE)
BARE_PROCESS_CALL = re.compile(r"(?<!\.)\bprocess\s*\(")
NEXT_ROUTE_SUFFIXES = ("route.ts", "route.js")
TOMCAT_WEB_XML_PATTERNS = [
    (re.compile(r"<url-pattern>\s*(?P<route>[^<]+)\s*</url-pattern>", re.IGNORECASE), "tomcat_url_pattern"),
    (re.compile(r"<servlet-class>\s*(?P<class>[^<]+)\s*</servlet-class>", re.IGNORECASE), "tomcat_servlet_class"),
    (re.compile(r"<filter-class>\s*(?P<class>[^<]+)\s*</filter-class>", re.IGNORECASE), "tomcat_filter_class"),
    (re.compile(r"<listener-class>\s*(?P<class>[^<]+)\s*</listener-class>", re.IGNORECASE), "tomcat_listener_class"),
]


def detect_entrypoints(repo_root: Path, files: list[FileRecord]) -> list[Entrypoint]:
    entrypoints: list[Entrypoint] = []
    evidence_counter = 1

    def add_entrypoint(
        *,
        entrypoint_type: EntrypointType,
        file: str,
        line: int,
        framework_hint: str,
        pattern: str,
        snippet: str,
        method: str | None = None,
        route_path: str | None = None,
        handler: str | None = None,
        message: str | None = None,
    ) -> None:
        nonlocal evidence_counter
        evidence = _evidence("ev_ep", evidence_counter, file, line, pattern, snippet, message=message)
        evidence_counter += 1
        entrypoints.append(
            Entrypoint(
                id=_detector_id("ep", len(entrypoints) + 1),
                type=entrypoint_type,
                file=file,
                line=line,
                framework_hint=framework_hint,
                method=method,
                route_path=route_path,
                handler=handler,
                evidence=[evidence],
            )
        )

    for record, lines in _iter_indexed_lines(repo_root, files):
        if _is_next_api_file(record.path):
            add_entrypoint(
                entrypoint_type=EntrypointType.HTTP_ROUTE,
                file=record.path,
                line=1,
                framework_hint="nextjs",
                pattern="next_api_route",
                snippet=lines[0][1] if lines else "",
            )

        if _is_tomcat_web_xml_file(record.path):
            for line_number, tomcat_pattern, route_path, snippet in _tomcat_web_xml_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="tomcat-web-xml",
                    pattern=tomcat_pattern,
                    snippet=snippet,
                    route_path=route_path,
                )
            for line_number, method, route_path, snippet in _tomcat_security_constraint_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="tomcat-security-constraint",
                    pattern="tomcat_security_constraint",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                )

        if _is_tomcat_server_xml_file(record.path):
            for line_number, route_path, snippet, message in _tomcat_server_xml_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="tomcat-connector",
                    pattern="tomcat_connector",
                    snippet=snippet,
                    route_path=route_path,
                    message=message,
                )

        if _is_zsec_security_xml_file(record.path):
            for line_number, method, route_path, snippet, message in _zsec_security_url_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="zsec-security",
                    pattern="zsec_security_url",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    message=message,
                )

        if _is_product_api_xml_file(record.path):
            for line_number, route_path, handler, snippet, message in _product_api_xml_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="product-api-xml",
                    pattern="product_api_xml",
                    snippet=snippet,
                    route_path=route_path,
                    handler=handler,
                    message=message,
                )

        if _is_servlet_forward_config_file(record.path):
            for line_number, route_path, handler, snippet, message in _servlet_forward_config_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="servlet-forward-config",
                    pattern="servlet_forward_config",
                    snippet=snippet,
                    route_path=route_path,
                    handler=handler,
                    message=message,
                )

        if _is_java_file(record.path):
            for java_match in _java_enterprise_matches(lines):
                line_number, entrypoint_type, framework_hint, method, route_path, handler, snippet, pattern_name = java_match
                add_entrypoint(
                    entrypoint_type=entrypoint_type,
                    file=record.path,
                    line=line_number,
                    framework_hint=framework_hint,
                    pattern=pattern_name,
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_javascript_url_config_file(record.path):
            for line_number, route_path, snippet in _javascript_url_config_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="javascript-url-config",
                    pattern="javascript_url_config",
                    snippet=snippet,
                    route_path=route_path,
                )

        if _has_xml_token(record.path, lines, "ADAPRestApiMapping"):
            for line_number, route_path, handler, snippet, message in _adap_rest_api_mapping_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="adap-rest-api",
                    pattern="adap_rest_api_mapping",
                    snippet=snippet,
                    route_path=route_path,
                    handler=handler,
                    message=message,
                )

        has_urlpatterns = any("urlpatterns" in candidate_line for _, candidate_line in lines)
        if has_urlpatterns:
            for line_number, route, snippet in _django_urlpatterns_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="django",
                    pattern="django_urlpatterns",
                    snippet=snippet,
                    route_path=route,
                )

        for line_number, line in lines:
            spring_mapping = _spring_mapping_from_line(line)
            if spring_mapping is not None:
                method, route = spring_mapping
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="spring",
                    pattern="spring_mapping",
                    snippet=line,
                    method=method,
                    route_path=route,
                )

            for pattern in ENTRYPOINT_PATTERNS:
                if pattern.pattern in {"django_urlpatterns", "spring_mapping"}:
                    continue
                for match in pattern.regex.finditer(line):
                    add_entrypoint(
                        entrypoint_type=pattern.type,
                        file=record.path,
                        line=line_number,
                        framework_hint=pattern.framework_hint,
                        pattern=pattern.pattern,
                        snippet=line,
                        method=_normalized_method(_optional_group(match, "method")),
                        route_path=_optional_group(match, "route"),
                    )

    return _dedupe_entrypoints(entrypoints)


def detect_consumers(repo_root: Path, files: list[FileRecord]) -> list[Consumer]:
    consumers: list[Consumer] = []
    evidence_counter = 1

    for record, lines in _iter_indexed_lines(repo_root, files):
        has_queue_context = _has_queue_worker_context(record.path, lines)
        if _is_zsec_security_xml_file(record.path):
            for line_number, consumer_type, pattern_name, snippet, message in _zsec_security_control_matches(lines):
                evidence = _evidence(
                    "ev_cons",
                    evidence_counter,
                    record.path,
                    line_number,
                    pattern_name,
                    snippet,
                    message=message,
                )
                evidence_counter += 1
                consumers.append(
                    Consumer(
                        id=_detector_id("cons", len(consumers) + 1),
                        type=consumer_type,
                        file=record.path,
                        line=line_number,
                        pattern=pattern_name,
                        evidence=[evidence],
                    )
                )
        for line_number, line in lines:
            for pattern in CONSUMER_PATTERNS:
                if pattern.regex.search(line):
                    evidence = _evidence("ev_cons", evidence_counter, record.path, line_number, pattern.pattern, line)
                    evidence_counter += 1
                    consumers.append(
                        Consumer(
                            id=_detector_id("cons", len(consumers) + 1),
                            type=pattern.type,
                            file=record.path,
                            line=line_number,
                            pattern=pattern.pattern,
                            evidence=[evidence],
                        )
                    )
            if has_queue_context and BARE_PROCESS_CALL.search(line):
                evidence = _evidence("ev_cons", evidence_counter, record.path, line_number, "queue_operation", line)
                evidence_counter += 1
                consumers.append(
                    Consumer(
                        id=_detector_id("cons", len(consumers) + 1),
                        type=ConsumerType.QUEUE_OPERATION,
                        file=record.path,
                        line=line_number,
                        pattern="queue_operation",
                        evidence=[evidence],
                    )
                )

    return consumers


def detect_workers(repo_root: Path, files: list[FileRecord]) -> list[Worker]:
    workers: list[Worker] = []
    evidence_counter = 1
    worker_keys: set[tuple[str, str]] = set()

    for record, lines in _iter_indexed_lines(repo_root, files):
        record_workers: list[Worker] = []
        has_queue_context = _has_queue_worker_context(record.path, lines)
        if _has_xml_token(record.path, lines, "TaskEngine_Task"):
            for line_number, snippet, message in _taskengine_task_matches(lines):
                key = (record.path, f"taskengine_task:{line_number}")
                evidence = _evidence(
                    "ev_worker",
                    evidence_counter,
                    record.path,
                    line_number,
                    "taskengine_task",
                    snippet,
                    message=message,
                )
                evidence_counter += 1
                worker = Worker(
                    id=_detector_id("worker", len(workers) + 1),
                    type=WorkerType.BACKGROUND_TASK,
                    file=record.path,
                    line=line_number,
                    framework_hint="taskengine",
                    pattern="taskengine_task",
                    evidence=[evidence],
                )
                workers.append(worker)
                record_workers.append(worker)
                worker_keys.add(key)

        for line_number, line in lines:
            for pattern in WORKER_PATTERNS:
                if pattern.regex.search(line):
                    key = (record.path, pattern.pattern)
                    evidence = _evidence("ev_worker", evidence_counter, record.path, line_number, pattern.pattern, line)
                    evidence_counter += 1
                    if key in worker_keys:
                        _append_worker_evidence(workers, key, evidence)
                        continue
                    worker = Worker(
                        id=_detector_id("worker", len(workers) + 1),
                        type=pattern.type,
                        file=record.path,
                        line=line_number,
                        framework_hint=pattern.framework_hint,
                        pattern=pattern.pattern,
                        evidence=[evidence],
                    )
                    workers.append(worker)
                    record_workers.append(worker)
                    worker_keys.add(key)
            if has_queue_context and BARE_PROCESS_CALL.search(line):
                key = (record.path, "queue_process")
                evidence = _evidence("ev_worker", evidence_counter, record.path, line_number, "queue_process", line)
                evidence_counter += 1
                if key in worker_keys:
                    _append_worker_evidence(workers, key, evidence)
                    continue
                worker = Worker(
                    id=_detector_id("worker", len(workers) + 1),
                    type=WorkerType.QUEUE_WORKER,
                    file=record.path,
                    line=line_number,
                    framework_hint="queue",
                    pattern="queue_process",
                    evidence=[evidence],
                )
                workers.append(worker)
                record_workers.append(worker)
                worker_keys.add(key)

        path_hint = _worker_path_hint(record.path)
        if path_hint is not None:
            first_line = lines[0][1] if lines else ""
            evidence = _evidence("ev_worker", evidence_counter, record.path, 1, f"path_hint:{path_hint}", first_line)
            evidence_counter += 1
            if record_workers:
                record_workers[0].evidence.append(evidence)
            else:
                key = (record.path, f"path_hint:{path_hint}")
                if key in worker_keys:
                    _append_worker_evidence(workers, key, evidence)
                    continue
                workers.append(
                    Worker(
                        id=_detector_id("worker", len(workers) + 1),
                        type=WorkerType.BACKGROUND_TASK,
                        file=record.path,
                        line=1,
                        pattern=f"path_hint:{path_hint}",
                        evidence=[evidence],
                    )
                )
                worker_keys.add(key)

    return workers


def _dedupe_entrypoints(entrypoints: list[Entrypoint]) -> list[Entrypoint]:
    deduped: list[Entrypoint] = []
    by_key: dict[tuple[EntrypointType, str, str | None, str | None, str | None, str | None], Entrypoint] = {}
    for entrypoint in entrypoints:
        if entrypoint.route_path is None and entrypoint.handler is None:
            deduped.append(entrypoint)
            continue
        key = (
            entrypoint.type,
            entrypoint.file,
            entrypoint.framework_hint,
            entrypoint.method,
            entrypoint.route_path,
            entrypoint.handler,
        )
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = entrypoint
            deduped.append(entrypoint)
        else:
            existing.evidence.extend(entrypoint.evidence)
    return deduped


def _spring_mapping_from_line(line: str) -> tuple[str | None, str] | None:
    match = re.search(
        r"@(?P<name>Get|Post|Put|Patch|Delete|Request)Mapping\s*\((?P<args>[^)]*)\)",
        line,
        re.IGNORECASE,
    )
    if match is None:
        return None

    args = match.group("args")
    route_match = re.search(r"\b(?:value|path)\s*=\s*['\"](?P<route>[^'\"]+)['\"]", args)
    if route_match is None:
        route_match = re.search(r"^\s*['\"](?P<route>[^'\"]+)['\"]", args)
    if route_match is None:
        return None

    name = match.group("name").lower()
    if name == "request":
        method_match = re.search(r"\bRequestMethod\.(?P<method>GET|POST|PUT|PATCH|DELETE)\b", args, re.IGNORECASE)
        method = method_match.group("method").lower() if method_match else None
    else:
        method = name

    return method, route_match.group("route")


def _taskengine_task_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for match in re.finditer(r"<TaskEngine_Task\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        attrs = _attrs_from_tag(tag)
        if "class_name" not in attrs:
            continue
        yield (
            _line_for_offset(text, match.start()),
            _compact_snippet(tag),
            _message_from_attrs(attrs, ("task_name", "class_name")),
        )


def _tomcat_web_xml_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str | None, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for regex, pattern in TOMCAT_WEB_XML_PATTERNS:
        for match in regex.finditer(text):
            route_path = match.groupdict().get("route")
            yield (
                _line_for_offset(text, match.start()),
                pattern,
                route_path.strip() if route_path else None,
                _compact_snippet(match.group(0)),
            )


def _tomcat_security_constraint_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for match in re.finditer(r"<security-constraint\b.*?</security-constraint>", text, re.IGNORECASE | re.DOTALL):
        block = match.group(0)
        route_match = re.search(r"<url-pattern>\s*(?P<route>[^<]+)\s*</url-pattern>", block, re.IGNORECASE)
        if route_match is None:
            continue
        method_match = re.search(r"<http-method>\s*(?P<method>[^<]+)\s*</http-method>", block, re.IGNORECASE)
        yield (
            _line_for_offset(text, match.start()),
            _normalized_method(method_match.group("method") if method_match else None),
            route_match.group("route").strip(),
            _compact_snippet(block),
        )


def _tomcat_server_xml_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for match in re.finditer(r"<Connector\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        attrs = _attrs_from_tag(tag)
        port = attrs.get("port")
        if port is None:
            continue
        scheme = attrs.get("scheme", "https" if attrs.get("secure") == "true" else "http")
        message = _message_from_attrs(
            attrs,
            ("protocol", "allowTrace", "clientAuth", "sslEnabledProtocols", "redirectPort"),
        )
        yield (
            _line_for_offset(text, match.start()),
            f"{scheme}://*:{port}",
            _compact_snippet(tag),
            message,
        )


def _zsec_security_url_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for match in re.finditer(r"<url(?=\s|>)[^>]*(?:/>|>.*?</url>)", text, re.IGNORECASE | re.DOTALL):
        block = match.group(0)
        attrs = _attrs_from_tag(block.split(">", 1)[0])
        route_path = attrs.get("path")
        if route_path is None:
            continue
        details = _message_from_attrs(attrs, ("authentication", "csrf"))
        param_names = _named_xml_children(block, "param")
        throttle_names = _named_xml_children(block, "throttle")
        child_details = [*(f"param={name}" for name in param_names), *(f"throttle={name}" for name in throttle_names)]
        message = ", ".join(part for part in [details, *child_details] if part)
        yield (
            _line_for_offset(text, match.start()),
            _normalized_method(attrs.get("method")),
            route_path,
            _compact_snippet(block),
            message,
        )


def _zsec_security_control_matches(
    lines: list[tuple[int, str]],
) -> Iterable[tuple[int, ConsumerType, str, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    config_terms: list[str] = []
    for block_name in ("default-request-headers", "safe-response-headers", "content-types"):
        if re.search(rf"<{block_name}\b", text, re.IGNORECASE):
            config_terms.append(block_name)
    config_terms.extend(f"header={name}" for name in _named_xml_children(text, "header"))
    config_terms.extend(f"cookie={name}" for name in _named_xml_children(text, "cookie"))
    config_terms.extend(f"content-type={name}" for name in _named_xml_children(text, "content-type"))
    config_terms.extend(f"url-validator={name}" for name in _named_xml_children(text, "url-validator"))
    config_terms.extend(f"xsspattern={name}" for name in _named_xml_children(text, "xsspattern"))
    if config_terms:
        first_match = re.search(
            r"<(?:default-request-headers|safe-response-headers|content-types|header|cookie|content-type|url-validator|xsspattern)\b",
            text,
            re.IGNORECASE,
        )
        yield (
            _line_for_offset(text, first_match.start() if first_match else 0),
            ConsumerType.CONFIG_OPERATION,
            "zsec_security_control",
            _compact_snippet(text),
            ", ".join(config_terms),
        )

    zip_terms = [f"zip-sanitizer={name}" for name in _named_xml_children(text, "zip-sanitizer")]
    if zip_terms:
        zip_match = re.search(r"<zip-sanitizer\b", text, re.IGNORECASE)
        yield (
            _line_for_offset(text, zip_match.start() if zip_match else 0),
            ConsumerType.ARCHIVE_OPERATION,
            "zsec_zip_sanitizer",
            _compact_snippet(text),
            ", ".join(zip_terms),
        )


def _product_api_xml_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str | None, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    params_by_api = _product_api_params_by_name(text)
    for match in re.finditer(r"<(?:ADSProductAPIs|RMPProductAPIs)\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        attrs = _attrs_from_tag(tag)
        route_path = attrs.get("API_URL")
        if route_path is None:
            continue
        api_name = attrs.get("API_NAME")
        params = params_by_api.get(api_name or "", [])
        details = _message_from_attrs(
            attrs,
            (
                "MTCALL_NAME",
                "MTCALL_VALUE",
                "IS_HS_REQUIRED",
                "IS_ALLOWED_ON_DEMO",
                "REQUIRES_ACCOUNT_AUTHORIZATION",
                "ACCESS_TYPE",
            ),
        )
        message = ", ".join(part for part in [details, *(f"param={param}" for param in params)] if part)
        yield (
            _line_for_offset(text, match.start()),
            route_path,
            attrs.get("SERVLET_CLASS_NAME") or attrs.get("MTCALL_VALUE"),
            _compact_snippet(tag),
            message,
        )


def _servlet_forward_config_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str | None, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for match in re.finditer(r"<request\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        attrs = _attrs_from_tag(tag)
        route_path = attrs.get("url")
        if route_path is None:
            continue
        message = _message_from_attrs(attrs, ("forward", "servlet"))
        yield (
            _line_for_offset(text, match.start()),
            route_path,
            attrs.get("servlet") or attrs.get("forward"),
            _compact_snippet(tag),
            message,
        )


def _adap_rest_api_mapping_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str | None, str, str]]:
    text = _strip_xml_comments(_joined_lines(lines))
    for match in re.finditer(r"<ADAPRestApiMapping\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        tag = match.group(0)
        attrs = _attrs_from_tag(tag)
        route_path = attrs.get("URL_PATH")
        if route_path is None:
            continue
        class_name = attrs.get("CLASS_NAME")
        method_name = attrs.get("METHOD_NAME")
        handler = f"{class_name}#{method_name}" if class_name and method_name else class_name or method_name
        yield (
            _line_for_offset(text, match.start()),
            route_path,
            handler,
            _compact_snippet(tag),
            _message_from_attrs(attrs, ("ACCESS_ID", "ACCESS_TYPE", "TAB_NAME", "DESCRIPTION")),
        )


def _java_enterprise_matches(
    lines: list[tuple[int, str]],
) -> Iterable[tuple[int, EntrypointType, str, str | None, str | None, str | None, str, str]]:
    text = _joined_lines(lines)
    strong_handlers: set[str] = set()

    for match in re.finditer(
        r"@WebServlet\s*\((?P<args>.*?)\)\s*(?:public\s+)?class\s+(?P<class>[A-Za-z_]\w*)",
        text,
        re.IGNORECASE | re.DOTALL,
    ):
        class_name = match.group("class")
        strong_handlers.add(class_name)
        for route in _routes_from_annotation_args(match.group("args")):
            yield (
                _line_for_offset(text, match.start()),
                EntrypointType.HTTP_ROUTE,
                "java-webservlet",
                None,
                route,
                class_name,
                _compact_snippet(match.group(0)),
                "java_webservlet",
            )

    for class_match in re.finditer(
        r"@Path\s*\(\s*['\"](?P<base>[^'\"]+)['\"]\s*\)\s*(?:public\s+)?class\s+(?P<class>[A-Za-z_]\w*)",
        text,
        re.IGNORECASE,
    ):
        class_name = class_match.group("class")
        strong_handlers.add(class_name)
        class_body = text[class_match.end() : _next_java_class_offset(text, class_match.end())]
        for method_match in re.finditer(
            r"@(?P<verb>GET|POST|PUT|PATCH|DELETE)\b\s*@Path\s*\(\s*['\"](?P<route>[^'\"]+)['\"]\s*\)\s*public\s+[\w<>\[\], ?]+\s+(?P<method>[A-Za-z_]\w*)\s*\(",
            class_body,
            re.IGNORECASE,
        ):
            yield (
                _line_for_offset(text, class_match.end() + method_match.start()),
                EntrypointType.HTTP_ROUTE,
                "jax-rs",
                method_match.group("verb").lower(),
                _join_route_parts(class_match.group("base"), method_match.group("route")),
                f"{class_name}#{method_match.group('method')}",
                _compact_snippet(method_match.group(0)),
                "jax_rs",
            )

    for class_match in re.finditer(r"@WebService\b.*?class\s+(?P<class>[A-Za-z_]\w*)", text, re.IGNORECASE | re.DOTALL):
        class_name = class_match.group("class")
        strong_handlers.add(class_name)
        class_body = text[class_match.end() : _next_java_class_offset(text, class_match.end())]
        for method_match in re.finditer(
            r"@WebMethod\b\s*public\s+[\w<>\[\], ?]+\s+(?P<method>[A-Za-z_]\w*)\s*\(",
            class_body,
            re.IGNORECASE,
        ):
            yield (
                _line_for_offset(text, class_match.end() + method_match.start()),
                EntrypointType.RPC_HANDLER,
                "java-soap",
                None,
                None,
                f"{class_name}#{method_match.group('method')}",
                _compact_snippet(method_match.group(0)),
                "java_soap",
            )

    for class_match in re.finditer(
        r"\bclass\s+(?P<class>[A-Za-z_]\w*(?:Controller|RestService|Servlet|ApiHandler|Action))\b",
        text,
    ):
        class_name = class_match.group("class")
        if class_name in strong_handlers:
            continue
        yield (
            _line_for_offset(text, class_match.start()),
            EntrypointType.GENERIC,
            "java-enterprise-handler",
            None,
            None,
            class_name,
            _compact_snippet(class_match.group(0)),
            "java_enterprise_handler",
        )


def _javascript_url_config_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str]]:
    for line_number, line in lines:
        match = re.search(
            r"\b(?:url|endpoint|apiUrl|action|mapping|methodToCall)\b\s*[:=]\s*['\"](?P<route>/[^'\"]+)['\"]",
            line,
            re.IGNORECASE,
        )
        if match is not None:
            yield line_number, match.group("route"), line


def _django_urlpatterns_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str]]:
    for index, (line_number, line) in enumerate(lines):
        if re.search(r"\b(?:path|re_path)\s*\(", line) is None:
            continue

        same_line_route = re.search(r"\b(?:path|re_path)\s*\(\s*['\"](?P<route>[^'\"]+)", line)
        if same_line_route is not None:
            yield line_number, same_line_route.group("route"), line
            continue

        for route_line_number, route_line in lines[index + 1 : index + 5]:
            route_match = re.search(r"['\"](?P<route>[^'\"]+)['\"]", route_line)
            if route_match is not None:
                yield route_line_number, route_match.group("route"), route_line
                break


def _iter_indexed_lines(repo_root: Path, files: list[FileRecord]) -> Iterable[tuple[FileRecord, list[tuple[int, str]]]]:
    for record in files:
        path = repo_root / record.path
        content = path.read_text(encoding="utf-8", errors="replace")
        yield record, list(enumerate(content.splitlines(), start=1))


def _evidence(
    prefix: str,
    counter: int,
    file: str,
    line: int,
    pattern: str,
    snippet: str,
    *,
    message: str | None = None,
    symbol: str | None = None,
) -> Evidence:
    return Evidence(
        id=_detector_id(prefix, counter),
        type=EvidenceType.PATTERN_MATCH,
        file=file,
        line=line,
        pattern=pattern,
        snippet=snippet.strip(),
        message=message,
        symbol=symbol,
    )


def _detector_id(prefix: str, counter: int) -> str:
    return f"{prefix}_{counter:04d}"


def _optional_group(match: re.Match[str], name: str) -> str | None:
    return match.groupdict().get(name)


def _normalized_method(method: str | None) -> str | None:
    if method is None:
        return None
    return method.removesuffix("Mapping").lower()


def _append_worker_evidence(workers: list[Worker], key: tuple[str, str], evidence: Evidence) -> None:
    for worker in workers:
        if (worker.file, worker.pattern) == key:
            worker.evidence.append(evidence)
            return


def _is_next_api_file(relative_path: str) -> bool:
    return relative_path.startswith("pages/api/") or (
        relative_path.startswith("app/api/") and relative_path.endswith(NEXT_ROUTE_SUFFIXES)
    )


def _is_tomcat_web_xml_file(relative_path: str) -> bool:
    return relative_path in {"WEB-INF/web.xml", "conf/web.xml"} or relative_path.endswith(
        ("/WEB-INF/web.xml", "/conf/web.xml")
    )


def _is_tomcat_server_xml_file(relative_path: str) -> bool:
    return relative_path == "conf/server.xml" or relative_path.endswith("/conf/server.xml")


def _is_zsec_security_xml_file(relative_path: str) -> bool:
    path = Path(relative_path)
    return path.name.startswith("security-") and path.suffix.lower() == ".xml" and (
        "conf" in path.parts or path.parts[-3:-1] == ("WEB-INF", "security")
    )


def _is_product_api_xml_file(relative_path: str) -> bool:
    return Path(relative_path).name in {"ADSProductAPIs.xml", "RMPProductAPIs.xml"}


def _is_servlet_forward_config_file(relative_path: str) -> bool:
    return Path(relative_path).name == "Servlet-Forward-Config.xml"


def _is_java_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".java"


def _is_javascript_url_config_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".cc"}


def _has_xml_token(relative_path: str, lines: list[tuple[int, str]], token: str) -> bool:
    return Path(relative_path).suffix.lower() == ".xml" and any(token in line for _, line in lines)


def _strip_xml_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", lambda match: "\n" * match.group(0).count("\n"), text, flags=re.DOTALL)


def _joined_lines(lines: list[tuple[int, str]]) -> str:
    return "\n".join(line for _, line in lines)


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _compact_snippet(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 1]}…"


def _attrs_from_tag(tag_text: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("value")
        for match in re.finditer(
            r"(?P<name>[A-Za-z_:][\w:.-]*)\s*=\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
            tag_text,
            re.DOTALL,
        )
    }


def _message_from_attrs(attrs: dict[str, str], names: tuple[str, ...]) -> str:
    return ", ".join(f"{name}={attrs[name]}" for name in names if name in attrs)


def _named_xml_children(text: str, tag_name: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(rf"<{tag_name}\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        name = _attrs_from_tag(match.group(0)).get("name")
        if name is not None:
            names.append(name)
    return names


def _product_api_params_by_name(text: str) -> dict[str, list[str]]:
    params: dict[str, list[str]] = {}
    for match in re.finditer(r"<ADSProductAPIParams\b[^>]*(?:/>|>)", text, re.IGNORECASE | re.DOTALL):
        attrs = _attrs_from_tag(match.group(0))
        api_name = attrs.get("API_NAME")
        param_name = attrs.get("PARAM_NAME") or attrs.get("PARAMETER_NAME") or attrs.get("NAME")
        if api_name is not None and param_name is not None:
            params.setdefault(api_name, []).append(param_name)
    return params


def _routes_from_annotation_args(args: str) -> list[str]:
    return re.findall(r"['\"](?P<route>/[^'\"]+)['\"]", args)


def _next_java_class_offset(text: str, offset: int) -> int:
    match = re.search(r"\n\s*(?:public\s+)?class\s+[A-Za-z_]\w*", text[offset:])
    return len(text) if match is None else offset + match.start()


def _join_route_parts(base: str, route: str) -> str:
    return f"/{base.strip('/')}/{route.strip('/')}"


def _worker_path_hint(relative_path: str) -> str | None:
    path_parts = Path(relative_path).parts
    for part in path_parts:
        stem = Path(part).stem.lower()
        if stem in WORKER_PATH_HINTS:
            return stem
    return None


def _has_queue_worker_context(relative_path: str, lines: list[tuple[int, str]]) -> bool:
    if _worker_path_hint(relative_path) is not None:
        return True
    return any(QUEUE_LIBRARY_HINT.search(line) for _, line in lines)
