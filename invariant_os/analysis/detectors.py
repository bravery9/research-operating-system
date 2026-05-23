"""Heuristic static detectors for indexed repository files."""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import re

from invariant_os.core.config import AuditConfig
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
NEXT_APP_ROUTE_METHOD = re.compile(
    r"\bexport\s+(?:async\s+)?function\s+(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"
)


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
NEXT_ROUTE_FILENAMES = {"route.js", "route.jsx", "route.ts", "route.tsx"}
TOMCAT_WEB_XML_PATTERNS = [
    (re.compile(r"<url-pattern>\s*(?P<route>[^<]+)\s*</url-pattern>", re.IGNORECASE), "tomcat_url_pattern"),
    (re.compile(r"<servlet-class>\s*(?P<class>[^<]+)\s*</servlet-class>", re.IGNORECASE), "tomcat_servlet_class"),
    (re.compile(r"<filter-class>\s*(?P<class>[^<]+)\s*</filter-class>", re.IGNORECASE), "tomcat_filter_class"),
    (re.compile(r"<listener-class>\s*(?P<class>[^<]+)\s*</listener-class>", re.IGNORECASE), "tomcat_listener_class"),
]


def known_entrypoint_patterns() -> set[str]:
    return {
        *(pattern.pattern for pattern in ENTRYPOINT_PATTERNS),
        *(pattern_name for _, pattern_name in TOMCAT_WEB_XML_PATTERNS),
        "adap_rest_api_mapping",
        "aiohttp_route",
        "aspnet_route",
        "bottle_route",
        "go_route",
        "hapi_route",
        "java_enterprise_handler",
        "java_soap",
        "java_webservlet",
        "javascript_url_config",
        "kotlin_route",
        "laravel_route",
        "jax_rs",
        "clojure_route",
        "next_api_route",
        "nestjs_route",
        "phoenix_route",
        "pyramid_route",
        "servant_route",
        "play_route",
        "product_api_xml",
        "rails_route",
        "rust_route",
        "sanic_route",
        "servlet_forward_config",
        "starlette_route",
        "sinatra_route",
        "spark_route",
        "spring_mapping",
        "tomcat_connector",
        "tomcat_security_constraint",
        "tornado_route",
        "zsec_security_url",
    }


def known_consumer_patterns() -> set[str]:
    return {
        *(pattern.pattern for pattern in CONSUMER_PATTERNS),
        "queue_operation",
        "zsec_security_control",
        "zsec_zip_sanitizer",
    }


def known_worker_patterns() -> set[str]:
    return {
        *(pattern.pattern for pattern in WORKER_PATTERNS),
        "path_hint",
        "queue_process",
        "taskengine_task",
    }


def known_detector_patterns() -> dict[str, set[str]]:
    return {
        "entrypoints": known_entrypoint_patterns(),
        "consumers": known_consumer_patterns(),
        "workers": known_worker_patterns(),
    }


def detect_entrypoints(repo_root: Path, files: list[FileRecord], config: AuditConfig | None = None) -> list[Entrypoint]:
    entrypoints: list[Entrypoint] = []
    allowed_patterns = _allowed_detector_patterns("entrypoints", config)
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
        if not _is_detector_allowed(pattern, allowed_patterns):
            return
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
        is_python = _is_python_file(record.path)
        is_javascript = _is_javascript_file(record.path)
        spring_allowed = _is_detector_allowed("spring_mapping", allowed_patterns)
        spring_source = spring_allowed and (_is_java_file(record.path) or _is_kotlin_file(record.path))

        if _is_next_api_file(record.path) and _is_detector_allowed("next_api_route", allowed_patterns):
            add_entrypoint(
                entrypoint_type=EntrypointType.HTTP_ROUTE,
                file=record.path,
                line=1,
                framework_hint="nextjs",
                pattern="next_api_route",
                snippet=lines[0][1] if lines else "",
                method=_next_app_route_method(lines) if _is_next_app_route_file(record.path) else None,
                route_path=_next_api_route_path(record.path),
            )

        if is_javascript and _is_nestjs_source(lines):
            for line_number, method, nest_route_path, handler, snippet in _nestjs_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="nestjs",
                    pattern="nestjs_route",
                    snippet=snippet,
                    method=method,
                    route_path=nest_route_path,
                    handler=handler,
                )

        if is_javascript and _is_hapi_source(lines):
            for line_number, method, hapi_route_path, handler, snippet in _hapi_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="hapi",
                    pattern="hapi_route",
                    snippet=snippet,
                    method=method,
                    route_path=hapi_route_path,
                    handler=handler,
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
            for line_number, method, spark_route_path, handler, snippet in _spark_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="spark-java",
                    pattern="spark_route",
                    snippet=snippet,
                    method=method,
                    route_path=spark_route_path,
                    handler=handler,
                )
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

        if is_python and _is_pyramid_source(lines):
            for line_number, method, pyramid_route_path, handler, snippet in _pyramid_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="pyramid",
                    pattern="pyramid_route",
                    snippet=snippet,
                    method=method,
                    route_path=pyramid_route_path,
                    handler=handler,
                )

        if is_python and _is_starlette_source(lines):
            for line_number, method, starlette_route_path, handler, snippet in _starlette_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="starlette",
                    pattern="starlette_route",
                    snippet=snippet,
                    method=method,
                    route_path=starlette_route_path,
                    handler=handler,
                )

        if is_python and _is_sanic_source(lines):
            for line_number, method, sanic_route_path, handler, snippet in _sanic_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="sanic",
                    pattern="sanic_route",
                    snippet=snippet,
                    method=method,
                    route_path=sanic_route_path,
                    handler=handler,
                )

        if is_python and _is_tornado_source(lines):
            for line_number, method, tornado_route_path, handler, snippet in _tornado_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="tornado",
                    pattern="tornado_route",
                    snippet=snippet,
                    method=method,
                    route_path=tornado_route_path,
                    handler=handler,
                )

        if is_python and _is_aiohttp_source(lines):
            for line_number, method, aiohttp_route_path, handler, snippet in _aiohttp_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="aiohttp",
                    pattern="aiohttp_route",
                    snippet=snippet,
                    method=method,
                    route_path=aiohttp_route_path,
                    handler=handler,
                )

        if _is_bottle_file(record.path) and _is_bottle_source(lines):
            for line_number, method, route_path, handler, snippet in _bottle_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="bottle",
                    pattern="bottle_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_go_file(record.path):
            for line_number, method, route_path, handler, snippet in _go_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="go-http",
                    pattern="go_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_csharp_file(record.path):
            for line_number, method, route_path, handler, snippet in _aspnet_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="aspnet-core",
                    pattern="aspnet_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_rust_file(record.path):
            for line_number, method, route_path, handler, snippet in _rust_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="rust-web",
                    pattern="rust_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_kotlin_file(record.path):
            for line_number, method, route_path, handler, snippet in _kotlin_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="kotlin-web",
                    pattern="kotlin_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_play_routes_file(record.path):
            for line_number, method, route_path, handler, snippet in _play_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="scala-play",
                    pattern="play_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_elixir_file(record.path):
            for line_number, method, route_path, handler, snippet in _phoenix_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="phoenix",
                    pattern="phoenix_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_clojure_file(record.path):
            for line_number, method, route_path, handler, snippet in _clojure_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="clojure-web",
                    pattern="clojure_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_haskell_file(record.path):
            for line_number, method, route_path, handler, snippet in _servant_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="haskell-servant",
                    pattern="servant_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_ruby_file(record.path):
            if _is_sinatra_source(lines):
                for line_number, method, route_path, handler, snippet in _sinatra_route_matches(lines):
                    add_entrypoint(
                        entrypoint_type=EntrypointType.HTTP_ROUTE,
                        file=record.path,
                        line=line_number,
                        framework_hint="sinatra",
                        pattern="sinatra_route",
                        snippet=snippet,
                        method=method,
                        route_path=route_path,
                        handler=handler,
                    )
            for line_number, method, route_path, handler, snippet in _rails_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="rails",
                    pattern="rails_route",
                    snippet=snippet,
                    method=method,
                    route_path=route_path,
                    handler=handler,
                )

        if _is_php_file(record.path):
            for line_number, method, route_path, handler, snippet in _laravel_route_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="laravel",
                    pattern="laravel_route",
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
            for line_number, route, handler, snippet in _django_urlpatterns_matches(lines):
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="django",
                    pattern="django_urlpatterns",
                    snippet=snippet,
                    route_path=route,
                    handler=handler,
                )

        enriched_spring_lines: set[int] = set()
        if spring_source:
            for line_number, method, route, handler, snippet in _spring_mapping_matches(lines):
                enriched_spring_lines.add(line_number)
                add_entrypoint(
                    entrypoint_type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=line_number,
                    framework_hint="spring",
                    pattern="spring_mapping",
                    snippet=snippet,
                    method=method,
                    route_path=route,
                    handler=handler,
                )

        for index, (line_number, line) in enumerate(lines):
            if spring_source:
                spring_mapping = _spring_mapping_from_line(line)
                if spring_mapping is not None and line_number not in enriched_spring_lines:
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
                if not _is_detector_allowed(pattern.pattern, allowed_patterns):
                    continue
                for match in pattern.regex.finditer(line):
                    if pattern.pattern == "express_route":
                        handler = _javascript_route_handler_from_line(line, match)
                    elif pattern.pattern in {"fastapi_route", "flask_route"}:
                        handler = _python_handler_after(lines, index)
                    else:
                        handler = None
                    method = (
                        _flask_route_method(line)
                        if pattern.pattern == "flask_route"
                        else _normalized_method(_optional_group(match, "method"))
                    )
                    add_entrypoint(
                        entrypoint_type=pattern.type,
                        file=record.path,
                        line=line_number,
                        framework_hint=pattern.framework_hint,
                        pattern=pattern.pattern,
                        snippet=line,
                        method=method,
                        route_path=_optional_group(match, "route"),
                        handler=handler,
                    )

    return _dedupe_entrypoints(entrypoints)


def detect_consumers(repo_root: Path, files: list[FileRecord], config: AuditConfig | None = None) -> list[Consumer]:
    consumers: list[Consumer] = []
    allowed_patterns = _allowed_detector_patterns("consumers", config)
    evidence_counter = 1

    for record, lines in _iter_indexed_lines(repo_root, files):
        has_queue_context = _has_queue_worker_context(record.path, lines)
        if _is_zsec_security_xml_file(record.path):
            for line_number, consumer_type, pattern_name, snippet, message in _zsec_security_control_matches(lines):
                if not _is_detector_allowed(pattern_name, allowed_patterns):
                    continue
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
                if _is_detector_allowed(pattern.pattern, allowed_patterns) and pattern.regex.search(line):
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
            if has_queue_context and _is_detector_allowed("queue_operation", allowed_patterns) and BARE_PROCESS_CALL.search(line):
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


def detect_workers(repo_root: Path, files: list[FileRecord], config: AuditConfig | None = None) -> list[Worker]:
    workers: list[Worker] = []
    allowed_patterns = _allowed_detector_patterns("workers", config)
    evidence_counter = 1
    worker_keys: set[tuple[str, str]] = set()

    for record, lines in _iter_indexed_lines(repo_root, files):
        record_workers: list[Worker] = []
        has_queue_context = _has_queue_worker_context(record.path, lines)
        if _has_xml_token(record.path, lines, "TaskEngine_Task") and _is_detector_allowed("taskengine_task", allowed_patterns):
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
                if _is_detector_allowed(pattern.pattern, allowed_patterns) and pattern.regex.search(line):
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
            if has_queue_context and _is_detector_allowed("queue_process", allowed_patterns) and BARE_PROCESS_CALL.search(line):
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
        if path_hint is not None and _is_detector_allowed("path_hint", allowed_patterns):
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


def _allowed_detector_patterns(detector_type: str, config: AuditConfig | None) -> set[str] | None:
    if config is None:
        return None
    selections = {
        "entrypoints": config.focus.detectors.entrypoints,
        "consumers": config.focus.detectors.consumers,
        "workers": config.focus.detectors.workers,
    }
    known = known_detector_patterns()[detector_type]
    selection = selections[detector_type]
    allowed = set(selection.include) if selection.include else set(known)
    allowed.difference_update(selection.exclude)
    return allowed


def _is_detector_allowed(pattern: str, allowed_patterns: set[str] | None) -> bool:
    return allowed_patterns is None or pattern in allowed_patterns


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


def _python_handler_after(lines: list[tuple[int, str]], index: int) -> str | None:
    for _, candidate in lines[index + 1 : index + 8]:
        match = re.search(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\(", candidate)
        if match is not None:
            return match.group("name")
        stripped = candidate.strip()
        if stripped and not stripped.startswith("@"):
            return None
    return None



def _single_list_method(args: str, keyword: str = "methods") -> str | None:
    methods_match = re.search(rf"\b{keyword}\s*=\s*\[(?P<methods>[^\]]*)\]", args)
    if methods_match is None:
        return None
    methods = re.findall(r"['\"](?P<method>[A-Za-z]+)['\"]", methods_match.group("methods"))
    return _normalized_method(methods[0]) if len(methods) == 1 else None


def _flask_route_method(line: str) -> str | None:
    return _single_list_method(line)



def _javascript_route_handler_from_line(line: str, route_match: re.Match[str]) -> str | None:
    remainder = line[route_match.end() :]
    handler_match = re.search(
        r"^\s*['\"]\s*,\s*"
        r"(?:(?:async\s+)?function\s+(?P<function>[A-Za-z_$][\w$]*)\s*\(|"
        r"(?P<identifier>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\b)",
        remainder,
    )
    if handler_match is None:
        return None
    return handler_match.group("function") or handler_match.group("identifier")



def _nestjs_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    text = _joined_lines(lines)
    for class_match in re.finditer(
        r"@Controller\s*\(\s*['\"](?P<prefix>[^'\"]*)['\"]\s*\)\s*"
        r"(?:export\s+)?class\s+(?P<class>[A-Za-z_$][\w$]*)\s*\{(?P<body>.*?)(?=\n\s*@Controller|\Z)",
        text,
        re.DOTALL,
    ):
        class_name = class_match.group("class")
        prefix = class_match.group("prefix")
        body = class_match.group("body")
        for route_match in re.finditer(
            r"@(?P<method>Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*['\"](?P<route>[^'\"]*)['\"]\s*\)\s*"
            r"(?:(?:public|private|protected|async|static)\s+)*"
            r"(?P<handler>[A-Za-z_$][\w$]*)\s*\(",
            body,
        ):
            yield (
                _line_for_offset(text, class_match.start("body") + route_match.start()),
                route_match.group("method").lower(),
                _join_route_parts(prefix, route_match.group("route")),
                f"{class_name}#{route_match.group('handler')}",
                _compact_snippet(route_match.group(0)),
            )



def _hapi_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    text = _joined_lines(lines)
    for route_match in re.finditer(r"\bserver\.route\s*\(\s*\{(?P<body>.*?)\}\s*\)", text, re.DOTALL):
        body = route_match.group("body")
        method_match = re.search(r"\bmethod\s*:\s*['\"](?P<method>[A-Za-z]+)['\"]", body)
        path_match = re.search(r"\bpath\s*:\s*['\"](?P<route>/[^'\"]*)['\"]", body)
        if method_match is None or path_match is None:
            continue
        yield (
            _line_for_offset(text, route_match.start()),
            _normalized_method(method_match.group("method")),
            path_match.group("route"),
            _hapi_handler_from_body(body),
            _compact_snippet(route_match.group(0)),
        )



def _hapi_handler_from_body(body: str) -> str | None:
    handler_match = re.search(r"\bhandler\s*:\s*(?P<handler>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\b", body)
    if handler_match is None:
        return None
    return handler_match.group("handler")



def _pyramid_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    views = _pyramid_view_handlers(lines)
    for line_number, line in lines:
        route_match = re.search(r"\b\w+\.add_route\s*\(\s*(?P<args>.*)\)\s*$", line)
        if route_match is None:
            continue
        parsed = _pyramid_add_route_args(route_match.group("args"))
        if parsed is None:
            continue
        route_name, route_path = parsed
        view = views.get(route_name)
        method, handler = view if view is not None else (None, None)
        yield line_number, method, route_path, handler, line



def _pyramid_add_route_args(args: str) -> tuple[str, str] | None:
    name_match = re.search(r"(?:^\s*['\"](?P<pos>[^'\"]+)['\"]|\bname\s*=\s*['\"](?P<kw>[^'\"]+)['\"])", args)
    pattern_match = re.search(
        r"(?:^\s*['\"][^'\"]+['\"]\s*,\s*['\"](?P<pos>/[^'\"]*)['\"]|\bpattern\s*=\s*['\"](?P<kw>/[^'\"]*)['\"])",
        args,
    )
    if name_match is None or pattern_match is None:
        return None
    return name_match.group("pos") or name_match.group("kw"), pattern_match.group("pos") or pattern_match.group("kw")



def _pyramid_view_handlers(lines: list[tuple[int, str]]) -> dict[str, tuple[str | None, str | None]]:
    handlers: dict[str, tuple[str | None, str | None]] = {}
    for index, (_, line) in enumerate(lines):
        view_match = re.search(r"@view_config\s*\((?P<args>[^)]*)\)", line)
        if view_match is None:
            continue
        route_match = re.search(r"\broute_name\s*=\s*['\"](?P<route>[^'\"]+)['\"]", view_match.group("args"))
        if route_match is None:
            continue
        method_match = re.search(r"\brequest_method\s*=\s*['\"](?P<method>[A-Za-z]+)['\"]", view_match.group("args"))
        handlers[route_match.group("route")] = (
            _normalized_method(method_match.group("method") if method_match else None),
            _python_handler_after(lines, index),
        )
    return handlers



def _starlette_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        route_match = re.search(r"\bRoute\s*\(\s*(?P<args>.*)\)\s*,?\s*$", line)
        if route_match is not None:
            parsed = _starlette_route_args(route_match.group("args"))
            if parsed is not None:
                route_path, handler = parsed
                yield line_number, _starlette_route_method(route_match.group("args")), route_path, handler, line
            continue

        add_route_match = re.search(r"\b\w+\.add_route\s*\(\s*(?P<args>.*)\)\s*$", line)
        if add_route_match is None:
            continue
        parsed = _starlette_add_route_args(add_route_match.group("args"))
        if parsed is None:
            continue
        route_path, handler = parsed
        yield line_number, _starlette_route_method(add_route_match.group("args")), route_path, handler, line



def _starlette_route_args(args: str) -> tuple[str, str] | None:
    route_match = re.search(r"(?:^\s*['\"](?P<pos>/[^'\"]*)['\"]|\bpath\s*=\s*['\"](?P<kw>/[^'\"]*)['\"])", args)
    if route_match is None:
        return None

    handler_match = re.search(
        r"\bendpoint\s*=\s*(?P<keyword>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
        args,
    )
    if handler_match is None:
        handler_match = re.search(
            r"^\s*['\"]/[^'\"]*['\"]\s*,\s*(?P<positional>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
            args,
        )
    if handler_match is None:
        return None
    handler = handler_match.groupdict().get("keyword") or handler_match.groupdict().get("positional")
    if handler is None:
        return None
    return route_match.group("pos") or route_match.group("kw"), handler



def _starlette_add_route_args(args: str) -> tuple[str, str] | None:
    match = re.search(
        r"^\s*['\"](?P<route>/[^'\"]*)['\"]\s*,\s*(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
        args,
    )
    if match is None:
        return None
    return match.group("route"), match.group("handler")



def _starlette_route_method(args: str) -> str | None:
    return _single_list_method(args)



def _sanic_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for index, (line_number, line) in enumerate(lines):
        decorator_match = re.search(
            r"^\s*@\w+\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['\"](?P<route>/[^'\"]*)['\"]\s*\)",
            line,
        )
        if decorator_match is not None:
            yield (
                line_number,
                decorator_match.group("method"),
                decorator_match.group("route"),
                _python_handler_after(lines, index),
                line,
            )
            continue

        add_route_match = re.search(
            r"\b\w+\.add_route\s*\(\s*(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*,\s*['\"](?P<route>/[^'\"]*)['\"](?P<args>[^)]*)\)",
            line,
        )
        if add_route_match is None:
            continue
        yield (
            line_number,
            _sanic_route_method(add_route_match.group("args")),
            add_route_match.group("route"),
            add_route_match.group("handler"),
            line,
        )



def _sanic_route_method(args: str) -> str | None:
    return _single_list_method(args)



def _tornado_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    text = _joined_lines(lines)
    handler_methods = _tornado_handler_methods(text)
    for route_match in re.finditer(
        r"\(\s*r?['\"](?P<route>/[^'\"]*)['\"]\s*,\s*(?P<handler>[A-Za-z_]\w*)\s*\)",
        text,
    ):
        handler = route_match.group("handler")
        method = handler_methods.get(handler)
        yield (
            _line_for_offset(text, route_match.start()),
            method,
            route_match.group("route"),
            f"{handler}#{method}" if method is not None else handler,
            _compact_snippet(route_match.group(0)),
        )



def _tornado_handler_methods(text: str) -> dict[str, str | None]:
    methods_by_handler: dict[str, str | None] = {}
    for class_match in re.finditer(
        r"class\s+(?P<class>[A-Za-z_]\w*)\s*\([^)]*RequestHandler[^)]*\)\s*:(?P<body>.*?)(?=\nclass\s+|\Z)",
        text,
        re.DOTALL,
    ):
        methods = re.findall(r"^\s+(?:async\s+)?def\s+(get|post|put|patch|delete|head|options)\s*\(", class_match.group("body"), re.MULTILINE)
        methods_by_handler[class_match.group("class")] = methods[0] if len(methods) == 1 else None
    return methods_by_handler



def _aiohttp_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for index, (line_number, line) in enumerate(lines):
        decorator_match = re.search(
            r"^\s*@\w+\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['\"](?P<route>/[^'\"]*)['\"]\s*\)",
            line,
        )
        if decorator_match is not None:
            yield (
                line_number,
                decorator_match.group("method"),
                decorator_match.group("route"),
                _python_handler_after(lines, index),
                line,
            )
            continue

        router_match = re.search(
            r"\bapp\.router\.add_(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['\"](?P<route>/[^'\"]*)['\"]\s*,\s*(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
            line,
        )
        if router_match is None:
            continue
        yield (
            line_number,
            router_match.group("method"),
            router_match.group("route"),
            router_match.group("handler"),
            line,
        )



def _bottle_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for index, (line_number, line) in enumerate(lines):
        route_match = re.search(r"^\s*@route\s*\(\s*['\"](?P<route>[^'\"]+)['\"](?P<args>[^)]*)\)", line)
        if route_match is None:
            continue
        yield (
            line_number,
            _bottle_route_method(route_match.group("args")),
            route_match.group("route"),
            _python_handler_after(lines, index),
            line,
        )



def _bottle_route_method(args: str) -> str | None:
    method_match = re.search(r"\bmethod\s*=\s*(?:['\"](?P<string>[A-Za-z]+)['\"]|\[\s*['\"](?P<list>[A-Za-z]+)['\"]\s*\])", args)
    method = method_match.group("string") or method_match.group("list") if method_match else None
    return _normalized_method(method)



def _spring_mapping_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    text = _joined_lines(lines)
    for class_match in re.finditer(
        r"(?P<annotations>(?:\s*@(?:RestController|Controller|RequestMapping)\b[^\n]*\n)*)"
        r"\s*(?:public\s+)?class\s+(?P<class>[A-Za-z_]\w*)\b",
        text,
        re.IGNORECASE,
    ):
        class_name = class_match.group("class")
        class_prefix = _spring_class_route_prefix(class_match.group("annotations") or "")
        class_body_start = class_match.end()
        class_body_end = _next_java_class_offset(text, class_body_start)
        class_body = text[class_body_start:class_body_end]

        for method_match in re.finditer(
            r"(?P<annotation>@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\([^)]*\))"
            r"\s*(?:public|private|protected)?\s*"
            r"[\w<>\[\], ?.@]+\s+"
            r"(?P<method_name>[A-Za-z_]\w*)\s*\(",
            class_body,
            re.IGNORECASE,
        ):
            mapping = _spring_mapping_from_line(method_match.group("annotation"))
            if mapping is None:
                continue
            method, route = mapping
            yield (
                _line_for_offset(text, class_body_start + method_match.start()),
                method,
                _join_route_parts(class_prefix, route) if class_prefix else route,
                f"{class_name}#{method_match.group('method_name')}",
                _compact_snippet(method_match.group(0)),
            )


def _spring_class_route_prefix(annotations: str) -> str | None:
    for line in annotations.splitlines():
        mapping = _spring_mapping_from_line(line)
        if mapping is not None:
            _, route = mapping
            return route
    return None



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


def _spark_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    if not any("spark.Spark" in line for _, line in lines):
        return
    for line_number, line in lines:
        route_match = re.search(
            r'\b(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*"(?P<route>/[^"]*)"\s*,\s*(?P<handler>[^);]+)',
            line,
        )
        if route_match is None:
            continue
        yield (
            line_number,
            route_match.group("method"),
            route_match.group("route"),
            _spark_handler_name(route_match.group("handler")),
            line,
        )



def _spark_handler_name(value: str) -> str | None:
    handler = value.strip()
    match = re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*::[A-Za-z_]\w*", handler)
    if match is None:
        return None
    return handler



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


def _go_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        method_match = re.search(
            r"\b[A-Za-z_]\w*\.(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Get|Post|Put|Patch|Delete|Head|Options)"
            r'\s*\(\s*"(?P<route>/[^"]*)"\s*,\s*(?P<handler>[^,)]+)',
            line,
        )
        if method_match is not None:
            yield (
                line_number,
                method_match.group("method").lower(),
                method_match.group("route"),
                _go_handler_name(method_match.group("handler")),
                line,
            )
            continue

        handle_match = re.search(
            r'\b[A-Za-z_]\w*\.Handle(?:Func)?\s*\(\s*"(?P<route>/[^"]*)"\s*,\s*(?P<handler>[^,)]+)',
            line,
        )
        if handle_match is not None:
            yield (
                line_number,
                None,
                handle_match.group("route"),
                _go_handler_name(handle_match.group("handler")),
                line,
            )



def _go_handler_name(value: str) -> str | None:
    handler = value.strip()
    if handler.startswith("func"):
        return None
    match = re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", handler)
    if match is None:
        return None
    return handler



def _aspnet_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    text = _joined_lines(lines)
    for class_match in re.finditer(
        r"(?P<attributes>(?:\s*\[[^\]]+\]\s*)*)\s*"
        r"(?:public\s+)?class\s+(?P<class>[A-Za-z_]\w*)\b",
        text,
        re.IGNORECASE,
    ):
        class_name = class_match.group("class")
        class_prefix = _aspnet_route_template(class_match.group("attributes") or "")
        class_body_start = class_match.end()
        class_body_end = _next_csharp_class_offset(text, class_body_start)
        class_body = text[class_body_start:class_body_end]
        for method_match in re.finditer(
            r"(?P<attribute>\[Http(?P<verb>Get|Post|Put|Patch|Delete|Head|Options)(?:\s*\(\s*\"(?P<route>[^\"]*)\"\s*\))?\])"
            r"\s*public\s+[\w<>\[\], ?]+\s+(?P<method>[A-Za-z_]\w*)\s*\(",
            class_body,
            re.IGNORECASE,
        ):
            route = method_match.group("route") or ""
            yield (
                _line_for_offset(text, class_body_start + method_match.start()),
                method_match.group("verb").lower(),
                _aspnet_join_route_parts(class_prefix, route),
                f"{class_name}#{method_match.group('method')}",
                _compact_snippet(method_match.group(0)),
            )



def _aspnet_route_template(attributes: str) -> str | None:
    match = re.search(r"\[Route\s*\(\s*\"(?P<route>[^\"]*)\"\s*\)\]", attributes, re.IGNORECASE)
    if match is None:
        return None
    return match.group("route")



def _aspnet_join_route_parts(base: str | None, route: str) -> str:
    if route.startswith("/"):
        return route
    if base is None:
        return f"/{route.strip('/')}"
    if not route:
        return f"/{base.strip('/')}"
    return _join_route_parts(base, route)



def _next_csharp_class_offset(text: str, start: int) -> int:
    match = re.search(r"\n\s*(?:public\s+)?class\s+[A-Za-z_]\w*\b", text[start:])
    return len(text) if match is None else start + match.start()



def _rust_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for index, (line_number, line) in enumerate(lines):
        axum_match = re.search(
            r'\.route\s*\(\s*"(?P<route>/[^"]*)"\s*,\s*'
            r'(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*(?P<handler>[^)]+)\s*\)',
            line,
        )
        if axum_match is not None:
            yield (
                line_number,
                axum_match.group("method"),
                axum_match.group("route"),
                _rust_handler_name(axum_match.group("handler")),
                line,
            )
            continue

        attribute_match = re.search(
            r'#\[(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*"(?P<route>/[^"]*)"\s*\)\]',
            line,
        )
        if attribute_match is not None:
            yield (
                line_number,
                attribute_match.group("method"),
                attribute_match.group("route"),
                _rust_handler_after(lines, index),
                line,
            )



def _rust_handler_name(value: str) -> str | None:
    handler = value.strip()
    match = re.fullmatch(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", handler)
    if match is None:
        return None
    return handler



def _rust_handler_after(lines: list[tuple[int, str]], index: int) -> str | None:
    for _, candidate in lines[index + 1 : index + 5]:
        match = re.search(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_]\w*)\s*\(", candidate)
        if match is not None:
            return match.group("name")
        if candidate.strip() and not candidate.strip().startswith("#"):
            continue
    return None



def _kotlin_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for index, (line_number, line) in enumerate(lines):
        ktor_match = re.search(
            r'\b(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*"(?P<route>/[^"]*)"'
            r'\s*(?:,\s*::(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*))?',
            line,
        )
        if ktor_match is not None:
            yield (
                line_number,
                ktor_match.group("method"),
                ktor_match.group("route"),
                ktor_match.group("handler"),
                line,
            )
            continue

        spring_mapping = _spring_mapping_from_line(line)
        if spring_mapping is not None:
            method, route = spring_mapping
            yield line_number, method, route, _kotlin_handler_after(lines, index), line



def _kotlin_handler_after(lines: list[tuple[int, str]], index: int) -> str | None:
    for _, candidate in lines[index + 1 : index + 5]:
        match = re.search(
            r"^\s*(?:(?:public|private|protected|internal)\s+)?(?:suspend\s+)?fun\s+(?P<name>[A-Za-z_]\w*)\s*\(",
            candidate,
        )
        if match is not None:
            return match.group("name")
        stripped = candidate.strip()
        if stripped and not stripped.startswith("@"):
            continue
    return None



def _play_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        route_match = re.search(
            r"^\s*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"
            r"(?P<route>/\S*)\s+"
            r"(?P<handler>controllers\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
            line,
        )
        if route_match is None:
            continue
        yield (
            line_number,
            route_match.group("method").lower(),
            route_match.group("route"),
            route_match.group("handler"),
            line,
        )



def _phoenix_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    scope_prefixes: list[tuple[str | None, str | None]] = []
    for line_number, line in lines:
        stripped = line.strip()
        scope_match = re.search(
            r'^scope\s+"(?P<scope>/[^"]*)"(?:\s*,\s*(?P<alias>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*))?\s+do\s*$',
            stripped,
        )
        if scope_match is not None:
            scope_prefixes.append((scope_match.group("scope"), scope_match.group("alias")))
            continue

        if stripped == "end" and scope_prefixes:
            scope_prefixes.pop()
            continue

        route_match = re.search(
            r'^\s*(?P<method>get|post|put|patch|delete|head|options)\s+"(?P<route>/[^"]*)"\s*,\s*'
            r'(?P<controller>[A-Z_]\w*(?:\.[A-Z_]\w*)*)\s*,\s*:(?P<action>[A-Za-z_]\w*)\b',
            line,
        )
        if route_match is None:
            continue

        scope_prefix, scope_alias = scope_prefixes[-1] if scope_prefixes else (None, None)
        route_path = _join_route_parts(scope_prefix, route_match.group("route")) if scope_prefix else route_match.group("route")
        controller = route_match.group("controller")
        handler = f"{scope_alias}.{controller}#{route_match.group('action')}" if scope_alias else f"{controller}#{route_match.group('action')}"
        yield (
            line_number,
            route_match.group("method").lower(),
            route_path,
            handler,
            line,
        )



def _clojure_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        route_match = re.search(
            r'^\s*\((?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"(?P<route>/[^"]*)"'
            r'(?:\s+(?:\[\s*\]|[A-Za-z_][\w-]*))?\s+'
            r'(?P<handler>[A-Za-z_][\w-]*(?:[./][A-Za-z_][\w-]*)*)\)?',
            line,
        )
        if route_match is None:
            continue
        yield (
            line_number,
            route_match.group("method").lower(),
            route_match.group("route"),
            route_match.group("handler"),
            line,
        )



def _servant_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        if ":>" not in line:
            continue
        method_match = re.search(r"\b(?P<method>Get|Post|Put|Patch|Delete|Head|Options)\b", line)
        route_tokens = list(re.finditer(r'(?:(?P<capture>Capture)\s+)?"(?P<segment>[^"]+)"', line))
        if method_match is None or not route_tokens:
            continue

        segments: list[str] = []
        for token in route_tokens:
            segment = token.group("segment")
            if token.group("capture") is not None:
                segments.append(f"{{{segment}}}")
            else:
                segments.append(segment)
        route_path = "/" + "/".join(segment.strip("/") for segment in segments if segment)
        yield (
            line_number,
            method_match.group("method").lower(),
            route_path,
            None,
            line,
        )



def _sinatra_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        route_match = re.search(
            r"^\s*(?P<method>get|post|put|patch|delete|head|options)\s+['\"](?P<route>/[^'\"]*)['\"](?P<rest>.*)$",
            line,
        )
        if route_match is None:
            continue
        yield (
            line_number,
            route_match.group("method"),
            route_match.group("route"),
            _sinatra_handler_from_rest(route_match.group("rest")),
            line,
        )



def _sinatra_handler_from_rest(rest: str) -> str | None:
    handler_match = re.search(r"&method\s*\(\s*:(?P<handler>[A-Za-z_]\w*)\s*\)", rest)
    if handler_match is None:
        return None
    return handler_match.group("handler")



def _rails_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        route_match = re.search(
            r"^\s*(?P<method>get|post|put|patch|delete|match)\s+['\"](?P<route>/[^'\"]*)['\"](?P<rest>.*)$",
            line,
        )
        if route_match is None:
            continue

        handler = _rails_handler_from_rest(route_match.group("rest"))
        if handler is None:
            continue
        method = route_match.group("method")
        yield line_number, _rails_route_method(method, route_match.group("rest")), route_match.group("route"), handler, line



def _rails_handler_from_rest(rest: str) -> str | None:
    match = re.search(r"(?:\bto:\s*|=>\s*)['\"](?P<handler>[A-Za-z_]\w*#[A-Za-z_]\w*)['\"]", rest)
    if match is None:
        return None
    return match.group("handler")



def _rails_route_method(method: str, rest: str) -> str | None:
    if method != "match":
        return method
    match = re.search(r"\bvia:\s*:(?P<method>get|post|put|patch|delete)\b", rest)
    if match is None:
        return None
    return match.group("method")



def _laravel_route_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str | None, str, str | None, str]]:
    for line_number, line in lines:
        route_match = re.search(
            r"\bRoute::(?P<method>get|post|put|patch|delete|match)\s*\(\s*(?P<args>.*)\s*\)\s*;?\s*$",
            line,
            re.IGNORECASE,
        )
        if route_match is None:
            continue

        method = route_match.group("method").lower()
        parsed = _laravel_route_args(method, route_match.group("args"))
        if parsed is None:
            continue
        route_path, handler = parsed
        yield line_number, None if method == "match" else method, route_path, handler, line



def _laravel_route_args(method: str, args: str) -> tuple[str, str] | None:
    if method == "match":
        route_match = re.search(r"\]\s*,\s*['\"](?P<route>/[^'\"]*)['\"]\s*,\s*(?P<handler>.*)$", args)
    else:
        route_match = re.search(r"^\s*['\"](?P<route>/[^'\"]*)['\"]\s*,\s*(?P<handler>.*)$", args)
    if route_match is None:
        return None
    handler = _laravel_handler_name(route_match.group("handler"))
    if handler is None:
        return None
    return route_match.group("route"), handler



def _laravel_handler_name(value: str) -> str | None:
    string_handler = re.search(r"['\"](?P<controller>[A-Za-z_]\w*)@(?P<action>[A-Za-z_]\w*)['\"]", value)
    if string_handler is not None:
        return f"{string_handler.group('controller')}@{string_handler.group('action')}"

    array_handler = re.search(
        r"\[\s*(?P<controller>[A-Za-z_]\w*)::class\s*,\s*['\"](?P<action>[A-Za-z_]\w*)['\"]\s*\]",
        value,
    )
    if array_handler is None:
        return None
    return f"{array_handler.group('controller')}@{array_handler.group('action')}"



def _javascript_url_config_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str]]:
    for line_number, line in lines:
        match = re.search(
            r"\b(?:url|endpoint|apiUrl|action|mapping|methodToCall)\b\s*[:=]\s*['\"](?P<route>/[^'\"]+)['\"]",
            line,
            re.IGNORECASE,
        )
        if match is not None:
            yield line_number, match.group("route"), line


def _django_urlpatterns_matches(lines: list[tuple[int, str]]) -> Iterable[tuple[int, str, str | None, str]]:
    for index, (line_number, line) in enumerate(lines):
        if re.search(r"\b(?:path|re_path)\s*\(", line) is None:
            continue

        call_text = _python_call_text(lines, index)
        handler = _django_handler_from_call(call_text)
        same_line_route = re.search(r"\b(?:path|re_path)\s*\(\s*(?:r)?['\"](?P<route>[^'\"]+)", line)
        if same_line_route is not None:
            yield line_number, same_line_route.group("route"), handler, line
            continue

        for route_line_number, route_line in lines[index + 1 : index + 5]:
            route_match = re.search(r"(?:r)?['\"](?P<route>[^'\"]+)['\"]", route_line)
            if route_match is not None:
                yield route_line_number, route_match.group("route"), handler, route_line
                break



def _python_call_text(lines: list[tuple[int, str]], index: int, max_lines: int = 8) -> str:
    return "\n".join(line for _, line in lines[index : index + max_lines])



def _django_handler_from_call(call_text: str) -> str | None:
    match = re.search(
        r"\b(?:path|re_path)\s*\(\s*"
        r"(?:r)?['\"][^'\"]+['\"]\s*,\s*"
        r"(?P<handler>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.as_view\s*\(\s*\)|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
        call_text,
        re.DOTALL,
    )
    if match is None:
        return None
    return re.sub(r"\s+", "", match.group("handler"))


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
    return relative_path.startswith("pages/api/") or _is_next_app_route_file(relative_path)


def _is_next_app_route_file(relative_path: str) -> bool:
    return relative_path.startswith("app/api/") and Path(relative_path).name in NEXT_ROUTE_FILENAMES


def _is_javascript_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}


def _is_nestjs_source(lines: list[tuple[int, str]]) -> bool:
    return any("@nestjs/common" in line for _, line in lines)


def _is_hapi_source(lines: list[tuple[int, str]]) -> bool:
    return any("@hapi/hapi" in line or "require(\"hapi\")" in line or "require('hapi')" in line for _, line in lines)


def _next_api_route_path(relative_path: str) -> str | None:
    parts = list(Path(relative_path).parts)
    if relative_path.startswith("pages/api/"):
        route_parts = parts[1:]
        route_parts[-1] = Path(route_parts[-1]).stem
    elif _is_next_app_route_file(relative_path):
        route_parts = parts[1:-1]
    else:
        return None

    if len(route_parts) > 1 and route_parts[-1] == "index":
        route_parts = route_parts[:-1]
    return "/" + "/".join(_next_route_segment(part) for part in route_parts)


def _next_route_segment(segment: str) -> str:
    if segment.startswith("[[...") and segment.endswith("]]"):
        return f"{{{segment[5:-2]}}}"
    if segment.startswith("[...") and segment.endswith("]"):
        return f"{{{segment[4:-1]}}}"
    if segment.startswith("[") and segment.endswith("]"):
        return f"{{{segment[1:-1]}}}"
    return segment


def _next_app_route_method(lines: list[tuple[int, str]]) -> str | None:
    for _, line in lines:
        match = NEXT_APP_ROUTE_METHOD.search(line)
        if match is not None:
            return match.group("method").lower()
    return None


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



def _is_python_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".py"



def _is_pyramid_source(lines: list[tuple[int, str]]) -> bool:
    return any("pyramid" in line or "Configurator(" in line for _, line in lines)



def _is_starlette_source(lines: list[tuple[int, str]]) -> bool:
    return any("starlette" in line or "Starlette(" in line for _, line in lines)



def _is_sanic_source(lines: list[tuple[int, str]]) -> bool:
    return any("from sanic import" in line or "import sanic" in line or "Sanic(" in line for _, line in lines)



def _is_tornado_source(lines: list[tuple[int, str]]) -> bool:
    return any("tornado.web" in line for _, line in lines)



def _is_aiohttp_source(lines: list[tuple[int, str]]) -> bool:
    return any("aiohttp" in line or "RouteTableDef" in line for _, line in lines)



def _is_bottle_file(relative_path: str) -> bool:
    return _is_python_file(relative_path)



def _is_bottle_source(lines: list[tuple[int, str]]) -> bool:
    return any("from bottle import" in line or "import bottle" in line or "Bottle(" in line for _, line in lines)



def _is_go_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".go"



def _is_csharp_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".cs"



def _is_rust_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".rs"



def _is_kotlin_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".kt"



def _is_play_routes_file(relative_path: str) -> bool:
    return Path(relative_path).parts[-2:] == ("conf", "routes")



def _is_elixir_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() in {".ex", ".exs"}



def _is_clojure_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() in {".clj", ".cljs", ".cljc"}



def _is_haskell_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".hs"



def _is_ruby_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".rb"



def _is_sinatra_source(lines: list[tuple[int, str]]) -> bool:
    return any(re.search(r"\brequire\s+['\"]sinatra", line) or "Sinatra::Base" in line for _, line in lines)



def _is_php_file(relative_path: str) -> bool:
    return Path(relative_path).suffix.lower() == ".php"


def _is_javascript_url_config_file(relative_path: str) -> bool:
    return _is_javascript_file(relative_path) or Path(relative_path).suffix.lower() == ".cc"


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
