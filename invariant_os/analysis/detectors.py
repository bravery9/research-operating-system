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
        re.compile(r"\bfetch\s*\(|\baxios\.|\brequests\.|\burllib\b|\bhttpx\.|\bnet/http\b|\bhttp\.Client\b"),
        "network_operation",
        ConsumerType.NETWORK_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bexec\s*\(|\bspawn\s*\(|\bsubprocess\.|\bProcessBuilder\b"),
        "process_operation",
        ConsumerType.PROCESS_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\brender_template\s*\(|\brender\s*\(|\brenderTemplate\s*\(|\bcompileTemplate\s*\(|\bjinja\b|\bhandlebars\b|\bejs\b", re.IGNORECASE),
        "template_operation",
        ConsumerType.TEMPLATE_OPERATION,
    ),
    ConsumerPattern(
        re.compile(r"\bpickle\.loads\s*\(|\byaml\.load\s*\(|\bdeserialize\b|\bObjectInputStream\b|\bunserialize\b|\bjson\.loads\s*\("),
        "deserialization",
        ConsumerType.DESERIALIZATION,
    ),
    ConsumerPattern(
        re.compile(r"\bconfig\b|\bsettings\b|\byaml\.safe_load\s*\(|\btoml\b", re.IGNORECASE),
        "config_operation",
        ConsumerType.CONFIG_OPERATION,
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
        re.compile(r"\bparser\b|\bparse\s*\(", re.IGNORECASE),
        "parser_operation",
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


def detect_entrypoints(repo_root: Path, files: list[FileRecord]) -> list[Entrypoint]:
    entrypoints: list[Entrypoint] = []
    evidence_counter = 1

    for record, lines in _iter_indexed_lines(repo_root, files):
        if _is_next_api_file(record.path):
            first_line = lines[0][1] if lines else ""
            evidence = _evidence("ev_ep", evidence_counter, record.path, 1, "next_api_route", first_line)
            evidence_counter += 1
            entrypoints.append(
                Entrypoint(
                    id=_detector_id("ep", len(entrypoints) + 1),
                    type=EntrypointType.HTTP_ROUTE,
                    file=record.path,
                    line=1,
                    framework_hint="nextjs",
                    evidence=[evidence],
                )
            )

        has_urlpatterns = any("urlpatterns" in candidate_line for _, candidate_line in lines)
        if has_urlpatterns:
            for line_number, route, snippet in _django_urlpatterns_matches(lines):
                evidence = _evidence("ev_ep", evidence_counter, record.path, line_number, "django_urlpatterns", snippet)
                evidence_counter += 1
                entrypoints.append(
                    Entrypoint(
                        id=_detector_id("ep", len(entrypoints) + 1),
                        type=EntrypointType.HTTP_ROUTE,
                        file=record.path,
                        line=line_number,
                        framework_hint="django",
                        route_path=route,
                        evidence=[evidence],
                    )
                )

        for line_number, line in lines:
            spring_mapping = _spring_mapping_from_line(line)
            if spring_mapping is not None:
                method, route = spring_mapping
                evidence = _evidence("ev_ep", evidence_counter, record.path, line_number, "spring_mapping", line)
                evidence_counter += 1
                entrypoints.append(
                    Entrypoint(
                        id=_detector_id("ep", len(entrypoints) + 1),
                        type=EntrypointType.HTTP_ROUTE,
                        file=record.path,
                        line=line_number,
                        framework_hint="spring",
                        method=method,
                        route_path=route,
                        evidence=[evidence],
                    )
                )

            for pattern in ENTRYPOINT_PATTERNS:
                if pattern.pattern in {"django_urlpatterns", "spring_mapping"}:
                    continue
                for match in pattern.regex.finditer(line):
                    evidence = _evidence("ev_ep", evidence_counter, record.path, line_number, pattern.pattern, line)
                    evidence_counter += 1
                    entrypoints.append(
                        Entrypoint(
                            id=_detector_id("ep", len(entrypoints) + 1),
                            type=pattern.type,
                            file=record.path,
                            line=line_number,
                            framework_hint=pattern.framework_hint,
                            method=_normalized_method(_optional_group(match, "method")),
                            route_path=_optional_group(match, "route"),
                            evidence=[evidence],
                        )
                    )

    return entrypoints


def detect_consumers(repo_root: Path, files: list[FileRecord]) -> list[Consumer]:
    consumers: list[Consumer] = []
    evidence_counter = 1

    for record, lines in _iter_indexed_lines(repo_root, files):
        has_queue_context = _has_queue_worker_context(record.path, lines)
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


def _evidence(prefix: str, counter: int, file: str, line: int, pattern: str, snippet: str) -> Evidence:
    return Evidence(
        id=_detector_id(prefix, counter),
        type=EvidenceType.PATTERN_MATCH,
        file=file,
        line=line,
        pattern=pattern,
        snippet=snippet.strip(),
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
