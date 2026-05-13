from enum import Enum

from pydantic import BaseModel, Field


class EntrypointType(str, Enum):
    HTTP_ROUTE = "http_route"
    CLI_COMMAND = "cli_command"
    WEBHOOK = "webhook"
    GRAPHQL_RESOLVER = "graphql_resolver"
    RPC_HANDLER = "rpc_handler"
    GENERIC = "generic"


class ConsumerType(str, Enum):
    FILE_OPERATION = "file_operation"
    NETWORK_OPERATION = "network_operation"
    PROCESS_OPERATION = "process_operation"
    TEMPLATE_OPERATION = "template_operation"
    DESERIALIZATION = "deserialization"
    CONFIG_OPERATION = "config_operation"
    QUEUE_OPERATION = "queue_operation"
    ARCHIVE_OPERATION = "archive_operation"
    PARSER_OPERATION = "parser_operation"
    DATABASE_OPERATION = "database_operation"
    DIRECTORY_OPERATION = "directory_operation"


class WorkerType(str, Enum):
    QUEUE_WORKER = "queue_worker"
    CRON_JOB = "cron_job"
    BACKGROUND_TASK = "background_task"
    EVENT_CONSUMER = "event_consumer"


class EvidenceType(str, Enum):
    CODE_REFERENCE = "code_reference"
    PATTERN_MATCH = "pattern_match"
    BOUNDARY_RULE = "boundary_rule"
    LLM_HYPOTHESIS = "llm_hypothesis"
    STATIC_ANALYSIS_HIT = "static_analysis_hit"
    MANUAL_NOTE = "manual_note"
    TEST_RESULT = "test_result"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class BoundaryType(str, Enum):
    REQUEST_TO_WORKER = "request_to_worker"
    DATA_TO_FILE = "data_to_file"
    DATA_TO_URL = "data_to_url"
    DATA_TO_TEMPLATE = "data_to_template"
    DATA_TO_CONFIG = "data_to_config"
    DATA_TO_JOB = "data_to_job"
    EXTERNAL_TO_INTERNAL = "external_to_internal"
    LOW_PRIV_TO_PRIVILEGED_CONSUMER = "low_priv_to_privileged_consumer"
    PARSER_TO_CONSUMER = "parser_to_consumer"
    DATA_TO_DATABASE = "data_to_database"
    DATA_TO_DIRECTORY = "data_to_directory"


class PrimitiveType(str, Enum):
    PATH_CONTROL = "path_control"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    URL_CONTROL = "url_control"
    INTERNAL_REQUEST_TRIGGER = "internal_request_trigger"
    TEMPLATE_CONTROL = "template_control"
    TYPE_CONTROL = "type_control"
    JOB_CONTROL = "job_control"
    CONFIG_CONTROL = "config_control"
    CACHE_POISONING = "cache_poisoning"
    AUTH_CONTEXT_CONFUSION = "auth_context_confusion"
    TENANT_CONFUSION = "tenant_confusion"
    PARSER_DIFFERENTIAL = "parser_differential"
    QUERY_CONTROL = "query_control"
    DIRECTORY_QUERY_CONTROL = "directory_query_control"


class Project(BaseModel):
    name: str
    root: str


class FileRecord(BaseModel):
    path: str
    language: str
    size_bytes: int
    sha256: str


class Evidence(BaseModel):
    id: str
    type: EvidenceType
    file: str
    line: int
    pattern: str | None = None
    snippet: str | None = None
    message: str | None = None
    symbol: str | None = None


class Entrypoint(BaseModel):
    id: str
    type: EntrypointType
    file: str
    line: int
    framework_hint: str | None = None
    method: str | None = None
    route_path: str | None = None
    handler: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class Consumer(BaseModel):
    id: str
    type: ConsumerType
    file: str
    line: int
    symbol: str | None = None
    pattern: str
    evidence: list[Evidence] = Field(default_factory=list)


class Worker(BaseModel):
    id: str
    type: WorkerType
    file: str
    line: int
    framework_hint: str | None = None
    pattern: str
    evidence: list[Evidence] = Field(default_factory=list)


class BoundaryCandidate(BaseModel):
    id: str
    type: BoundaryType
    confidence: Confidence
    reason: str
    evidence: list[Evidence] = Field(default_factory=list)


class PrimitiveCandidate(BaseModel):
    id: str
    primitive: PrimitiveType
    confidence: Confidence
    evidence: list[Evidence] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    safe_next_steps: list[str] = Field(default_factory=list)


class AuditSummary(BaseModel):
    files: int
    entrypoints: int
    consumers: int
    workers: int
    boundaries: int
    primitive_candidates: int


class SafetyMetadata(BaseModel):
    scope: str = "authorized_local_repo_analysis_only"
    principle: str = "LLM proposes. Tools prove. Human approves."
    limitations: list[str] = Field(
        default_factory=lambda: [
            "No exploitability claims",
            "No public target scanning",
            "No exploit payload generation",
        ]
    )


class AuditResult(BaseModel):
    project: Project
    files: list[FileRecord] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    consumers: list[Consumer] = Field(default_factory=list)
    workers: list[Worker] = Field(default_factory=list)
    boundaries: list[BoundaryCandidate] = Field(default_factory=list)
    primitive_candidates: list[PrimitiveCandidate] = Field(default_factory=list)
    summary: AuditSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = "0.1"
    tool: str = "invariant-os"
