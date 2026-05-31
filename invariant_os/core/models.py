from enum import Enum

from pydantic import BaseModel, Field


AUDIT_SCHEMA_VERSION = "0.10"
REVIEW_QUEUE_SCHEMA_VERSION = "0.10"


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


class StaticFlowTargetType(str, Enum):
    CONSUMER = "consumer"
    WORKER = "worker"


class StaticFlowSignalType(str, Enum):
    HANDLER_EXACT = "handler_exact"
    HANDLER_CLASS = "handler_class"
    HANDLER_METHOD = "handler_method"
    DECLARED_PARAMETER = "declared_parameter"
    REQUEST_PARAMETER = "request_parameter"
    ROUTE_TOKEN = "route_token"
    SAME_FILE_PROXIMITY = "same_file_proximity"


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


class EvidenceGraphNodeType(str, Enum):
    FILE = "file"
    ENTRYPOINT = "entrypoint"
    CONSUMER = "consumer"
    WORKER = "worker"
    BOUNDARY = "boundary"
    PRIMITIVE = "primitive"
    STATIC_FLOW = "static_flow"


class EvidenceGraphEdgeType(str, Enum):
    DEFINED_IN = "defined_in"
    SAME_FILE_CORRELATION = "same_file_correlation"
    HANDLER_NAME_CORRELATION = "handler_name_correlation"
    ROUTE_TO_WORKER_CANDIDATE = "route_to_worker_candidate"
    ROUTE_TO_CONSUMER_CANDIDATE = "route_to_consumer_candidate"
    BOUNDARY_EVIDENCE = "boundary_evidence"
    PRIMITIVE_EVIDENCE = "primitive_evidence"
    STATIC_FLOW_SOURCE = "static_flow_source"
    STATIC_FLOW_TARGET = "static_flow_target"


class ReasoningCategory(str, Enum):
    HIGH_VALUE_SURFACE = "high_value_surface"
    SECURITY_INVARIANT_HYPOTHESIS = "security_invariant_hypothesis"
    PRIMITIVE_TRIAGE = "primitive_triage"
    MISSING_EVIDENCE = "missing_evidence"
    SAFE_NEXT_STEP = "safe_next_step"


class PatchDiffInputType(str, Enum):
    PATCH_FILE = "patch_file"
    GIT_DIFF = "git_diff"


class PatchChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class PatchCorrelationType(str, Enum):
    LINE_OVERLAP = "line_overlap"
    LINE_PROXIMITY = "line_proximity"
    SAME_FILE = "same_file"


class PatchVariantSourceType(str, Enum):
    EVIDENCE = "evidence"
    BOUNDARY = "boundary"
    PRIMITIVE = "primitive"
    STATIC_FLOW = "static_flow"


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


class StaticFlowSignal(BaseModel):
    type: StaticFlowSignalType
    term: str
    score: int
    evidence_ids: list[str] = Field(default_factory=list)


class StaticFlowCandidate(BaseModel):
    id: str
    source_entrypoint_id: str
    target_ref_id: str
    target_type: StaticFlowTargetType
    confidence: Confidence
    score: int
    summary: str
    signals: list[StaticFlowSignal] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class EvidenceGraphNode(BaseModel):
    id: str
    type: EvidenceGraphNodeType
    label: str
    ref_id: str | None = None
    file: str | None = None
    line: int | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    id: str
    type: EvidenceGraphEdgeType
    source: str
    target: str
    confidence: Confidence
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class EvidenceGraph(BaseModel):
    nodes: list[EvidenceGraphNode] = Field(default_factory=list)
    edges: list[EvidenceGraphEdge] = Field(default_factory=list)


class AuditSummary(BaseModel):
    files: int
    entrypoints: int
    consumers: int
    workers: int
    boundaries: int
    primitive_candidates: int
    static_flow_candidates: int


class FocusMetadata(BaseModel):
    mode: str = "all"
    label: str = "All Evidence"
    description: str = "Default lens over all deterministic audit evidence."
    boundary_matches: int = 0
    primitive_matches: int = 0
    static_flow_matches: int = 0
    total_matches: int = 0


class SafetyMetadata(BaseModel):
    scope: str = "authorized_local_repo_analysis_only"
    principle: str = "LLM proposes. Tools prove. Human approves."
    limitations: list[str] = Field(
        default_factory=lambda: [
            "No exploitability claims",
            "No public target scanning",
            "No exploit payload generation",
            "No target code execution",
            "No network or public target scanning",
            "Static candidates and hypotheses require human review",
        ]
    )


class ReasoningItem(BaseModel):
    id: str
    category: ReasoningCategory
    title: str
    summary: str
    confidence: Confidence
    related_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    safe_next_steps: list[str] = Field(default_factory=list)


class ReasoningSummary(BaseModel):
    high_value_surfaces: int
    invariant_hypotheses: int
    primitive_triage_items: int
    missing_evidence_items: int
    safe_next_steps: int


class ReasoningResult(BaseModel):
    source_schema_version: str
    source_project: Project
    source_audit_file: str
    items: list[ReasoningItem] = Field(default_factory=list)
    summary: ReasoningSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = "0.6"
    tool: str = "invariant-os"


class PatchHunk(BaseModel):
    id: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    added_lines: list[int] = Field(default_factory=list)
    removed_lines: list[int] = Field(default_factory=list)
    context: str | None = None


class PatchChangedFile(BaseModel):
    id: str
    old_path: str | None = None
    new_path: str | None = None
    change_type: PatchChangeType
    hunks: list[PatchHunk] = Field(default_factory=list)


class PatchCorrelation(BaseModel):
    id: str
    type: PatchCorrelationType
    changed_file_id: str
    hunk_id: str | None = None
    related_id: str
    related_type: PatchVariantSourceType
    file: str
    line: int | None = None
    confidence: Confidence
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class PatchVariantCandidate(BaseModel):
    id: str
    source_type: PatchVariantSourceType
    source_id: str
    changed_file_id: str
    hunk_id: str | None = None
    confidence: Confidence
    title: str
    summary: str
    related_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    safe_next_steps: list[str] = Field(default_factory=list)


class PatchDiffSummary(BaseModel):
    changed_files: int
    hunks: int
    correlations: int
    variant_candidates: int
    files_with_audit_context: int


class PatchDiffResult(BaseModel):
    source_schema_version: str
    source_project: Project
    source_audit_file: str
    input_type: PatchDiffInputType
    patch_file: str | None = None
    repo_path: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None
    changed_files: list[PatchChangedFile] = Field(default_factory=list)
    correlations: list[PatchCorrelation] = Field(default_factory=list)
    variant_candidates: list[PatchVariantCandidate] = Field(default_factory=list)
    summary: PatchDiffSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = "0.7"
    tool: str = "invariant-os"


class AuditResult(BaseModel):
    project: Project
    files: list[FileRecord] = Field(default_factory=list)
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    consumers: list[Consumer] = Field(default_factory=list)
    workers: list[Worker] = Field(default_factory=list)
    boundaries: list[BoundaryCandidate] = Field(default_factory=list)
    primitive_candidates: list[PrimitiveCandidate] = Field(default_factory=list)
    static_flow_candidates: list[StaticFlowCandidate] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    focus: FocusMetadata = Field(default_factory=FocusMetadata)
    summary: AuditSummary
    safety: SafetyMetadata = Field(default_factory=SafetyMetadata)
    schema_version: str = AUDIT_SCHEMA_VERSION
    tool: str = "invariant-os"
