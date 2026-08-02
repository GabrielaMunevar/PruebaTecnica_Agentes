from enum import Enum, IntEnum


class WorkflowStatus(str, Enum):
    """Estados posibles de un caso dentro del flujo."""

    RECEIVED = "RECEIVED"
    READY_FOR_AI = "READY_FOR_AI"
    DATA_QUALITY_REVIEW = "DATA_QUALITY_REVIEW"
    PROCESSING = "PROCESSING"
    APPROVED_DRAFT = "APPROVED_DRAFT"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    PROCESSING_ERROR = "PROCESSING_ERROR"


class AuditVerdict(str, Enum):
    """Decisiones que puede emitir el agente auditor."""

    APPROVED = "APPROVED"
    REVISE = "REVISE"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class ReportClassification(str, Enum):
    """Clasificaciones utilizadas en el informe de análisis."""

    FALSE_POSITIVE = "Falso positivo"
    PENDING_MANAGEMENT = "Pendiente por gestionar"
    POSITIVE = "Positivo"


class ManagementCode(IntEnum):
    """Códigos oficiales de las respuestas tipificadas."""

    FALSE_POSITIVE = 1
    MANAGEMENT_NOT_APPLICABLE = 2
    SOFTWARE_NOT_INSTALLED = 3
    PLATFORM_OR_VERSION_NOT_AFFECTED = 4
    MANAGEMENT_BELONGS_TO_ANOTHER_AREA = 5
    NOT_MANAGED = 6
    NO_SOLUTION_FOR_PLATFORM = 7
    RESOURCE_DECOMMISSIONING = 8
    RISK_ACCEPTANCE_REQUIRED = 9
    SOLUTION_REQUIRES_EVALUATION = 10
    REMEDIATED = 11