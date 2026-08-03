from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import (BaseModel,ConfigDict,Field,field_validator,model_validator,)

from src.constants import OBSERVATION_MAX_LENGTH
from src.enums import (AuditVerdict,ManagementCode, PolicyDecision, ReportClassification, WorkflowStatus,)


NULL_LIKE_VALUES = {"","ND","NA","N/A","NULL","NONE",}


def normalize_optional_text(value: Any) -> str | None:
    """
    Convierte los valores equivalentes a ausencia de información en None.

    Ejemplos:
    - "ND" -> None
    - " NA " -> None
    - "" -> None
    - "Producción" -> "Producción"
    """
    if value is None:
        return None

    text = str(value).strip()

    if text.upper() in NULL_LIKE_VALUES:
        return None

    return text

def normalize_text_list(value: Any) -> list[str]:
    """
    Normaliza una colección de textos.

    - Elimina valores vacíos, ND, NA y N/A.
    - Elimina espacios al inicio y al final.
    - Elimina duplicados conservando el orden.
    """
    if value is None:
        return []

    if not isinstance(value, (list, tuple, set)):
        raise TypeError(
            "El valor debe ser una colección de textos."
        )

    normalized_items: list[str] = []
    seen: set[str] = set()

    for item in value:
        normalized_item = normalize_optional_text(item)

        if normalized_item is None:
            continue

        comparison_key = normalized_item.casefold()

        if comparison_key in seen:
            continue

        seen.add(comparison_key)
        normalized_items.append(normalized_item)

    return normalized_items

class StrictModel(BaseModel):
    """
    Configuración común para todos los modelos del proyecto.

    - No permite campos inesperados.
    - Elimina espacios al inicio y al final.
    - Valida también cuando un atributo se modifica.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class AssetContext(StrictModel):
    """Información del host donde fue detectada la vulnerabilidad."""

    host_id: int = Field(gt=0)

    ip: str = Field(
        min_length=1,
        max_length=50,
    )

    dns: str | None = None
    netbios: str | None = None
    product: str | None = None
    environment: str | None = None
    condition: str | None = None

    # Debe provenir exclusivamente de TBL_HOST.GROUP_DS.
    internal_group: str | None = None

    @field_validator(
        "dns",
        "netbios",
        "product",
        "environment",
        "condition",
        "internal_group",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)


class VulnerabilityDetails(StrictModel):
    """Información funcional y técnica asociada al QID y sus CVE."""

    qid_id: int = Field(gt=0)

    qid: str = Field(
        min_length=1,
        max_length=100,
    )

    title: str = Field(min_length=1)

    threat: str | None = None
    impact: str | None = None

    # Corresponde a TBL_QID.SOLUTION_DS.
    # No se considera automáticamente un plan de mitigación.
    vendor_information: str | None = None

    # Puede contener uno, varios o ningún CVE.
    cves: list[str] = Field(default_factory=list)

    vendor_reference: str | None = None
    bugtraq_id: str | None = None
    exploitability: str | None = None
    associated_malware: str | None = None
    pci_vulnerability: str | None = None

    @field_validator(
        "threat",
        "impact",
        "vendor_information",
        "vendor_reference",
        "bugtraq_id",
        "exploitability",
        "associated_malware",
        "pci_vulnerability",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @field_validator("cves", mode="before")
    @classmethod
    def parse_cves(
        cls,
        value: Any,
    ) -> list[str]:
        """
        Convierte el campo CVE_CD de la vista en una lista.

        Ejemplo:
        "CVE-2023-36728,CVE-2023-36730"

        Resultado:
        [
            "CVE-2023-36728",
            "CVE-2023-36730"
        ]
        """
        if value is None:
            return []

        if isinstance(value, str):
            raw_items = value.split(",")

        elif isinstance(value, (list, tuple, set)):
            raw_items = list(value)

        else:
            raise TypeError(
                "cves debe ser un texto separado por comas "
                "o una colección de textos."
            )

        normalized: list[str] = []
        seen: set[str] = set()

        for item in raw_items:
            cve = normalize_optional_text(item)

            if cve is None:
                continue

            cve = cve.upper()

            if cve not in seen:
                seen.add(cve)
                normalized.append(cve)

        return normalized


class TechnicalContext(StrictModel):
    """Contexto técnico de la detección."""

    os_id: int = Field(gt=0)
    operating_system: str = Field(min_length=1)

    port_id: int = Field(gt=0)
    port: str | None = None
    protocol: str | None = None

    detection_type: str | None = None

    risk_id: int = Field(gt=0)

    risk_code: str = Field(
        min_length=1,
        max_length=2,
    )

    # En los datos actuales CVSS_DS contiene valores
    # como Crítico, Alto, Medio o Bajo.
    risk_description: str | None = None

    scan_result: str | None = None

    @field_validator(
        "port",
        "protocol",
        "detection_type",
        "risk_description",
        "scan_result",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)


class DetectionHistory(StrictModel):
    """Información histórica de aparición de la vulnerabilidad."""

    first_detected_at: datetime | None = None
    last_detected_at: datetime | None = None

    reoffending: bool

    times_detected: int | None = Field(
        default=None,
        ge=0,
    )


class DataQuality(StrictModel):
    """Indicadores calculados en la vista enriquecida."""

    required_references_ok: bool
    has_internal_group: bool
    has_qid_detail: bool
    has_vendor_information: bool
    has_cve_detail: bool


class VulnerabilityCase(StrictModel):
    """
    Caso completo que será enviado al flujo de LangGraph.

    Representa una fila enriquecida de
    VW_AI_INTERNAL_VULNERABILITIES_ENRICHED.
    """

    vulnerability_id: str = Field(
        min_length=1,
        max_length=100,
    )

    asset: AssetContext
    vulnerability: VulnerabilityDetails
    technical: TechnicalContext
    detection: DetectionHistory
    quality: DataQuality

    # Valores actuales en STG_INTERNAL_VULNERABILITIES.
    # Normalmente llegan como ND y serán convertidos en None.
    current_management_ds: str | None = None
    current_group_ds: str | None = None
    current_observation_ds: str | None = None

    inserted_at: datetime | None = None
    inserted_user: str | None = None

    @field_validator(
        "current_management_ds",
        "current_group_ds",
        "current_observation_ds",
        "inserted_user",
        mode="before",
    )
    @classmethod
    def normalize_current_values(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @property
    def initial_status(self) -> WorkflowStatus:
        """
        Define si el caso puede entrar al sistema multiagente.

        Los problemas estructurados de datos se separan del análisis
        técnico realizado por los agentes.
        """
        if not self.quality.required_references_ok:
            return WorkflowStatus.DATA_QUALITY_REVIEW

        if not self.quality.has_internal_group:
            return WorkflowStatus.DATA_QUALITY_REVIEW

        if not self.quality.has_qid_detail:
            return WorkflowStatus.DATA_QUALITY_REVIEW

        return WorkflowStatus.READY_FOR_AI

class ManagementCatalogEntry(StrictModel):
    """
    Representa una respuesta tipificada del catálogo corporativo.

    El catálogo determina los textos oficiales, la clasificación
    del informe y las reglas de revisión humana. Estos valores
    no quedan bajo el control del agente.
    """

    code: ManagementCode

    management_ds: str = Field(
        min_length=1,
        max_length=100,
        description=(
            "Texto normalizado que puede almacenarse "
            "en MANAGEMENT_DS."
        ),
    )

    report_classification: ReportClassification

    allowed_as_initial_proposal: bool = Field(
        description=(
            "Indica si el agente puede proponer esta respuesta "
            "durante el análisis inicial."
        ),
    )

    human_review_required: bool = Field(
        description=(
            "Indica si la propuesta requiere validación humana."
        ),
    )

    required_evidence: list[str] = Field(
        min_length=1,
        description=(
            "Evidencia mínima necesaria para respaldar "
            "esta respuesta tipificada."
        ),
    )

    system_status: WorkflowStatus | None = Field(
        default=None,
        description=(
            "Estado especial del flujo cuando la respuesta "
            "representa una inconsistencia o bloqueo."
        ),
    )

    @field_validator(
        "management_ds",
        mode="before",
    )
    @classmethod
    def normalize_management_description(
        cls,
        value: Any,
    ) -> str:
        normalized_value = normalize_optional_text(value)

        if normalized_value is None:
            raise ValueError(
                "management_ds debe contener un texto válido."
            )

        return normalized_value

    @field_validator(
        "required_evidence",
        mode="before",
    )
    @classmethod
    def normalize_required_evidence(
        cls,
        value: Any,
    ) -> list[str]:
        return normalize_text_list(value)

    @model_validator(mode="after")
    def validate_catalog_consistency(
        self,
    ) -> "ManagementCatalogEntry":
        """
        Valida relaciones generales entre los campos del catálogo.
        """

        if (
            not self.allowed_as_initial_proposal
            and not self.human_review_required
        ):
            raise ValueError(
                "Una respuesta no permitida como propuesta inicial "
                "debe requerir revisión humana."
            )

        allowed_special_statuses = {
            WorkflowStatus.DATA_QUALITY_REVIEW,
            WorkflowStatus.HUMAN_REVIEW,
        }

        if (
            self.system_status is not None
            and self.system_status not in allowed_special_statuses
        ):
            raise ValueError(
                "system_status solo puede ser "
                "DATA_QUALITY_REVIEW o HUMAN_REVIEW."
            )

        return self


class FullMitigationPlan(StrictModel):

    """
    Plan técnico completo generado por el agente planificador.

    Este contenido se utiliza durante la demo y la auditoría,
    pero no se almacena en OBSERVATION_DS porque ese campo
    admite únicamente 500 caracteres.
    """

    summary: str = Field(
        min_length=1,
        description="Resumen técnico de la estrategia propuesta.",
    )

    recommended_actions: list[str] = Field(
        min_length=1,
        description="Acciones técnicas recomendadas.",
    )

    prerequisites: list[str] = Field(
        default_factory=list,
        description="Condiciones requeridas antes de aplicar el plan.",
    )

    operational_impact: str = Field(
        min_length=1,
        description=(
            "Impacto esperado sobre el servicio, activo "
            "o aplicaciones relacionadas."
        ),
    )

    maintenance_window_required: bool = Field(
        description=(
            "Indica si la implementación requiere "
            "ventana de mantenimiento."
        ),
    )

    validation_steps: list[str] = Field(
        min_length=1,
        description=(
            "Pasos para comprobar que la remediación fue exitosa."
        ),
    )

    rollback_steps: list[str] = Field(
        default_factory=list,
        description=(
            "Pasos para revertir la implementación si se presentan fallos."
        ),
    )

    rollback_not_applicable_reason: str | None = Field(
        default=None,
        description=(
            "Explicación obligatoria cuando no se requiere rollback."
        ),
    )

    assumptions: list[str] = Field(
        default_factory=list,
        description="Supuestos utilizados para elaborar el plan.",
    )

    missing_information: list[str] = Field(
        default_factory=list,
        description=(
            "Información que todavía debe confirmar el especialista."
        ),
    )

    evidence_used: list[str] = Field(
        min_length=1,
        description=(
            "Evidencias del caso utilizadas para generar el plan."
        ),
    )

    @field_validator(
        "recommended_actions",
        "prerequisites",
        "validation_steps",
        "rollback_steps",
        "assumptions",
        "missing_information",
        "evidence_used",
        mode="before",
    )
    @classmethod
    def normalize_list_fields(
        cls,
        value: Any,
    ) -> list[str]:
        return normalize_text_list(value)

    @field_validator(
        "rollback_not_applicable_reason",
        mode="before",
    )
    @classmethod
    def normalize_optional_rollback_reason(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def validate_rollback_definition(
        self,
    ) -> "FullMitigationPlan":
        """
        Todo plan debe incluir rollback o explicar por qué no aplica.

        Esta regla se valida en código y no depende únicamente
        de que el prompt se lo solicite al modelo.
        """
        if (
            not self.rollback_steps
            and self.rollback_not_applicable_reason is None
        ):
            raise ValueError(
                "El plan debe incluir pasos de rollback "
                "o justificar por qué el rollback no aplica."
            )

        return self

class MitigationProposal(StrictModel):
    """
    Propuesta estructurada producida por el agente planificador.

    El agente selecciona el código de gestión, pero no genera
    el texto oficial de MANAGEMENT_DS ni la clasificación
    del informe. Esos valores se recuperan posteriormente
    desde management_catalog.json.
    """

    vulnerability_id: str = Field(
        min_length=1,
        max_length=100,
    )

    management_code: ManagementCode = Field(
        description=(
            "Código de la respuesta tipificada propuesta."
        ),
    )

    classification_reason: str = Field(
        min_length=1,
        description=(
            "Justificación técnica de la respuesta tipificada."
        ),
    )

    observation_ds: str = Field(
        min_length=1,
        max_length=OBSERVATION_MAX_LENGTH,
        description=(
            "Resumen de máximo 500 caracteres que podría "
            "almacenarse en STG_INTERNAL_VULNERABILITIES."
        ),
    )

    full_plan: FullMitigationPlan

    confidence: float = Field(
        ge=0,
        le=1,
        description=(
            "Confianza declarada por el agente entre 0 y 1. "
            "No reemplaza las validaciones del auditor."
        ),
    )

    @field_validator(
        "classification_reason",
        "observation_ds",
        mode="before",
    )
    @classmethod
    def normalize_required_text(
        cls,
        value: Any,
    ) -> str:
        normalized_value = normalize_optional_text(value)

        if normalized_value is None:
            raise ValueError(
                "El campo debe contener información útil."
            )

        return normalized_value

class PolicyFinding(StrictModel):
    """Incumplimiento o condición encontrada por el Policy Gate."""

    code: str = Field(
        min_length=1,
        max_length=100,
    )

    message: str = Field(
        min_length=1,
    )

    field: str | None = None

    @field_validator(
        "code",
        "message",
        "field",
        mode="before",
    )
    @classmethod
    def normalize_finding_text(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)


class PolicyEvaluation(StrictModel):
    """Resultado estructurado de las políticas deterministas."""

    decision: PolicyDecision

    findings: list[PolicyFinding] = Field(
        default_factory=list,
    )

    requires_human_review: bool = False

    @property
    def passed(self) -> bool:
        return self.decision is PolicyDecision.PASS

class AuditFinding(StrictModel):
    """
    Hallazgo semántico o técnico identificado por el auditor.
    """

    code: str = Field(
        min_length=1,
        max_length=100,
    )

    message: str = Field(
        min_length=1,
    )

    field: str | None = None

    blocking: bool = Field(
        default=True,
        description=(
            "Indica si el hallazgo impide aprobar el plan."
        ),
    )

    @field_validator(
        "code",
        "message",
        "field",
        mode="before",
    )
    @classmethod
    def normalize_audit_finding(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)


class AuditResult(StrictModel):
    """
    Resultado estructurado del agente auditor.

    No determina por sí solo el estado final del workflow.
    LangGraph combinará este resultado con las políticas,
    el catálogo y el número de intentos.
    """

    vulnerability_id: str = Field(
        min_length=1,
        max_length=100,
    )

    verdict: AuditVerdict

    summary: str = Field(
        min_length=1,
        description="Conclusión general de la auditoría.",
    )

    findings: list[AuditFinding] = Field(
        default_factory=list,
    )

    evidence_sufficient: bool

    missing_information: list[str] = Field(
        default_factory=list,
    )

    feedback_for_planner: str | None = Field(
        default=None,
        description=(
            "Instrucción concreta para corregir la propuesta."
        ),
    )

    confidence: float = Field(
        ge=0,
        le=1,
    )

    @field_validator(
        "missing_information",
        mode="before",
    )
    @classmethod
    def normalize_missing_information(
        cls,
        value: Any,
    ) -> list[str]:
        return normalize_text_list(value)

    @field_validator(
        "feedback_for_planner",
        mode="before",
    )
    @classmethod
    def normalize_feedback(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def validate_verdict_consistency(
        self,
    ) -> "AuditResult":
        blocking_findings = any(
            finding.blocking
            for finding in self.findings
        )

        if self.verdict is AuditVerdict.APPROVED:
            if blocking_findings:
                raise ValueError(
                    "Un resultado aprobado no puede contener "
                    "hallazgos bloqueantes."
                )

            if not self.evidence_sufficient:
                raise ValueError(
                    "Un resultado aprobado debe contar con "
                    "evidencia suficiente."
                )

            if self.feedback_for_planner is not None:
                raise ValueError(
                    "Un resultado aprobado no debe incluir "
                    "retroalimentación de corrección."
                )

        if self.verdict is AuditVerdict.REVISE:
            if not self.findings:
                raise ValueError(
                    "Un resultado REVISE debe incluir "
                    "al menos un hallazgo."
                )

            if self.feedback_for_planner is None:
                raise ValueError(
                    "Un resultado REVISE debe incluir "
                    "retroalimentación para el planificador."
                )

        if self.verdict is AuditVerdict.HUMAN_REVIEW:
            if (
                not self.findings
                and not self.missing_information
            ):
                raise ValueError(
                    "HUMAN_REVIEW debe explicar los hallazgos "
                    "o la información faltante."
                )

        return self

class WorkflowResult(StrictModel):
    """
    Resultado final y estable del análisis de una vulnerabilidad.

    Oculta los detalles internos de LangGraph y expone únicamente
    la información necesaria para la aplicación, la demostración
    y futuras integraciones.
    """

    vulnerability_id: str = Field(
        min_length=1,
        max_length=100,
    )

    final_status: WorkflowStatus

    attempt_count: int = Field(
        ge=0,
    )

    max_attempts: int = Field(
        ge=1,
    )

    requires_human_review: bool

    group_ds: str | None = Field(
        default=None,
        max_length=200,
        description=(
            "Grupo interno obtenido exclusivamente "
            "del contexto del host."
        ),
    )

    management_code: ManagementCode | None = None

    management_ds: str | None = Field(
        default=None,
        max_length=100,
        description=(
            "Texto oficial recuperado desde el catálogo."
        ),
    )

    report_classification: (
        ReportClassification | None
    ) = None

    observation_ds: str | None = Field(
        default=None,
        max_length=OBSERVATION_MAX_LENGTH,
    )

    proposal: MitigationProposal | None = None

    policy_evaluation: PolicyEvaluation | None = None

    audit_result: AuditResult | None = None

    revision_feedback: str | None = None

    error_stage: str | None = None

    error_message: str | None = None

    @field_validator(
        "group_ds",
        "management_ds",
        "observation_ds",
        "revision_feedback",
        "error_stage",
        "error_message",
        mode="before",
    )
    @classmethod
    def normalize_optional_result_text(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def validate_result_consistency(
        self,
    ) -> "WorkflowResult":
        """
        Impide construir resultados finales contradictorios.
        """

        if (
            self.final_status
            is WorkflowStatus.PROCESSING_ERROR
        ):
            if (
                self.error_stage is None
                or self.error_message is None
            ):
                raise ValueError(
                    "PROCESSING_ERROR debe indicar "
                    "la etapa y el mensaje del error."
                )

        if (
            self.final_status
            is WorkflowStatus.APPROVED_DRAFT
        ):
            if self.proposal is None:
                raise ValueError(
                    "APPROVED_DRAFT debe incluir "
                    "una propuesta de mitigación."
                )

            if self.audit_result is None:
                raise ValueError(
                    "APPROVED_DRAFT debe incluir "
                    "el resultado de la auditoría."
                )

            if (
                self.audit_result.verdict
                is not AuditVerdict.APPROVED
            ):
                raise ValueError(
                    "APPROVED_DRAFT requiere que el "
                    "auditor haya aprobado la propuesta."
                )

        if self.proposal is None:
            controlled_fields = (
                self.management_code,
                self.management_ds,
                self.report_classification,
                self.observation_ds,
            )

            if any(
                value is not None
                for value in controlled_fields
            ):
                raise ValueError(
                    "No pueden existir campos de gestión "
                    "sin una propuesta asociada."
                )

        else:
            if (
                self.management_code
                is not self.proposal.management_code
            ):
                raise ValueError(
                    "management_code no coincide con "
                    "la propuesta del planificador."
                )

            if self.management_ds is None:
                raise ValueError(
                    "Una propuesta debe resolverse contra "
                    "el texto oficial del catálogo."
                )

            if self.report_classification is None:
                raise ValueError(
                    "Una propuesta debe incluir su "
                    "clasificación oficial."
                )

            if (
                self.observation_ds
                != self.proposal.observation_ds
            ):
                raise ValueError(
                    "observation_ds no coincide con "
                    "la propuesta validada."
                )

        return self