from __future__ import annotations

from src.catalog import ManagementCatalog
from src.enums import (
    PolicyDecision,
    WorkflowStatus,
)
from src.models import (
    MitigationProposal,
    PolicyEvaluation,
    PolicyFinding,
    VulnerabilityCase,
)


def evaluate_mitigation_proposal(
    case: VulnerabilityCase,
    proposal: MitigationProposal,
    catalog: ManagementCatalog,
) -> PolicyEvaluation:
    """
    Evalúa una propuesta mediante reglas deterministas.

    No realiza evaluación semántica profunda. Esa responsabilidad
    corresponde posteriormente al agente auditor.
    """

    findings: list[PolicyFinding] = []

    # -------------------------------------------------------------
    # 1. Calidad de datos del caso
    # -------------------------------------------------------------
    if (
        case.initial_status
        is WorkflowStatus.DATA_QUALITY_REVIEW
    ):
        return PolicyEvaluation(
            decision=PolicyDecision.DATA_QUALITY_REVIEW,
            findings=[
                PolicyFinding(
                    code="CASE_NOT_READY_FOR_AI",
                    message=(
                        "El caso no cumple las condiciones mínimas "
                        "de calidad para ser procesado por agentes."
                    ),
                    field="case.initial_status",
                )
            ],
            requires_human_review=True,
        )

    # -------------------------------------------------------------
    # 2. Integridad entre caso y propuesta
    # -------------------------------------------------------------
    if (
        proposal.vulnerability_id
        != case.vulnerability_id
    ):
        findings.append(
            PolicyFinding(
                code="VULNERABILITY_ID_MISMATCH",
                message=(
                    "La propuesta no corresponde al identificador "
                    "de la vulnerabilidad analizada."
                ),
                field="vulnerability_id",
            )
        )

    # -------------------------------------------------------------
    # 3. Resolver políticas del código de gestión
    # -------------------------------------------------------------
    catalog_entry = catalog.get(
        proposal.management_code
    )

    if not catalog_entry.allowed_as_initial_proposal:
        findings.append(
            PolicyFinding(
                code="MANAGEMENT_CODE_NOT_ALLOWED_INITIAL",
                message=(
                    "La respuesta tipificada seleccionada no puede "
                    "proponerse durante el análisis inicial."
                ),
                field="management_code",
            )
        )

        if (
            catalog_entry.system_status
            is WorkflowStatus.DATA_QUALITY_REVIEW
        ):
            return PolicyEvaluation(
                decision=PolicyDecision.DATA_QUALITY_REVIEW,
                findings=findings,
                requires_human_review=True,
            )

        return PolicyEvaluation(
            decision=PolicyDecision.HUMAN_REVIEW,
            findings=findings,
            requires_human_review=True,
        )

    # -------------------------------------------------------------
    # 4. El grupo debe provenir del host
    # -------------------------------------------------------------
    if case.asset.internal_group is None:
        findings.append(
            PolicyFinding(
                code="HOST_GROUP_NOT_CONFIGURED",
                message=(
                    "El host no tiene un grupo interno "
                    "parametrizado en TBL_HOST.GROUP_DS."
                ),
                field="asset.internal_group",
            )
        )

        return PolicyEvaluation(
            decision=PolicyDecision.DATA_QUALITY_REVIEW,
            findings=findings,
            requires_human_review=True,
        )

    # -------------------------------------------------------------
    # 5. Una ventana de mantenimiento exige prerrequisitos
    # -------------------------------------------------------------
    if (
        proposal.full_plan.maintenance_window_required
        and not proposal.full_plan.prerequisites
    ):
        findings.append(
            PolicyFinding(
                code="MAINTENANCE_WINDOW_WITHOUT_PREREQUISITES",
                message=(
                    "El plan requiere ventana de mantenimiento, "
                    "pero no define aprobación, respaldo u otras "
                    "condiciones previas."
                ),
                field="full_plan.prerequisites",
            )
        )

    # -------------------------------------------------------------
    # 6. La propuesta debe usar evidencia del caso
    # -------------------------------------------------------------
    if not proposal.full_plan.evidence_used:
        findings.append(
            PolicyFinding(
                code="EVIDENCE_NOT_PROVIDED",
                message=(
                    "El plan no identifica la evidencia utilizada "
                    "para respaldar la recomendación."
                ),
                field="full_plan.evidence_used",
            )
        )

    # -------------------------------------------------------------
    # 7. Si existen incumplimientos corregibles, solicitar revisión
    # -------------------------------------------------------------
    if findings:
        return PolicyEvaluation(
            decision=PolicyDecision.REVISE,
            findings=findings,
            requires_human_review=False,
        )

    # -------------------------------------------------------------
    # 8. Algunas respuestas son válidas, pero requieren una persona
    # -------------------------------------------------------------
    if catalog_entry.human_review_required:
        return PolicyEvaluation(
            decision=PolicyDecision.HUMAN_REVIEW,
            findings=[],
            requires_human_review=True,
        )

    return PolicyEvaluation(
        decision=PolicyDecision.PASS,
        findings=[],
        requires_human_review=False,
    )