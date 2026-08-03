from __future__ import annotations

from typing import TypedDict

from src.enums import WorkflowStatus
from src.models import (
    AuditResult,
    MitigationProposal,
    PolicyEvaluation,
    VulnerabilityCase,
)


class WorkflowState(TypedDict, total=False):
    """
    Estado compartido del flujo de análisis de vulnerabilidades.

    LangGraph entrega este estado a cada nodo. Cada nodo devuelve
    únicamente los campos que necesita actualizar.
    """

    # Entrada principal
    case: VulnerabilityCase

    # Resultados intermedios
    proposal: MitigationProposal | None
    policy_evaluation: PolicyEvaluation | None
    audit_result: AuditResult | None

    # Control del ciclo
    attempt_count: int
    max_attempts: int
    revision_feedback: str | None

    # Decisiones acumuladas
    requires_human_review: bool
    final_status: WorkflowStatus | None

    # Manejo controlado de errores
    error_stage: str | None
    error_message: str | None