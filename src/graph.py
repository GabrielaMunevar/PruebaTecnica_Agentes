from __future__ import annotations

import logging
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from src.agents.auditor import MitigationAuditor
from src.agents.planner import MitigationPlanner
from src.catalog import ManagementCatalog
from src.constants import DEFAULT_MAX_ATTEMPTS
from src.enums import (
    AuditVerdict,
    PolicyDecision,
    WorkflowStatus,
)
from src.exceptions import ConfigurationError
from src.models import (
    AuditResult,
    PolicyEvaluation,
)
from src.policies import evaluate_mitigation_proposal
from src.state import WorkflowState


logger = logging.getLogger(__name__)


def _build_policy_feedback(
    evaluation: PolicyEvaluation,
) -> str:
    """
    Convierte los hallazgos deterministas en retroalimentación
    legible para el agente planificador.
    """

    finding_lines = [
        f"- [{finding.code}] {finding.message}"
        for finding in evaluation.findings
    ]

    return "\n".join(
        [
            "La propuesta incumplió los siguientes guardrails:",
            *finding_lines,
            "Genera una nueva propuesta corrigiendo "
            "todos los hallazgos.",
        ]
    )


def _build_audit_feedback(
    audit_result: AuditResult,
) -> str:
    """
    Convierte el resultado del auditor en retroalimentación
    concreta para el agente planificador.
    """

    sections: list[str] = [
        "El agente auditor solicitó corregir la propuesta."
    ]

    if audit_result.feedback_for_planner:
        sections.append(
            audit_result.feedback_for_planner
        )

    if audit_result.findings:
        sections.append("Hallazgos del auditor:")

        sections.extend(
            f"- [{finding.code}] {finding.message}"
            for finding in audit_result.findings
        )

    if audit_result.missing_information:
        sections.append("Información faltante identificada:")

        sections.extend(
            f"- {item}"
            for item in audit_result.missing_information
        )

    return "\n".join(sections)


def _route_after_validation(
    state: WorkflowState,
) -> Literal["planner", "finalize"]:
    if state.get("final_status") is not None:
        return "finalize"

    return "planner"


def _route_after_planner(
    state: WorkflowState,
) -> Literal["policy_gate", "finalize"]:
    if (
        state.get("final_status")
        is WorkflowStatus.PROCESSING_ERROR
    ):
        return "finalize"

    return "policy_gate"


def _route_after_policy(
    state: WorkflowState,
) -> Literal[
    "auditor",
    "prepare_revision",
    "finalize",
]:
    if (
        state.get("final_status")
        is WorkflowStatus.PROCESSING_ERROR
    ):
        return "finalize"

    evaluation = state.get("policy_evaluation")

    if evaluation is None:
        return "finalize"

    if evaluation.decision is PolicyDecision.PASS:
        return "auditor"

    if evaluation.decision is PolicyDecision.REVISE:
        return "prepare_revision"

    return "finalize"


def _route_after_audit(
    state: WorkflowState,
) -> Literal[
    "prepare_revision",
    "finalize",
]:
    if (
        state.get("final_status")
        is WorkflowStatus.PROCESSING_ERROR
    ):
        return "finalize"

    audit_result = state.get("audit_result")

    if audit_result is None:
        return "finalize"

    if audit_result.verdict is AuditVerdict.REVISE:
        return "prepare_revision"

    return "finalize"


def _route_after_revision(
    state: WorkflowState,
) -> Literal["planner", "finalize"]:
    if state.get("final_status") is not None:
        return "finalize"

    return "planner"


def build_vulnerability_workflow(
    *,
    planner: MitigationPlanner,
    auditor: MitigationAuditor,
    catalog: ManagementCatalog,
    default_max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> Any:
    """
    Construye y compila el flujo multiagente.

    Las dependencias se reciben externamente para permitir
    pruebas con modelos simulados y proveedores intercambiables.
    """

    if default_max_attempts < 1:
        raise ConfigurationError(
            "default_max_attempts debe ser mayor que cero."
        )

    def processing_error_update(
        *,
        state: WorkflowState,
        stage: str,
        exc: Exception,
    ) -> WorkflowState:
        """
        Registra internamente el error y expone al estado
        únicamente un mensaje controlado.
        """

        case = state.get("case")

        logger.exception(
            "Error durante la etapa %s para la vulnerabilidad %s.",
            stage,
            (
                case.vulnerability_id
                if case is not None
                else "UNKNOWN"
            ),
        )

        return {
            "final_status": WorkflowStatus.PROCESSING_ERROR,
            "error_stage": stage,
            "error_message": (
                "Ocurrió un error controlado durante "
                f"la etapa {stage}."
            ),
        }

    def validate_case_node(
        state: WorkflowState,
    ) -> WorkflowState:
        """
        Valida la entrada antes de ejecutar agentes.
        """

        case = state.get("case")

        if case is None:
            return {
                "final_status": (
                    WorkflowStatus.PROCESSING_ERROR
                ),
                "error_stage": "validate_case",
                "error_message": (
                    "No se recibió un caso de vulnerabilidad."
                ),
            }

        max_attempts = state.get(
            "max_attempts",
            default_max_attempts,
        )

        if max_attempts < 1:
            return {
                "final_status": (
                    WorkflowStatus.PROCESSING_ERROR
                ),
                "error_stage": "validate_case",
                "error_message": (
                    "El número máximo de intentos "
                    "debe ser mayor que cero."
                ),
            }

        if (
            case.initial_status
            is WorkflowStatus.DATA_QUALITY_REVIEW
        ):
            return {
                "attempt_count": 0,
                "max_attempts": max_attempts,
                "requires_human_review": True,
                "final_status": (
                    WorkflowStatus.DATA_QUALITY_REVIEW
                ),
            }

        return {
            "attempt_count": state.get(
                "attempt_count",
                0,
            ),
            "max_attempts": max_attempts,
            "requires_human_review": False,
            "final_status": None,
            "error_stage": None,
            "error_message": None,
        }

    def planner_node(
        state: WorkflowState,
    ) -> WorkflowState:
        """
        Ejecuta el agente planificador.

        Cada ejecución incrementa attempt_count.
        """

        case = state["case"]
        revision_feedback = state.get(
            "revision_feedback"
        )

        previous_proposal = (
            state.get("proposal")
            if revision_feedback
            else None
        )

        try:
            proposal = planner.generate(
                case,
                previous_proposal=previous_proposal,
                revision_feedback=revision_feedback,
            )

        except Exception as exc:
            return processing_error_update(
                state=state,
                stage="planner",
                exc=exc,
            )

        return {
            "proposal": proposal,
            "policy_evaluation": None,
            "audit_result": None,
            "attempt_count": (
                state.get("attempt_count", 0) + 1
            ),
            "revision_feedback": None,
            "requires_human_review": False,
            "final_status": None,
        }

    def policy_gate_node(
        state: WorkflowState,
    ) -> WorkflowState:
        """
        Ejecuta los guardrails deterministas.
        """

        case = state["case"]
        proposal = state.get("proposal")

        if proposal is None:
            return {
                "final_status": (
                    WorkflowStatus.PROCESSING_ERROR
                ),
                "error_stage": "policy_gate",
                "error_message": (
                    "No existe una propuesta para validar."
                ),
            }

        try:
            evaluation = evaluate_mitigation_proposal(
                case=case,
                proposal=proposal,
                catalog=catalog,
            )

        except Exception as exc:
            return processing_error_update(
                state=state,
                stage="policy_gate",
                exc=exc,
            )

        return {
            "policy_evaluation": evaluation,
            "requires_human_review": (
                evaluation.requires_human_review
            ),
        }

    def auditor_node(
        state: WorkflowState,
    ) -> WorkflowState:
        """
        Ejecuta el agente auditor únicamente después
        de superar el Policy Gate.
        """

        case = state["case"]
        proposal = state.get("proposal")
        policy_evaluation = state.get(
            "policy_evaluation"
        )

        if (
            proposal is None
            or policy_evaluation is None
        ):
            return {
                "final_status": (
                    WorkflowStatus.PROCESSING_ERROR
                ),
                "error_stage": "auditor",
                "error_message": (
                    "No existe suficiente información "
                    "para ejecutar la auditoría."
                ),
            }

        try:
            audit_result = auditor.review(
                case=case,
                proposal=proposal,
                policy_evaluation=policy_evaluation,
            )

        except Exception as exc:
            return processing_error_update(
                state=state,
                stage="auditor",
                exc=exc,
            )

        return {
            "audit_result": audit_result,
        }

    def prepare_revision_node(
        state: WorkflowState,
    ) -> WorkflowState:
        """
        Prepara la retroalimentación y controla el límite
        máximo de intentos.
        """

        policy_evaluation = state.get(
            "policy_evaluation"
        )

        audit_result = state.get(
            "audit_result"
        )

        if (
            policy_evaluation is not None
            and policy_evaluation.decision
            is PolicyDecision.REVISE
        ):
            feedback = _build_policy_feedback(
                policy_evaluation
            )

        elif (
            audit_result is not None
            and audit_result.verdict
            is AuditVerdict.REVISE
        ):
            feedback = _build_audit_feedback(
                audit_result
            )

        else:
            return {
                "final_status": (
                    WorkflowStatus.PROCESSING_ERROR
                ),
                "error_stage": "prepare_revision",
                "error_message": (
                    "No se encontró retroalimentación "
                    "válida para corregir la propuesta."
                ),
            }

        attempt_count = state.get(
            "attempt_count",
            0,
        )

        max_attempts = state.get(
            "max_attempts",
            default_max_attempts,
        )

        if attempt_count >= max_attempts:
            return {
                "revision_feedback": (
                    feedback
                    + "\nSe alcanzó el número máximo "
                    "de intentos automáticos."
                ),
                "requires_human_review": True,
                "final_status": (
                    WorkflowStatus.HUMAN_REVIEW
                ),
            }

        return {
            "revision_feedback": feedback,
            "final_status": None,
        }

    def finalize_node(
        state: WorkflowState,
    ) -> WorkflowState:
        """
        Traduce los resultados intermedios al estado final
        del proceso.
        """

        existing_status = state.get(
            "final_status"
        )

        terminal_statuses = {
            WorkflowStatus.APPROVED_DRAFT,
            WorkflowStatus.HUMAN_REVIEW,
            WorkflowStatus.DATA_QUALITY_REVIEW,
            WorkflowStatus.POLICY_BLOCKED,
            WorkflowStatus.PROCESSING_ERROR,
        }

        if existing_status in terminal_statuses:
            return {
                "final_status": existing_status,
            }

        policy_evaluation = state.get(
            "policy_evaluation"
        )

        audit_result = state.get(
            "audit_result"
        )

        if policy_evaluation is not None:
            if (
                policy_evaluation.decision
                is PolicyDecision.DATA_QUALITY_REVIEW
            ):
                return {
                    "final_status": (
                        WorkflowStatus.DATA_QUALITY_REVIEW
                    ),
                    "requires_human_review": True,
                }

            if (
                policy_evaluation.decision
                is PolicyDecision.HUMAN_REVIEW
            ):
                return {
                    "final_status": (
                        WorkflowStatus.HUMAN_REVIEW
                    ),
                    "requires_human_review": True,
                }

        if audit_result is not None:
            if (
                audit_result.verdict
                is AuditVerdict.HUMAN_REVIEW
            ):
                return {
                    "final_status": (
                        WorkflowStatus.HUMAN_REVIEW
                    ),
                    "requires_human_review": True,
                }

            if (
                audit_result.verdict
                is AuditVerdict.APPROVED
            ):
                if state.get(
                    "requires_human_review",
                    False,
                ):
                    return {
                        "final_status": (
                            WorkflowStatus.HUMAN_REVIEW
                        ),
                        "requires_human_review": True,
                    }

                return {
                    "final_status": (
                        WorkflowStatus.APPROVED_DRAFT
                    ),
                    "requires_human_review": False,
                }

        return {
            "final_status": (
                WorkflowStatus.PROCESSING_ERROR
            ),
            "error_stage": "finalize",
            "error_message": (
                "El workflow terminó sin una decisión válida."
            ),
        }

    graph_builder = StateGraph(
        WorkflowState
    )

    graph_builder.add_node(
        "validate_case",
        validate_case_node,
    )

    graph_builder.add_node(
        "planner",
        planner_node,
    )

    graph_builder.add_node(
        "policy_gate",
        policy_gate_node,
    )

    graph_builder.add_node(
        "auditor",
        auditor_node,
    )

    graph_builder.add_node(
        "prepare_revision",
        prepare_revision_node,
    )

    graph_builder.add_node(
        "finalize",
        finalize_node,
    )

    graph_builder.add_edge(
        START,
        "validate_case",
    )

    graph_builder.add_conditional_edges(
        "validate_case",
        _route_after_validation,
        {
            "planner": "planner",
            "finalize": "finalize",
        },
    )

    graph_builder.add_conditional_edges(
        "planner",
        _route_after_planner,
        {
            "policy_gate": "policy_gate",
            "finalize": "finalize",
        },
    )

    graph_builder.add_conditional_edges(
        "policy_gate",
        _route_after_policy,
        {
            "auditor": "auditor",
            "prepare_revision": "prepare_revision",
            "finalize": "finalize",
        },
    )

    graph_builder.add_conditional_edges(
        "auditor",
        _route_after_audit,
        {
            "prepare_revision": "prepare_revision",
            "finalize": "finalize",
        },
    )

    graph_builder.add_conditional_edges(
        "prepare_revision",
        _route_after_revision,
        {
            "planner": "planner",
            "finalize": "finalize",
        },
    )

    graph_builder.add_edge(
        "finalize",
        END,
    )

    return graph_builder.compile()