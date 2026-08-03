from __future__ import annotations

from pydantic import ValidationError

from src.catalog import ManagementCatalog
from src.enums import (
    PolicyDecision,
    WorkflowStatus,
)
from src.exceptions import (
    AgentExecutionError,
    DataQualityError,
    PolicyValidationError,
    StructuredOutputError,
)
from src.models import (
    AuditResult,
    MitigationProposal,
    PolicyEvaluation,
    VulnerabilityCase,
)
from src.prompts import build_auditor_messages
from src.protocols import StructuredModel


class MitigationAuditor:
    """
    Agente responsable de evaluar técnica y semánticamente
    una propuesta de mitigación.
    """

    def __init__(
        self,
        model: StructuredModel,
        catalog: ManagementCatalog,
    ) -> None:
        self._model = model
        self._catalog = catalog

    def review(
        self,
        case: VulnerabilityCase,
        proposal: MitigationProposal,
        policy_evaluation: PolicyEvaluation,
    ) -> AuditResult:
        """
        Audita una propuesta que ya superó los guardrails
        deterministas.
        """

        if (
            case.initial_status
            is not WorkflowStatus.READY_FOR_AI
        ):
            raise DataQualityError(
                "El caso no tiene la calidad mínima "
                "para ser auditado."
            )

        if (
            policy_evaluation.decision
            is not PolicyDecision.PASS
        ):
            raise PolicyValidationError(
                "El auditor solo puede revisar propuestas "
                "que hayan superado el Policy Gate."
            )

        if (
            proposal.vulnerability_id
            != case.vulnerability_id
        ):
            raise PolicyValidationError(
                "La propuesta no corresponde al caso "
                "que se intenta auditar."
            )

        messages = build_auditor_messages(
            case=case,
            proposal=proposal,
            policy_evaluation=policy_evaluation,
            catalog=self._catalog,
        )

        try:
            raw_response = self._model.invoke(
                messages
            )

        except Exception as exc:
            raise AgentExecutionError(
                "El agente auditor no pudo evaluar "
                f"la propuesta {case.vulnerability_id!r}."
            ) from exc

        try:
            if isinstance(
                raw_response,
                AuditResult,
            ):
                audit_result = raw_response
            else:
                audit_result = (
                    AuditResult.model_validate(
                        raw_response
                    )
                )

        except (
            ValidationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StructuredOutputError(
                "La respuesta del agente auditor "
                "no cumple el contrato AuditResult."
            ) from exc

        if (
            audit_result.vulnerability_id
            != case.vulnerability_id
        ):
            raise StructuredOutputError(
                "El identificador retornado por el auditor "
                "no corresponde al caso procesado."
            )

        return audit_result