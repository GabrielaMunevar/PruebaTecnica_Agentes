from __future__ import annotations

from pydantic import ValidationError

from src.catalog import ManagementCatalog
from src.enums import WorkflowStatus
from src.exceptions import (
    AgentExecutionError,
    DataQualityError,
    StructuredOutputError,
)
from src.models import (
    MitigationProposal,
    VulnerabilityCase,
)
from src.prompts import build_planner_messages
from src.protocols import StructuredModel


class MitigationPlanner:
    """
    Agente responsable de proponer la clasificación inicial
    y el plan técnico de mitigación.
    """

    def __init__(
        self,
        model: StructuredModel,
        catalog: ManagementCatalog,
    ) -> None:
        self._model = model
        self._catalog = catalog

    def generate(
        self,
        case: VulnerabilityCase,
        *,
        previous_proposal: MitigationProposal | None = None,
        revision_feedback: str | None = None,
    ) -> MitigationProposal:
        """
        Genera una propuesta estructurada.

        Cuando recibe una propuesta anterior y retroalimentación,
        solicita al modelo una versión corregida.
        """

        if (
            case.initial_status
            is not WorkflowStatus.READY_FOR_AI
        ):
            raise DataQualityError(
                "El caso no tiene la calidad mínima "
                "para ser procesado por el planificador."
            )

        messages = build_planner_messages(
            case=case,
            catalog=self._catalog,
            previous_proposal=previous_proposal,
            revision_feedback=revision_feedback,
        )

        try:
            raw_response = self._model.invoke(
                messages
            )

        except Exception as exc:
            raise AgentExecutionError(
                "El agente planificador no pudo generar "
                f"una propuesta para {case.vulnerability_id!r}."
            ) from exc

        try:
            if isinstance(
                raw_response,
                MitigationProposal,
            ):
                proposal = raw_response
            else:
                proposal = (
                    MitigationProposal.model_validate(
                        raw_response
                    )
                )

        except (
            ValidationError,
            TypeError,
            ValueError,
        ) as exc:
            raise StructuredOutputError(
                "La respuesta del agente planificador "
                "no cumple el contrato MitigationProposal."
            ) from exc

        if (
            proposal.vulnerability_id
            != case.vulnerability_id
        ):
            raise StructuredOutputError(
                "El identificador retornado por el agente "
                "no corresponde al caso procesado."
            )

        return proposal