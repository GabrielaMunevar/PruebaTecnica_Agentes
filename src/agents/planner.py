from __future__ import annotations

from typing import Any, Protocol

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


class StructuredModel(Protocol):
    """
    Contrato mínimo requerido por el agente planificador.

    Tanto un modelo real de LangChain como un modelo falso
    utilizado en pruebas pueden implementar este protocolo.
    """

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        ...


class MitigationPlanner:
    """
    Agente responsable de proponer la clasificación inicial
    y el plan técnico de mitigación.

    La clase no conoce el proveedor concreto del modelo.
    Recibe una dependencia que cumple StructuredModel.
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
    ) -> MitigationProposal:
        """
        Genera una propuesta estructurada para un caso válido.

        Los problemas de datos se detienen antes de invocar el LLM.
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
            case,
            self._catalog,
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