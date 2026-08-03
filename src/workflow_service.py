from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from src.catalog import ManagementCatalog
from src.exceptions import (
    ConfigurationError,
    WorkflowExecutionError,
)
from src.models import (
    MitigationProposal,
    VulnerabilityCase,
    WorkflowResult,
)
from src.protocols import InvokableWorkflow


class VulnerabilityWorkflowService:
    """
    Fachada de aplicación para ejecutar el flujo multiagente.

    La capa que invoque este servicio no necesita conocer nodos,
    rutas condicionales ni la estructura interna de LangGraph.
    """

    def __init__(
        self,
        workflow: InvokableWorkflow,
        catalog: ManagementCatalog,
    ) -> None:
        self._workflow = workflow
        self._catalog = catalog

    def analyze(
        self,
        case: VulnerabilityCase,
        *,
        max_attempts: int | None = None,
    ) -> WorkflowResult:
        """
        Ejecuta el workflow y transforma su estado interno
        en un resultado final estable.
        """

        initial_state: dict[str, Any] = {
            "case": case,
        }

        if max_attempts is not None:
            if max_attempts < 1:
                raise ConfigurationError(
                    "max_attempts debe ser mayor que cero."
                )

            initial_state["max_attempts"] = max_attempts

        try:
            raw_state = self._workflow.invoke(
                initial_state
            )

        except Exception as exc:
            raise WorkflowExecutionError(
                "El workflow no pudo ejecutarse para "
                f"la vulnerabilidad {case.vulnerability_id!r}."
            ) from exc

        if not isinstance(raw_state, Mapping):
            raise WorkflowExecutionError(
                "El workflow devolvió un resultado "
                "con un formato no reconocido."
            )

        try:
            return self._build_result(
                case=case,
                state=raw_state,
            )

        except (
            ValidationError,
            TypeError,
            ValueError,
            KeyError,
        ) as exc:
            raise WorkflowExecutionError(
                "No fue posible construir el resultado "
                "final del workflow."
            ) from exc

    def _build_result(
        self,
        *,
        case: VulnerabilityCase,
        state: Mapping[str, Any],
    ) -> WorkflowResult:
        """
        Traduce el estado mutable de LangGraph a un contrato
        final validado mediante Pydantic.
        """

        proposal_value = state.get("proposal")

        proposal: MitigationProposal | None

        if proposal_value is None:
            proposal = None

        elif isinstance(
            proposal_value,
            MitigationProposal,
        ):
            proposal = proposal_value

        else:
            proposal = MitigationProposal.model_validate(
                proposal_value
            )

        catalog_entry = (
            self._catalog.get(
                proposal.management_code
            )
            if proposal is not None
            else None
        )

        return WorkflowResult(
            vulnerability_id=case.vulnerability_id,
            final_status=state["final_status"],
            attempt_count=state.get(
                "attempt_count",
                0,
            ),
            max_attempts=state.get(
                "max_attempts",
                1,
            ),
            requires_human_review=state.get(
                "requires_human_review",
                False,
            ),
            group_ds=case.asset.internal_group,
            management_code=(
                proposal.management_code
                if proposal is not None
                else None
            ),
            management_ds=(
                catalog_entry.management_ds
                if catalog_entry is not None
                else None
            ),
            report_classification=(
                catalog_entry.report_classification
                if catalog_entry is not None
                else None
            ),
            observation_ds=(
                proposal.observation_ds
                if proposal is not None
                else None
            ),
            proposal=proposal,
            policy_evaluation=state.get(
                "policy_evaluation"
            ),
            audit_result=state.get(
                "audit_result"
            ),
            revision_feedback=state.get(
                "revision_feedback"
            ),
            error_stage=state.get(
                "error_stage"
            ),
            error_message=state.get(
                "error_message"
            ),
        )