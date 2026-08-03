from __future__ import annotations

from typing import Any

import pytest

from src.adapters import row_to_vulnerability_case
from src.agents.planner import MitigationPlanner
from src.catalog import load_management_catalog
from src.enums import ManagementCode
from src.exceptions import (
    AgentExecutionError,
    DataQualityError,
    StructuredOutputError,
)
from src.models import (
    FullMitigationPlan,
    MitigationProposal,
)
from tests.test_adapters import build_valid_sql_row


class FakeStructuredModel:
    """
    Modelo controlado para probar el agente sin consumir API.
    """

    def __init__(
        self,
        *,
        response: Any = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.called = False
        self.last_input: Any = None

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        self.called = True
        self.last_input = input

        if self.error is not None:
            raise self.error

        return self.response


def build_valid_proposal() -> MitigationProposal:
    return MitigationProposal(
        vulnerability_id="DEMO-SQL-91721",
        management_code=(
            ManagementCode.SOLUTION_REQUIRES_EVALUATION
        ),
        classification_reason=(
            "La actualización requiere pruebas de "
            "compatibilidad antes de aplicarse."
        ),
        observation_ds=(
            "Evaluar la actualización en un ambiente "
            "controlado, validar compatibilidad, programar "
            "ventana y verificar mediante un nuevo escaneo."
        ),
        full_plan=FullMitigationPlan(
            summary=(
                "Evaluar e implementar la actualización "
                "de seguridad."
            ),
            recommended_actions=[
                "Validar compatibilidad.",
                "Aplicar la actualización aprobada.",
            ],
            prerequisites=[
                "Generar respaldo.",
                "Aprobar ventana de mantenimiento.",
            ],
            operational_impact=(
                "Puede requerir indisponibilidad temporal."
            ),
            maintenance_window_required=True,
            validation_steps=[
                "Validar la versión instalada.",
                "Ejecutar un nuevo escaneo.",
            ],
            rollback_steps=[
                "Restaurar el respaldo previo.",
            ],
            evidence_used=[
                "QID 91721",
                "CVE-2021-1636",
                "Ambiente de producción",
            ],
        ),
        confidence=0.86,
    )


def test_planner_returns_structured_proposal() -> None:
    model = FakeStructuredModel(
        response=build_valid_proposal(),
    )

    planner = MitigationPlanner(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    proposal = planner.generate(case)

    assert model.called is True
    assert (
        proposal.management_code
        is ManagementCode.SOLUTION_REQUIRES_EVALUATION
    )
    assert (
        proposal.vulnerability_id
        == case.vulnerability_id
    )

    # Comprueba que el prompt contiene los mensajes esperados.
    assert len(model.last_input) == 2
    assert (
        case.vulnerability_id
        in model.last_input[1].content
    )


def test_planner_does_not_call_model_for_invalid_case() -> None:
    sql_row = build_valid_sql_row()
    sql_row["HOST_GROUP_DS"] = "ND"
    sql_row["HAS_INTERNAL_GROUP_FLG"] = 0

    case = row_to_vulnerability_case(
        sql_row
    )

    model = FakeStructuredModel(
        response=build_valid_proposal(),
    )

    planner = MitigationPlanner(
        model=model,
        catalog=load_management_catalog(),
    )

    with pytest.raises(DataQualityError):
        planner.generate(case)

    assert model.called is False


def test_planner_rejects_invalid_structured_output() -> None:
    model = FakeStructuredModel(
        response={
            "unexpected_field": "invalid response",
        },
    )

    planner = MitigationPlanner(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(StructuredOutputError):
        planner.generate(case)


def test_planner_wraps_provider_errors() -> None:
    model = FakeStructuredModel(
        error=TimeoutError(
            "Provider timeout"
        ),
    )

    planner = MitigationPlanner(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(AgentExecutionError) as exc_info:
        planner.generate(case)

    assert isinstance(
        exc_info.value.__cause__,
        TimeoutError,
    )


def test_planner_rejects_mismatched_case_id() -> None:
    proposal = build_valid_proposal()
    proposal.vulnerability_id = "OTHER-CASE"

    model = FakeStructuredModel(
        response=proposal,
    )

    planner = MitigationPlanner(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(
        StructuredOutputError,
        match="identificador",
    ):
        planner.generate(case)