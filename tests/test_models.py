import pytest
from pydantic import ValidationError

from src.enums import ManagementCode
from src.models import (
    FullMitigationPlan,
    MitigationProposal,
)


def build_valid_full_plan() -> FullMitigationPlan:
    return FullMitigationPlan(
        summary=(
            "Evaluar e implementar la actualización "
            "de seguridad recomendada."
        ),
        recommended_actions=[
            "Validar compatibilidad en un ambiente controlado.",
            "Programar la implementación del parche.",
        ],
        prerequisites=[
            "Contar con respaldo actualizado.",
            "Obtener aprobación para la ventana de mantenimiento.",
        ],
        operational_impact=(
            "La actualización puede requerir indisponibilidad "
            "temporal del servicio."
        ),
        maintenance_window_required=True,
        validation_steps=[
            "Verificar la versión instalada.",
            "Ejecutar nuevamente el escaneo de vulnerabilidades.",
        ],
        rollback_steps=[
            "Restaurar el respaldo previo.",
            "Reinstalar la versión anterior si el servicio falla.",
        ],
        assumptions=[
            "El activo corresponde al sistema reportado.",
        ],
        missing_information=[
            "Fecha disponible para la ventana de mantenimiento.",
        ],
        evidence_used=[
            "QID 91721",
            "CVE-2021-1636",
            "Ambiente de producción",
        ],
    )


def test_valid_mitigation_proposal() -> None:
    proposal = MitigationProposal(
        vulnerability_id="DEMO-SQL-91721",
        management_code=(
            ManagementCode.SOLUTION_REQUIRES_EVALUATION
        ),
        classification_reason=(
            "Existe una actualización disponible, pero debe "
            "validarse su compatibilidad antes de implementarla."
        ),
        observation_ds=(
            "Se recomienda validar la actualización en un "
            "ambiente controlado, confirmar compatibilidad, "
            "programar ventana de mantenimiento y verificar "
            "la remediación mediante un nuevo escaneo."
        ),
        full_plan=build_valid_full_plan(),
        confidence=0.86,
    )

    assert (
        proposal.management_code
        is ManagementCode.SOLUTION_REQUIRES_EVALUATION
    )
    assert proposal.confidence == 0.86
    assert len(proposal.observation_ds) <= 500


def test_observation_cannot_exceed_database_limit() -> None:
    with pytest.raises(ValidationError):
        MitigationProposal(
            vulnerability_id="DEMO-SQL-91721",
            management_code=(
                ManagementCode.SOLUTION_REQUIRES_EVALUATION
            ),
            classification_reason="Justificación válida.",
            observation_ds="X" * 501,
            full_plan=build_valid_full_plan(),
            confidence=0.80,
        )


def test_plan_requires_rollback_or_explanation() -> None:
    with pytest.raises(ValidationError):
        FullMitigationPlan(
            summary="Evaluar la solución propuesta.",
            recommended_actions=[
                "Realizar pruebas de compatibilidad.",
            ],
            prerequisites=[],
            operational_impact=(
                "No se prevén cambios inmediatos."
            ),
            maintenance_window_required=False,
            validation_steps=[
                "Documentar el resultado de las pruebas.",
            ],
            rollback_steps=[],
            rollback_not_applicable_reason=None,
            assumptions=[],
            missing_information=[],
            evidence_used=[
                "Información del QID",
            ],
        )


def test_plan_accepts_rollback_not_applicable_reason() -> None:
    plan = FullMitigationPlan(
        summary="Evaluar la solución propuesta.",
        recommended_actions=[
            "Realizar pruebas de compatibilidad.",
        ],
        prerequisites=[],
        operational_impact=(
            "No se realizan cambios sobre el activo."
        ),
        maintenance_window_required=False,
        validation_steps=[
            "Documentar el resultado de la evaluación.",
        ],
        rollback_steps=[],
        rollback_not_applicable_reason=(
            "No aplica porque el plan solo contempla "
            "actividades de análisis."
        ),
        assumptions=[],
        missing_information=[],
        evidence_used=[
            "Información del QID",
        ],
    )

    assert plan.rollback_steps == []
    assert plan.rollback_not_applicable_reason is not None