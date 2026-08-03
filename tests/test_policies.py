from copy import deepcopy

from src.catalog import load_management_catalog
from src.enums import (
    ManagementCode,
    PolicyDecision,
)
from src.models import (
    AssetContext,
    DataQuality,
    DetectionHistory,
    FullMitigationPlan,
    MitigationProposal,
    TechnicalContext,
    VulnerabilityCase,
    VulnerabilityDetails,
)
from src.policies import evaluate_mitigation_proposal


def build_case(
    *,
    internal_group: str | None = "Soporte Windows",
    has_internal_group: bool = True,
) -> VulnerabilityCase:
    return VulnerabilityCase(
        vulnerability_id="DEMO-SQL-91721",
        asset=AssetContext(
            host_id=444,
            ip="10.0.10.25",
            environment="Producción",
            internal_group=internal_group,
        ),
        vulnerability=VulnerabilityDetails(
            qid_id=8050,
            qid="91721",
            title="SQL Server Elevation of Privilege",
            vendor_information=(
                "Evaluate and install the security update."
            ),
            cves=["CVE-2021-1636"],
        ),
        technical=TechnicalContext(
            os_id=9,
            operating_system="Windows Server 2012 R2",
            port_id=1067,
            risk_id=4,
            risk_code="4",
            risk_description="Alto",
        ),
        detection=DetectionHistory(
            reoffending=True,
            times_detected=4111,
        ),
        quality=DataQuality(
            required_references_ok=True,
            has_internal_group=has_internal_group,
            has_qid_detail=True,
            has_vendor_information=True,
            has_cve_detail=True,
        ),
    )


def build_proposal(
    *,
    management_code: ManagementCode = (
        ManagementCode.SOLUTION_REQUIRES_EVALUATION
    ),
) -> MitigationProposal:
    return MitigationProposal(
        vulnerability_id="DEMO-SQL-91721",
        management_code=management_code,
        classification_reason=(
            "La actualización debe evaluarse antes de "
            "su implementación en producción."
        ),
        observation_ds=(
            "Validar compatibilidad, programar ventana "
            "de mantenimiento y verificar la remediación."
        ),
        full_plan=FullMitigationPlan(
            summary="Evaluar e implementar la actualización.",
            recommended_actions=[
                "Validar compatibilidad.",
                "Aplicar la actualización aprobada.",
            ],
            prerequisites=[
                "Obtener aprobación para la ventana.",
                "Generar un respaldo actualizado.",
            ],
            operational_impact=(
                "Puede requerirse indisponibilidad temporal."
            ),
            maintenance_window_required=True,
            validation_steps=[
                "Verificar la versión instalada.",
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


def test_valid_proposal_passes_policy_gate() -> None:
    evaluation = evaluate_mitigation_proposal(
        build_case(),
        build_proposal(),
        load_management_catalog(),
    )

    assert evaluation.decision is PolicyDecision.PASS
    assert evaluation.passed is True
    assert evaluation.findings == []


def test_mismatched_vulnerability_id_requires_revision() -> None:
    proposal = build_proposal()
    proposal.vulnerability_id = "OTHER-CASE"

    evaluation = evaluate_mitigation_proposal(
        build_case(),
        proposal,
        load_management_catalog(),
    )

    assert evaluation.decision is PolicyDecision.REVISE
    assert evaluation.findings[0].code == (
        "VULNERABILITY_ID_MISMATCH"
    )


def test_missing_host_group_goes_to_data_quality_review() -> None:
    evaluation = evaluate_mitigation_proposal(
        build_case(
            internal_group=None,
            has_internal_group=False,
        ),
        build_proposal(),
        load_management_catalog(),
    )

    assert (
        evaluation.decision
        is PolicyDecision.DATA_QUALITY_REVIEW
    )
    assert evaluation.requires_human_review is True


def test_disallowed_initial_code_requires_revision() -> None:
    evaluation = evaluate_mitigation_proposal(
        build_case(),
        build_proposal(
            management_code=(
                ManagementCode.RESOURCE_DECOMMISSIONING
            )
        ),
        load_management_catalog(),
    )

    assert (
        evaluation.decision
        is PolicyDecision.REVISE
    )
    assert evaluation.requires_human_review is False

def test_management_for_another_area_goes_to_data_quality() -> None:
    evaluation = evaluate_mitigation_proposal(
        build_case(),
        build_proposal(
            management_code=(
                ManagementCode.MANAGEMENT_BELONGS_TO_ANOTHER_AREA
            )
        ),
        load_management_catalog(),
    )

    assert (
        evaluation.decision
        is PolicyDecision.DATA_QUALITY_REVIEW
    )

def test_disallowed_initial_code_requires_revision() -> None:
    evaluation = evaluate_mitigation_proposal(
        build_case(),
        build_proposal(
            management_code=(
                ManagementCode.RESOURCE_DECOMMISSIONING
            )
        ),
        load_management_catalog(),
    )

    assert (
        evaluation.decision
        is PolicyDecision.REVISE
    )
    assert evaluation.requires_human_review is False