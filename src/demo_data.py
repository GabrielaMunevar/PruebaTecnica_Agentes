from __future__ import annotations

from src.enums import (
    AuditVerdict,
    ManagementCode,
)
from src.models import (
    AssetContext,
    AuditFinding,
    AuditResult,
    DataQuality,
    DetectionHistory,
    FullMitigationPlan,
    MitigationProposal,
    TechnicalContext,
    VulnerabilityCase,
    VulnerabilityDetails,
)


DEMO_VULNERABILITY_ID = "DEMO-SQL-91721"


def build_demo_case(
    *,
    has_internal_group: bool = True,
) -> VulnerabilityCase:
    """
    Construye un caso sintético para la demostración.

    No contiene direcciones, nombres de host ni información
    procedente de la infraestructura real del cliente.
    """

    internal_group = (
        "Soporte de Plataformas"
        if has_internal_group
        else None
    )

    return VulnerabilityCase(
        vulnerability_id=DEMO_VULNERABILITY_ID,
        asset=AssetContext(
            host_id=1001,
            ip="192.0.2.25",
            dns="demo-sql-01.example.test",
            netbios="DEMO-SQL-01",
            product=(
                "Motor de base de datos de demostración"
            ),
            environment="Producción",
            condition="Activo",
            internal_group=internal_group,
        ),
        vulnerability=VulnerabilityDetails(
            qid_id=8050,
            qid="91721",
            title=(
                "Vulnerabilidad de elevación de privilegios "
                "en motor de base de datos"
            ),
            threat=(
                "Un usuario autenticado podría elevar "
                "sus privilegios."
            ),
            impact=(
                "Posible ejecución de acciones con permisos "
                "superiores a los autorizados."
            ),
            vendor_information=(
                "El fabricante recomienda evaluar e instalar "
                "la actualización de seguridad aplicable."
            ),
            cves=[
                "CVE-2021-1636",
            ],
        ),
        technical=TechnicalContext(
            os_id=9,
            operating_system=(
                "Sistema operativo de servidor "
                "de demostración"
            ),
            port_id=1067,
            port="1433",
            protocol="TCP",
            detection_type="Confirmed",
            risk_id=4,
            risk_code="4",
            risk_description="Alto",
            scan_result=(
                "El servicio presenta una versión "
                "potencialmente vulnerable."
            ),
        ),
        detection=DetectionHistory(
            first_detected_at=None,
            last_detected_at=None,
            reoffending=True,
            times_detected=12,
        ),
                quality=DataQuality(
            required_references_ok=True,
            has_internal_group=has_internal_group,
            has_qid_detail=True,
            has_vendor_information=True,
            has_cve_detail=True,
        ),
        current_management_ds=None,
        current_group_ds=None,
        current_observation_ds=None,
        inserted_at=None,
    
    )


def build_demo_proposal() -> MitigationProposal:
    """
    Construye una propuesta sintética válida producida
    conceptualmente por el agente planificador.
    """

    return MitigationProposal(
        vulnerability_id=DEMO_VULNERABILITY_ID,
        management_code=(
            ManagementCode.SOLUTION_REQUIRES_EVALUATION
        ),
        classification_reason=(
            "Existe una recomendación del fabricante, pero "
            "la actualización debe validarse antes de ser "
            "implementada en el ambiente de producción."
        ),
        observation_ds=(
            "Validar la actualización en un ambiente controlado, "
            "confirmar compatibilidad, generar respaldo, programar "
            "ventana de mantenimiento y verificar la remediación "
            "mediante un nuevo escaneo."
        ),
        full_plan=FullMitigationPlan(
            summary=(
                "Evaluar e implementar la actualización "
                "de seguridad aplicable."
            ),
            recommended_actions=[
                "Confirmar la versión instalada.",
                (
                    "Validar la actualización en un "
                    "ambiente controlado."
                ),
                (
                    "Aplicar la actualización durante "
                    "la ventana aprobada."
                ),
            ],
            prerequisites=[
                "Contar con un respaldo actualizado.",
                (
                    "Obtener aprobación para la ventana "
                    "de mantenimiento."
                ),
                (
                    "Confirmar la compatibilidad con las "
                    "aplicaciones dependientes."
                ),
            ],
            operational_impact=(
                "La actualización puede requerir "
                "indisponibilidad temporal del servicio."
            ),
            maintenance_window_required=True,
            validation_steps=[
                "Confirmar la versión instalada.",
                "Validar el inicio correcto del servicio.",
                (
                    "Ejecutar un nuevo escaneo y comprobar "
                    "que el QID ya no sea detectado."
                ),
            ],
            rollback_steps=[
                (
                    "Restaurar el respaldo previo si la "
                    "actualización afecta el servicio."
                ),
                (
                    "Reinstalar la versión anterior "
                    "previamente validada."
                ),
            ],
            rollback_not_applicable_reason=None,
            assumptions=[
                (
                    "El activo corresponde al producto "
                    "reportado por el escáner."
                ),
            ],
            missing_information=[
                (
                    "Fecha disponible para la ventana "
                    "de mantenimiento."
                ),
            ],
            evidence_used=[
                "QID 91721",
                "CVE-2021-1636",
                "Ambiente de producción",
                "Caso reincidente",
                "Recomendación técnica del fabricante",
            ],
        ),
        confidence=0.86,
    )


def build_demo_approved_audit() -> AuditResult:
    """
    Construye una auditoría sintética aprobada.
    """

    return AuditResult(
        vulnerability_id=DEMO_VULNERABILITY_ID,
        verdict=AuditVerdict.APPROVED,
        summary=(
            "La propuesta corresponde a la evidencia disponible "
            "y contempla acciones, validación, impacto operativo "
            "y un mecanismo de reversión."
        ),
        findings=[],
        evidence_sufficient=True,
        missing_information=[],
        feedback_for_planner=None,
        confidence=0.91,
    )


def build_demo_revision_audit() -> AuditResult:
    """
    Construye una auditoría sintética que solicita una corrección.
    """

    return AuditResult(
        vulnerability_id=DEMO_VULNERABILITY_ID,
        verdict=AuditVerdict.REVISE,
        summary=(
            "La primera versión del plan requiere una validación "
            "posterior más específica."
        ),
        findings=[
            AuditFinding(
                code="VALIDATION_NOT_SPECIFIC",
                message=(
                    "El plan debe comprobar mediante un nuevo "
                    "escaneo que el QID dejó de ser detectado."
                ),
                field="full_plan.validation_steps",
                blocking=True,
            ),
        ],
        evidence_sufficient=True,
        missing_information=[],
        feedback_for_planner=(
            "Agregar un nuevo escaneo y confirmar explícitamente "
            "que el QID 91721 ya no sea detectado."
        ),
        confidence=0.88,
    )