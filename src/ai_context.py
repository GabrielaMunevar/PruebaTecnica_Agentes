from __future__ import annotations

from typing import Any

from src.models import VulnerabilityCase


def build_ai_case_context(
    case: VulnerabilityCase,
) -> dict[str, Any]:
    """
    Construye el contexto mínimo que puede enviarse
    a un modelo externo.

    Se utiliza una lista explícita de campos permitidos.
    Los identificadores del host y otros datos operativos
    internos no se incluyen.
    """

    return {
        "vulnerability_id": case.vulnerability_id,
        "asset": {
            "product": case.asset.product,
            "environment": case.asset.environment,
            "condition": case.asset.condition,
        },
        "vulnerability": {
            "qid": case.vulnerability.qid,
            "title": case.vulnerability.title,
            "threat": case.vulnerability.threat,
            "impact": case.vulnerability.impact,
            "vendor_information": (
                case.vulnerability.vendor_information
            ),
            "cves": case.vulnerability.cves,
        },
        "technical": {
            "operating_system": (
                case.technical.operating_system
            ),
            "port": case.technical.port,
            "protocol": case.technical.protocol,
            "detection_type": (
                case.technical.detection_type
            ),
            "risk_code": case.technical.risk_code,
            "risk_description": (
                case.technical.risk_description
            ),
        },
        "detection": {
            "reoffending": (
                case.detection.reoffending
            ),
            "times_detected": (
                case.detection.times_detected
            ),
        },
    }