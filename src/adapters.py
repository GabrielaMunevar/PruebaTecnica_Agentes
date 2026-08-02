from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from src.exceptions import AdapterError
from src.models import VulnerabilityCase


def _normalize_keys(row: Mapping[str, Any]) -> dict[str, Any]:
    """
    Normaliza los nombres de las columnas a mayúsculas.

    Esto permite que el adaptador funcione aunque el conector SQL
    entregue nombres como IP_CD, ip_cd o Ip_Cd.
    """
    return {
        str(column_name).upper(): value
        for column_name, value in row.items()
    }


def _first_value(
    row: Mapping[str, Any],
    *column_names: str,
    default: Any = None,
) -> Any:
    """
    Devuelve el valor de la primera columna encontrada.

    Es útil cuando una columna pudo cambiar de alias durante
    la evolución de la vista.

    Ejemplo:
    - HAS_VENDOR_INFORMATION_FLG
    - HAS_VENDOR_SOLUTION_FLG
    """
    for column_name in column_names:
        normalized_name = column_name.upper()

        if normalized_name in row:
            return row[normalized_name]

    return default


def _required_value(
    row: Mapping[str, Any],
    *column_names: str,
) -> Any:
    """
    Obtiene un campo obligatorio.

    Genera un error legible si ninguna de las columnas indicadas
    existe o si su valor es NULL.
    """
    value = _first_value(
        row,
        *column_names,
        default=None,
    )

    if value is None:
        expected_columns = ", ".join(column_names)

        raise AdapterError(
            "No se encontró un valor obligatorio en las columnas: "
            f"{expected_columns}."
        )

    return value


def _as_bool(
    value: Any,
    *,
    field_name: str,
) -> bool:
    """
    Convierte valores provenientes de SQL en booleanos.

    Acepta:
    - True / False
    - 1 / 0
    - "true" / "false"
    - "sí" / "no"
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return False

    if isinstance(value, (int, float)):
        return value != 0

    if isinstance(value, str):
        normalized = value.strip().upper()

        if normalized in {
            "1",
            "TRUE",
            "T",
            "YES",
            "Y",
            "SI",
            "SÍ",
        }:
            return True

        if normalized in {
            "0",
            "FALSE",
            "F",
            "NO",
            "N",
            "",
        }:
            return False

    raise AdapterError(
        f"No se pudo convertir el campo {field_name} "
        f"con valor {value!r} a booleano."
    )


def row_to_vulnerability_case(
    row: Mapping[str, Any],
) -> VulnerabilityCase:
    """
    Convierte una fila plana de
    VW_AI_INTERNAL_VULNERABILITIES_ENRICHED
    en un VulnerabilityCase.

    Esta función no contiene lógica de IA.
    Solo adapta, organiza y valida datos.
    """
    normalized_row = _normalize_keys(row)

    payload = {
        "vulnerability_id": _required_value(
            normalized_row,
            "VULNERABILITIES_ID",
        ),

        "asset": {
            "host_id": _required_value(
                normalized_row,
                "HOST_ID",
            ),
            "ip": _required_value(
                normalized_row,
                "IP_CD",
            ),
            "dns": _first_value(
                normalized_row,
                "DNS_DS",
            ),
            "netbios": _first_value(
                normalized_row,
                "NET_BIOS_DS",
            ),
            "product": _first_value(
                normalized_row,
                "PRODUCT_DS",
            ),
            "environment": _first_value(
                normalized_row,
                "ENVIRONMENT_DS",
            ),
            "condition": _first_value(
                normalized_row,
                "CONDITION_DS",
            ),

            # Fuente oficial del grupo interno:
            # TBL_HOST.GROUP_DS.
            "internal_group": _first_value(
                normalized_row,
                "RESOLVED_GROUP_DS",
                "HOST_GROUP_DS",
            ),
        },

        "vulnerability": {
            "qid_id": _required_value(
                normalized_row,
                "QID_ID",
            ),
            "qid": _required_value(
                normalized_row,
                "QID_CD",
            ),
            "title": _required_value(
                normalized_row,
                "TITLE_DS",
            ),
            "threat": _first_value(
                normalized_row,
                "THREAT_DS",
            ),
            "impact": _first_value(
                normalized_row,
                "IMPACT_DS",
            ),
            "vendor_information": _first_value(
                normalized_row,
                "SOLUTION_DS",
            ),

            # Puede llegar como:
            # "CVE-2023-1,CVE-2023-2"
            # El modelo se encarga de convertirlo en lista.
            "cves": _first_value(
                normalized_row,
                "CVE_CD",
                default=[],
            ),
            "vendor_reference": _first_value(
                normalized_row,
                "VENDOR_REFERENCE",
            ),
            "bugtraq_id": _first_value(
                normalized_row,
                "BUGTRAQ_ID",
            ),
            "exploitability": _first_value(
                normalized_row,
                "EXPLOITABILITY",
            ),
            "associated_malware": _first_value(
                normalized_row,
                "ASSOCIATED_MALWARE",
            ),
            "pci_vulnerability": _first_value(
                normalized_row,
                "PCI_VULN",
            ),
        },

        "technical": {
            "os_id": _required_value(
                normalized_row,
                "OS_ID",
            ),
            "operating_system": _required_value(
                normalized_row,
                "OS_DS",
            ),
            "port_id": _required_value(
                normalized_row,
                "PORT_ID",
            ),
            "port": _first_value(
                normalized_row,
                "PORT_CD",
            ),
            "protocol": _first_value(
                normalized_row,
                "PROTOCOL_DS",
            ),
            "detection_type": _first_value(
                normalized_row,
                "DETECTION_TYPE_DS",
                "TYPE_DS",
            ),
            "risk_id": _required_value(
                normalized_row,
                "RISK_ID",
            ),
            "risk_code": _required_value(
                normalized_row,
                "RISK_CD",
            ),
            "risk_description": _first_value(
                normalized_row,
                "CVSS_DS",
            ),
            "scan_result": _first_value(
                normalized_row,
                "RESULT_DS",
            ),
        },

        "detection": {
            "first_detected_at": _first_value(
                normalized_row,
                "FIRST_DT",
            ),
            "last_detected_at": _first_value(
                normalized_row,
                "LAST_DT",
            ),
            "reoffending": _as_bool(
                _required_value(
                    normalized_row,
                    "REOFFENDING_FLG",
                ),
                field_name="REOFFENDING_FLG",
            ),
            "times_detected": _first_value(
                normalized_row,
                "TIMES_DETECTED",
            ),
        },

        "quality": {
            "required_references_ok": _as_bool(
                _required_value(
                    normalized_row,
                    "REQUIRED_REFERENCES_OK_FLG",
                ),
                field_name="REQUIRED_REFERENCES_OK_FLG",
            ),
            "has_internal_group": _as_bool(
                _required_value(
                    normalized_row,
                    "HAS_INTERNAL_GROUP_FLG",
                ),
                field_name="HAS_INTERNAL_GROUP_FLG",
            ),
            "has_qid_detail": _as_bool(
                _required_value(
                    normalized_row,
                    "HAS_QID_DETAIL_FLG",
                ),
                field_name="HAS_QID_DETAIL_FLG",
            ),
            "has_vendor_information": _as_bool(
                _first_value(
                    normalized_row,
                    "HAS_VENDOR_INFORMATION_FLG",
                    "HAS_VENDOR_SOLUTION_FLG",
                    default=False,
                ),
                field_name="HAS_VENDOR_INFORMATION_FLG",
            ),
            "has_cve_detail": _as_bool(
                _first_value(
                    normalized_row,
                    "HAS_CVE_DETAIL_FLG",
                    default=False,
                ),
                field_name="HAS_CVE_DETAIL_FLG",
            ),
        },

        "current_management_ds": _first_value(
            normalized_row,
            "CURRENT_MANAGEMENT_DS",
        ),
        "current_group_ds": _first_value(
            normalized_row,
            "CURRENT_GROUP_DS",
        ),
        "current_observation_ds": _first_value(
            normalized_row,
            "CURRENT_OBSERVATION_DS",
        ),

        "inserted_at": _first_value(
            normalized_row,
            "INSERT_DT",
        ),
        "inserted_user": _first_value(
            normalized_row,
            "INSERT_USER",
        ),
    }

    try:
        return VulnerabilityCase.model_validate(payload)

    except ValidationError as exc:
        vulnerability_id = payload.get(
            "vulnerability_id",
            "UNKNOWN",
        )

        raise AdapterError(
            "La fila de la vulnerabilidad "
            f"{vulnerability_id!r} no cumple el contrato de entrada.\n"
            f"{exc}"
        ) from exc