from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


NULL_LIKE_VALUES = {
    "",
    "ND",
    "NA",
    "N/A",
    "NULL",
    "NONE",
}


def normalize_optional_text(value: Any) -> str | None:
    """
    Convierte los valores equivalentes a ausencia de información en None.

    Ejemplos:
    - "ND" -> None
    - " NA " -> None
    - "" -> None
    - "Producción" -> "Producción"
    """
    if value is None:
        return None

    text = str(value).strip()

    if text.upper() in NULL_LIKE_VALUES:
        return None

    return text


class StrictModel(BaseModel):
    """
    Configuración común para todos los modelos del proyecto.

    - No permite campos inesperados.
    - Elimina espacios al inicio y al final.
    - Valida también cuando un atributo se modifica.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class AssetContext(StrictModel):
    """Información del host donde fue detectada la vulnerabilidad."""

    host_id: int = Field(gt=0)

    ip: str = Field(
        min_length=1,
        max_length=50,
    )

    dns: str | None = None
    netbios: str | None = None
    product: str | None = None
    environment: str | None = None
    condition: str | None = None

    # Debe provenir exclusivamente de TBL_HOST.GROUP_DS.
    internal_group: str | None = None

    @field_validator(
        "dns",
        "netbios",
        "product",
        "environment",
        "condition",
        "internal_group",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)


class VulnerabilityDetails(StrictModel):
    """Información funcional y técnica asociada al QID y sus CVE."""

    qid_id: int = Field(gt=0)

    qid: str = Field(
        min_length=1,
        max_length=100,
    )

    title: str = Field(min_length=1)

    threat: str | None = None
    impact: str | None = None

    # Corresponde a TBL_QID.SOLUTION_DS.
    # No se considera automáticamente un plan de mitigación.
    vendor_information: str | None = None

    # Puede contener uno, varios o ningún CVE.
    cves: list[str] = Field(default_factory=list)

    vendor_reference: str | None = None
    bugtraq_id: str | None = None
    exploitability: str | None = None
    associated_malware: str | None = None
    pci_vulnerability: str | None = None

    @field_validator(
        "threat",
        "impact",
        "vendor_information",
        "vendor_reference",
        "bugtraq_id",
        "exploitability",
        "associated_malware",
        "pci_vulnerability",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @field_validator("cves", mode="before")
    @classmethod
    def parse_cves(
        cls,
        value: Any,
    ) -> list[str]:
        """
        Convierte el campo CVE_CD de la vista en una lista.

        Ejemplo:
        "CVE-2023-36728,CVE-2023-36730"

        Resultado:
        [
            "CVE-2023-36728",
            "CVE-2023-36730"
        ]
        """
        if value is None:
            return []

        if isinstance(value, str):
            raw_items = value.split(",")

        elif isinstance(value, (list, tuple, set)):
            raw_items = list(value)

        else:
            raise TypeError(
                "cves debe ser un texto separado por comas "
                "o una colección de textos."
            )

        normalized: list[str] = []
        seen: set[str] = set()

        for item in raw_items:
            cve = normalize_optional_text(item)

            if cve is None:
                continue

            cve = cve.upper()

            if cve not in seen:
                seen.add(cve)
                normalized.append(cve)

        return normalized


class TechnicalContext(StrictModel):
    """Contexto técnico de la detección."""

    os_id: int = Field(gt=0)
    operating_system: str = Field(min_length=1)

    port_id: int = Field(gt=0)
    port: str | None = None
    protocol: str | None = None

    detection_type: str | None = None

    risk_id: int = Field(gt=0)

    risk_code: str = Field(
        min_length=1,
        max_length=2,
    )

    # En los datos actuales CVSS_DS contiene valores
    # como Crítico, Alto, Medio o Bajo.
    risk_description: str | None = None

    scan_result: str | None = None

    @field_validator(
        "port",
        "protocol",
        "detection_type",
        "risk_description",
        "scan_result",
        mode="before",
    )
    @classmethod
    def normalize_optional_fields(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)


class DetectionHistory(StrictModel):
    """Información histórica de aparición de la vulnerabilidad."""

    first_detected_at: datetime | None = None
    last_detected_at: datetime | None = None

    reoffending: bool

    times_detected: int | None = Field(
        default=None,
        ge=0,
    )


class DataQuality(StrictModel):
    """Indicadores calculados en la vista enriquecida."""

    required_references_ok: bool
    has_internal_group: bool
    has_qid_detail: bool
    has_vendor_information: bool
    has_cve_detail: bool


class VulnerabilityCase(StrictModel):
    """
    Caso completo que será enviado al flujo de LangGraph.

    Representa una fila enriquecida de
    VW_AI_INTERNAL_VULNERABILITIES_ENRICHED.
    """

    vulnerability_id: str = Field(
        min_length=1,
        max_length=100,
    )

    asset: AssetContext
    vulnerability: VulnerabilityDetails
    technical: TechnicalContext
    detection: DetectionHistory
    quality: DataQuality

    # Valores actuales en STG_INTERNAL_VULNERABILITIES.
    # Normalmente llegan como ND y serán convertidos en None.
    current_management_ds: str | None = None
    current_group_ds: str | None = None
    current_observation_ds: str | None = None

    inserted_at: datetime | None = None
    inserted_user: str | None = None

    @field_validator(
        "current_management_ds",
        "current_group_ds",
        "current_observation_ds",
        "inserted_user",
        mode="before",
    )
    @classmethod
    def normalize_current_values(
        cls,
        value: Any,
    ) -> str | None:
        return normalize_optional_text(value)

    @property
    def initial_status(self) -> str:
        """
        Define si el caso puede entrar al sistema multiagente.

        El modelo no intenta completar información faltante:
        enruta los casos incompletos a revisión de calidad.
        """
        if not self.quality.required_references_ok:
            return "DATA_QUALITY_REVIEW"

        if not self.quality.has_internal_group:
            return "DATA_QUALITY_REVIEW"

        if not self.quality.has_qid_detail:
            return "DATA_QUALITY_REVIEW"

        return "READY_FOR_AI"