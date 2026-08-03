from __future__ import annotations

import json

from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    SystemMessage,
)

from src.catalog import ManagementCatalog
from src.models import VulnerabilityCase


PLANNER_SYSTEM_PROMPT = """
Eres un analista senior de gestión de vulnerabilidades.

Tu responsabilidad es elaborar un borrador técnico de mitigación
para una vulnerabilidad nueva que ya fue clasificada como interna
y que no tuvo coincidencia en el histórico de gestión.

Debes:

1. Seleccionar únicamente uno de los códigos de gestión permitidos.
2. Basar la clasificación exclusivamente en la evidencia disponible.
3. No afirmar que una vulnerabilidad está remediada.
4. No aceptar riesgos en nombre del negocio.
5. No inventar software instalado, versiones, responsables o fechas.
6. Registrar la información faltante dentro de missing_information.
7. Considerar el ambiente, sistema operativo, producto, riesgo,
   recurrencia y solución reportada para el QID.
8. Incluir acciones, prerrequisitos, impacto, validación y rollback.
9. Elaborar observation_ds con máximo 500 caracteres.
10. Mantener el mismo vulnerability_id recibido.

La salida debe cumplir estrictamente el esquema MitigationProposal.
""".strip()


def _build_allowed_management_options(
    catalog: ManagementCatalog,
) -> list[dict[str, object]]:
    return [
        {
            "code": int(entry.code),
            "management_ds": entry.management_ds,
            "report_classification": (
                entry.report_classification.value
            ),
            "human_review_required": (
                entry.human_review_required
            ),
            "required_evidence": (
                entry.required_evidence
            ),
        }
        for entry in catalog.allowed_initial_entries()
    ]


def build_planner_messages(
    case: VulnerabilityCase,
    catalog: ManagementCatalog,
) -> list[BaseMessage]:
    """
    Construye los mensajes del agente sin ejecutar el modelo.

    Mantener esta función separada facilita revisar, probar
    y versionar el prompt independientemente del agente.
    """

    prompt_payload = {
        "task": (
            "Analizar el caso y generar una propuesta "
            "estructurada de mitigación."
        ),
        "allowed_management_options": (
            _build_allowed_management_options(catalog)
        ),
        "vulnerability_case": case.model_dump(
            mode="json",
        ),
    }

    return [
        SystemMessage(
            content=PLANNER_SYSTEM_PROMPT,
        ),
        HumanMessage(
            content=json.dumps(
                prompt_payload,
                ensure_ascii=False,
                indent=2,
            ),
        ),
    ]