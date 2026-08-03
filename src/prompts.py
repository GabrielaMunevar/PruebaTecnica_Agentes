from __future__ import annotations

import json

from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    SystemMessage,
)

from src.catalog import ManagementCatalog
from src.models import (
    MitigationProposal,
    PolicyEvaluation,
    VulnerabilityCase,
)


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
11. Cuando recibas una propuesta anterior y retroalimentación,
    debes corregir específicamente los hallazgos indicados sin
    perder la información válida del plan anterior.

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
    previous_proposal: MitigationProposal | None = None,
    revision_feedback: str | None = None,
) -> list[BaseMessage]:
    """
    Construye los mensajes del agente planificador.

    Cuando se recibe retroalimentación, incorpora la propuesta
    anterior para que el agente pueda corregirla.
    """

    prompt_payload: dict[str, object] = {
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

    if (
        previous_proposal is not None
        or revision_feedback is not None
    ):
        prompt_payload["revision_context"] = {
            "instruction": (
                "Corrige la propuesta anterior atendiendo "
                "todos los hallazgos indicados."
            ),
            "previous_proposal": (
                previous_proposal.model_dump(mode="json")
                if previous_proposal is not None
                else None
            ),
            "feedback": revision_feedback,
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

AUDITOR_SYSTEM_PROMPT = """
Eres un auditor senior independiente especializado en gestión
de vulnerabilidades y control de calidad técnico.

Debes evaluar la propuesta elaborada por otro agente.

No debes reescribir el plan completo. Tu responsabilidad es
aprobarlo, devolverlo para corrección o solicitar revisión humana.

Evalúa:

1. Si la respuesta tipificada corresponde a la evidencia.
2. Si las acciones están relacionadas con el QID, CVE,
   plataforma y producto analizados.
3. Si el plan considera correctamente el ambiente.
4. Si el impacto operativo es coherente.
5. Si los pasos de validación permiten verificar la remediación.
6. Si el rollback es viable o está correctamente justificado.
7. Si existen afirmaciones no sustentadas.
8. Si falta información que solo una persona puede confirmar.
9. Si el plan evita declarar una remediación no ejecutada.
10. Si el identificador corresponde al caso recibido.

Usa los veredictos:

APPROVED:
El plan es coherente y la evidencia es suficiente.

REVISE:
El planificador puede corregir los problemas utilizando
la información disponible.

HUMAN_REVIEW:
La decisión requiere inventario adicional, confirmación del
especialista, aceptación de riesgo, autorización del negocio
u otra información que no está disponible.

La salida debe cumplir estrictamente el esquema AuditResult.
""".strip()

def build_auditor_messages(
    case: VulnerabilityCase,
    proposal: MitigationProposal,
    policy_evaluation: PolicyEvaluation,
    catalog: ManagementCatalog,
) -> list[BaseMessage]:
    """
    Construye el contexto del auditor sin ejecutar el modelo.
    """

    catalog_entry = catalog.get(
        proposal.management_code
    )

    prompt_payload = {
        "task": (
            "Auditar técnica y semánticamente "
            "la propuesta de mitigación."
        ),
        "selected_management_option": (
            catalog_entry.model_dump(
                mode="json",
            )
        ),
        "vulnerability_case": case.model_dump(
            mode="json",
        ),
        "mitigation_proposal": proposal.model_dump(
            mode="json",
        ),
        "policy_evaluation": (
            policy_evaluation.model_dump(
                mode="json",
            )
        ),
    }

    return [
        SystemMessage(
            content=AUDITOR_SYSTEM_PROMPT,
        ),
        HumanMessage(
            content=json.dumps(
                prompt_payload,
                ensure_ascii=False,
                indent=2,
            ),
        ),
    ]