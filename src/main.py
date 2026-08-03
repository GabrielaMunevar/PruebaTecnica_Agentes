from __future__ import annotations

import argparse
import json
import logging
from typing import Literal

from src.agents.auditor import MitigationAuditor
from src.agents.planner import MitigationPlanner
from src.catalog import load_management_catalog
from src.demo_data import (
    build_demo_approved_audit,
    build_demo_case,
    build_demo_proposal,
    build_demo_revision_audit,
)
from src.demo_models import SequenceDemoModel
from src.graph import build_vulnerability_workflow
from src.workflow_service import (
    VulnerabilityWorkflowService,
)


DemoScenario = Literal[
    "approved",
    "revision",
    "data-quality",
]


def configure_logging() -> None:
    """
    Configura un logging básico para la ejecución local.
    """

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | %(levelname)s | "
            "%(name)s | %(message)s"
        ),
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Demostración local del flujo multiagente "
            "de gestión de vulnerabilidades."
        )
    )

    parser.add_argument(
        "--scenario",
        choices=[
            "approved",
            "revision",
            "data-quality",
        ],
        default="approved",
        help="Escenario sintético que se ejecutará.",
    )

    return parser.parse_args()


def build_demo_application(
    scenario: DemoScenario,
) -> tuple[
    VulnerabilityWorkflowService,
    object,
]:
    """
    Construye la aplicación local con modelos deterministas.
    """

    catalog = load_management_catalog()

    if scenario == "revision":
        planner_responses = [
            build_demo_proposal(),
            build_demo_proposal(),
        ]

        auditor_responses = [
            build_demo_revision_audit(),
            build_demo_approved_audit(),
        ]

        case = build_demo_case()

    elif scenario == "data-quality":
        planner_responses = []
        auditor_responses = []

        case = build_demo_case(
            has_internal_group=False,
        )

    else:
        planner_responses = [
            build_demo_proposal(),
        ]

        auditor_responses = [
            build_demo_approved_audit(),
        ]

        case = build_demo_case()

    planner = MitigationPlanner(
        model=SequenceDemoModel(
            planner_responses
        ),
        catalog=catalog,
    )

    auditor = MitigationAuditor(
        model=SequenceDemoModel(
            auditor_responses
        ),
        catalog=catalog,
    )

    workflow = build_vulnerability_workflow(
        planner=planner,
        auditor=auditor,
        catalog=catalog,
    )

    service = VulnerabilityWorkflowService(
        workflow=workflow,
        catalog=catalog,
    )

    return service, case


def print_result(
    result,
) -> None:
    """
    Presenta un resumen y el JSON completo del resultado.
    """

    print()
    print("=" * 72)
    print("RESULTADO DEL FLUJO MULTIAGENTE")
    print("=" * 72)

    print(
        f"Vulnerabilidad: {result.vulnerability_id}"
    )

    print(
        f"Estado final: {result.final_status.value}"
    )

    print(
        "Intentos: "
        f"{result.attempt_count}/{result.max_attempts}"
    )

    print(
        "Revisión humana requerida: "
        f"{'Sí' if result.requires_human_review else 'No'}"
    )

    if result.group_ds:
        print(
            f"Grupo interno: {result.group_ds}"
        )

    if result.management_ds:
        print(
            f"Respuesta tipificada: {result.management_ds}"
        )

    if result.report_classification:
        print(
            "Clasificación del informe: "
            f"{result.report_classification.value}"
        )

    if result.audit_result:
        print(
            "Veredicto del auditor: "
            f"{result.audit_result.verdict.value}"
        )

    if result.error_message:
        print(
            f"Error controlado: {result.error_message}"
        )

    print()
    print("JSON COMPLETO")
    print("-" * 72)

    print(
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
        )
    )


def main() -> None:
    configure_logging()

    arguments = parse_arguments()

    service, case = build_demo_application(
        arguments.scenario
    )

    result = service.analyze(case)

    print_result(result)


if __name__ == "__main__":
    main()