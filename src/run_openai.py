from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.adapters import row_to_vulnerability_case
from src.agents.auditor import MitigationAuditor
from src.agents.planner import MitigationPlanner
from src.catalog import load_management_catalog
from src.config import LLMSettings
from src.demo_data import build_demo_case
from src.graph import build_vulnerability_workflow
from src.main import configure_logging, print_result
from src.model_factory import (
    build_mitigation_auditor_model,
    build_mitigation_planner_model,
)
from src.models import VulnerabilityCase
from src.workflow_service import (
    VulnerabilityWorkflowService,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Ejecuta el workflow multiagente utilizando "
            "modelos reales de OpenAI."
        )
    )

    parser.add_argument(
        "--input-json",
        type=Path,
        default=None,
        help=(
            "Ruta opcional a una fila JSON proveniente "
            "de la vista SQL enriquecida."
        ),
    )

    parser.add_argument(
        "--max-attempts",
        type=int,
        default=2,
        help=(
            "Máximo de propuestas generadas antes de "
            "enviar el caso a revisión humana."
        ),
    )

    return parser.parse_args()


def load_case_from_json(
    file_path: Path,
) -> VulnerabilityCase:
    """
    Lee una fila plana de la vista SQL y la transforma
    mediante el adaptador existente.
    """

    try:
        raw_text = file_path.read_text(
            encoding="utf-8",
        )

        raw_data: Any = json.loads(raw_text)

    except FileNotFoundError as exc:
        raise RuntimeError(
            f"No se encontró el archivo: {file_path}"
        ) from exc

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "El archivo de entrada no contiene JSON válido."
        ) from exc

    if not isinstance(raw_data, dict):
        raise RuntimeError(
            "El archivo debe contener una única fila "
            "representada como objeto JSON."
        )

    return row_to_vulnerability_case(raw_data)


def build_openai_service() -> VulnerabilityWorkflowService:
    """
    Construye el flujo utilizando modelos reales de OpenAI.
    """

    settings = LLMSettings.from_env()
    catalog = load_management_catalog()

    planner_model = build_mitigation_planner_model(
        settings
    )

    auditor_model = build_mitigation_auditor_model(
        settings
    )

    planner = MitigationPlanner(
        model=planner_model,
        catalog=catalog,
    )

    auditor = MitigationAuditor(
        model=auditor_model,
        catalog=catalog,
    )

    workflow = build_vulnerability_workflow(
        planner=planner,
        auditor=auditor,
        catalog=catalog,
    )

    return VulnerabilityWorkflowService(
        workflow=workflow,
        catalog=catalog,
    )


def main() -> None:
    configure_logging()

    arguments = parse_arguments()

    case = (
        load_case_from_json(arguments.input_json)
        if arguments.input_json is not None
        else build_demo_case()
    )

    service = build_openai_service()

    result = service.analyze(
        case,
        max_attempts=arguments.max_attempts,
    )

    print_result(result)


if __name__ == "__main__":
    main()