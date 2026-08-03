from __future__ import annotations

from typing import Any

from langchain.chat_models import init_chat_model
from pydantic import BaseModel

from src.config import LLMSettings
from src.exceptions import ConfigurationError
from src.models import (
    AuditResult,
    MitigationProposal,
)


def _build_structured_model(
    settings: LLMSettings,
    output_schema: type[BaseModel],
) -> Any:
    """
    Inicializa un modelo y configura su salida estructurada.

    Esta función centraliza la configuración común de los
    agentes para evitar duplicación.
    """

    model_arguments: dict[str, Any] = {
        "temperature": settings.temperature,
        "timeout": settings.timeout_seconds,
        "max_retries": settings.max_retries,
    }

    if settings.provider is not None:
        model_arguments["model_provider"] = (
            settings.provider
        )

    try:
        chat_model = init_chat_model(
            settings.model,
            **model_arguments,
        )

        return chat_model.with_structured_output(
            output_schema
        )

    except Exception as exc:
        raise ConfigurationError(
            "No fue posible inicializar el modelo "
            f"{settings.model!r} con salida estructurada."
        ) from exc


def build_mitigation_planner_model(
    settings: LLMSettings,
) -> Any:
    """Construye el modelo del agente planificador."""

    return _build_structured_model(
        settings,
        MitigationProposal,
    )


def build_mitigation_auditor_model(
    settings: LLMSettings,
) -> Any:
    """Construye el modelo del agente auditor."""

    return _build_structured_model(
        settings,
        AuditResult,
    )