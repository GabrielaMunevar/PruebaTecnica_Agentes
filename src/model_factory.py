from __future__ import annotations

from typing import Any

from langchain.chat_models import init_chat_model

from src.config import LLMSettings
from src.exceptions import ConfigurationError
from src.models import MitigationProposal


def build_mitigation_planner_model(
    settings: LLMSettings,
) -> Any:
    """
    Inicializa el modelo del agente planificador y fuerza
    una salida estructurada de tipo MitigationProposal.

    El tipo Any queda limitado a esta frontera porque LangChain
    puede devolver diferentes implementaciones Runnable según
    el proveedor seleccionado.
    """

    model_arguments: dict[str, Any] = {
        "temperature": settings.temperature,
        "timeout": settings.timeout_seconds,
        "max_retries": settings.max_retries,
    }

    if settings.provider is not None:
        model_arguments["model_provider"] = settings.provider

    try:
        chat_model = init_chat_model(
            settings.model,
            **model_arguments,
        )

    except Exception as exc:
        raise ConfigurationError(
            "No fue posible inicializar el modelo "
            f"{settings.model!r}."
        ) from exc

    return chat_model.with_structured_output(
        MitigationProposal
    )