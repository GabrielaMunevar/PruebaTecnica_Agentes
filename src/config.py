from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from src.exceptions import ConfigurationError


def _read_float(
    variable_name: str,
    default: float,
) -> float:
    raw_value = os.getenv(variable_name)

    if raw_value is None or not raw_value.strip():
        return default

    try:
        return float(raw_value)

    except ValueError as exc:
        raise ConfigurationError(
            f"{variable_name} debe contener un número válido."
        ) from exc


def _read_int(
    variable_name: str,
    default: int,
) -> int:
    raw_value = os.getenv(variable_name)

    if raw_value is None or not raw_value.strip():
        return default

    try:
        return int(raw_value)

    except ValueError as exc:
        raise ConfigurationError(
            f"{variable_name} debe contener un entero válido."
        ) from exc


@dataclass(
    frozen=True,
    slots=True,
)
class LLMSettings:
    """
    Configuración necesaria para inicializar el modelo.

    No almacena credenciales. Las llaves son administradas
    mediante las variables esperadas por cada proveedor.
    """

    model: str
    provider: str | None = None
    temperature: float = 0.0
    timeout_seconds: float = 60.0
    max_retries: int = 2

    @classmethod
    def from_env(
        cls,
    ) -> "LLMSettings":
        load_dotenv()

        model = os.getenv(
            "LLM_MODEL",
            "",
        ).strip()

        if not model:
            raise ConfigurationError(
                "La variable LLM_MODEL es obligatoria."
            )

        provider_value = os.getenv(
            "LLM_PROVIDER",
            "",
        ).strip()

        provider = (
            provider_value
            if provider_value
            else None
        )

        temperature = _read_float(
            "LLM_TEMPERATURE",
            0.0,
        )

        timeout_seconds = _read_float(
            "LLM_TIMEOUT_SECONDS",
            60.0,
        )

        max_retries = _read_int(
            "LLM_MAX_RETRIES",
            2,
        )

        if not 0 <= temperature <= 2:
            raise ConfigurationError(
                "LLM_TEMPERATURE debe estar entre 0 y 2."
            )

        if timeout_seconds <= 0:
            raise ConfigurationError(
                "LLM_TIMEOUT_SECONDS debe ser mayor que cero."
            )

        if max_retries < 0:
            raise ConfigurationError(
                "LLM_MAX_RETRIES no puede ser negativo."
            )

        return cls(
            model=model,
            provider=provider,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )