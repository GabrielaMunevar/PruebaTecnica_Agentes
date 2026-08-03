from __future__ import annotations

from typing import Any, Protocol


class StructuredModel(Protocol):
    """
    Contrato mínimo de un modelo que recibe una entrada
    y devuelve una salida estructurada.
    """

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        ...


class InvokableWorkflow(Protocol):
    """
    Contrato mínimo requerido para ejecutar un workflow.
    """

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        ...