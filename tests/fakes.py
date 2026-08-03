from __future__ import annotations

from typing import Any


class FakeStructuredModel:
    """
    Modelo simulado para probar los agentes sin consumir
    una API ni requerir credenciales.
    """

    def __init__(
        self,
        *,
        response: Any = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.called = False
        self.last_input: Any = None

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Simula el método invoke de un modelo estructurado.
        """

        self.called = True
        self.last_input = input

        if self.error is not None:
            raise self.error

        return self.response