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

class SequenceStructuredModel:
    """
    Modelo simulado que entrega una secuencia de respuestas.

    Permite probar ciclos de corrección:
    primera llamada -> propuesta incorrecta
    segunda llamada -> propuesta corregida
    """

    def __init__(
        self,
        responses: list[Any],
    ) -> None:
        self._responses = list(responses)
        self.call_count = 0
        self.inputs: list[Any] = []

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        self.inputs.append(input)

        if self.call_count >= len(self._responses):
            raise AssertionError(
                "El modelo simulado recibió más llamadas "
                "de las configuradas."
            )

        response = self._responses[
            self.call_count
        ]

        self.call_count += 1

        if isinstance(response, BaseException):
            raise response

        return response