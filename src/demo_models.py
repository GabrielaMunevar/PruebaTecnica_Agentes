from __future__ import annotations

from typing import Any


class SequenceDemoModel:
    """
    Modelo determinista para la demostración local.

    Devuelve respuestas estructuradas previamente configuradas
    sin invocar proveedores externos ni consumir credenciales.
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
        """
        Devuelve la siguiente respuesta configurada.

        También registra las entradas recibidas para facilitar
        la trazabilidad de la demostración.
        """

        self.inputs.append(input)

        if self.call_count >= len(self._responses):
            raise RuntimeError(
                "El modelo de demostración recibió más "
                "llamadas de las configuradas."
            )

        response = self._responses[
            self.call_count
        ]

        self.call_count += 1

        if isinstance(response, BaseException):
            raise response

        return response