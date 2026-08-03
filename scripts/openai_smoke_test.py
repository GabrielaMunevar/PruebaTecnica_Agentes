from __future__ import annotations

from dotenv import load_dotenv
from openai import OpenAI


def main() -> None:
    """
    Comprueba autenticación y acceso al modelo sin ejecutar
    todavía el workflow multiagente.
    """

    load_dotenv()

    client = OpenAI()

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=(
            "Responde únicamente con el texto API_OK. "
            "No agregues explicaciones."
        ),
    )

    print(response.output_text)


if __name__ == "__main__":
    main()