from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from pydantic import ValidationError

from src.enums import ManagementCode
from src.exceptions import CatalogError
from src.models import ManagementCatalogEntry


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_MANAGEMENT_CATALOG_PATH = (
    PROJECT_ROOT
    / "data"
    / "management_catalog.json"
)


class ManagementCatalog:
    """
    Catálogo validado e inmutable de respuestas tipificadas.

    Permite resolver un código de gestión sin depender de búsquedas
    manuales ni de textos generados por el modelo de lenguaje.
    """

    def __init__(
        self,
        entries: list[ManagementCatalogEntry],
    ) -> None:
        self._validate_catalog(entries)

        ordered_entries = sorted(
            entries,
            key=lambda entry: int(entry.code),
        )

        self._entries = tuple(ordered_entries)

        self._entries_by_code: Mapping[
            ManagementCode,
            ManagementCatalogEntry,
        ] = MappingProxyType(
            {
                entry.code: entry
                for entry in ordered_entries
            }
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
    ) -> "ManagementCatalog":
        """
        Carga y valida el catálogo desde un archivo JSON.
        """

        catalog_path = Path(path)

        try:
            raw_text = catalog_path.read_text(
                encoding="utf-8",
            )

        except FileNotFoundError as exc:
            raise CatalogError(
                "No se encontró el catálogo de respuestas "
                f"en la ruta: {catalog_path}"
            ) from exc

        except UnicodeDecodeError as exc:
            raise CatalogError(
                "El catálogo no está codificado correctamente "
                "en UTF-8."
            ) from exc

        except OSError as exc:
            raise CatalogError(
                "No fue posible leer el catálogo de respuestas "
                f"desde: {catalog_path}"
            ) from exc

        try:
            raw_data = json.loads(raw_text)

        except json.JSONDecodeError as exc:
            raise CatalogError(
                "El archivo management_catalog.json "
                "no contiene un JSON válido."
            ) from exc

        if not isinstance(raw_data, list):
            raise CatalogError(
                "El catálogo debe contener una lista "
                "de respuestas tipificadas."
            )

        try:
            entries = [
                ManagementCatalogEntry.model_validate(item)
                for item in raw_data
            ]

        except ValidationError as exc:
            raise CatalogError(
                "Una o más entradas del catálogo "
                "no cumplen el contrato esperado.\n"
                f"{exc}"
            ) from exc

        return cls(entries)

    @classmethod
    def load_default(
        cls,
    ) -> "ManagementCatalog":
        """
        Carga el catálogo ubicado en data/management_catalog.json.
        """

        return cls.from_file(
            DEFAULT_MANAGEMENT_CATALOG_PATH
        )

    @staticmethod
    def _validate_catalog(
        entries: list[ManagementCatalogEntry],
    ) -> None:
        """
        Comprueba integridad global del catálogo.

        Una entrada individual puede ser válida, pero el catálogo
        completo también debe contener todos los códigos una sola vez.
        """

        if not entries:
            raise CatalogError(
                "El catálogo de respuestas está vacío."
            )

        code_counts = Counter(
            entry.code
            for entry in entries
        )

        duplicate_codes = sorted(
            (
                code
                for code, count in code_counts.items()
                if count > 1
            ),
            key=int,
        )

        if duplicate_codes:
            duplicate_values = ", ".join(
                str(int(code))
                for code in duplicate_codes
            )

            raise CatalogError(
                "El catálogo contiene códigos duplicados: "
                f"{duplicate_values}."
            )

        expected_codes = set(ManagementCode)
        actual_codes = set(code_counts)

        missing_codes = sorted(
            expected_codes - actual_codes,
            key=int,
        )

        if missing_codes:
            missing_values = ", ".join(
                str(int(code))
                for code in missing_codes
            )

            raise CatalogError(
                "El catálogo no contiene todos los códigos. "
                f"Faltan: {missing_values}."
            )

    def get(
        self,
        code: ManagementCode | int,
    ) -> ManagementCatalogEntry:
        """
        Obtiene una respuesta tipificada mediante su código.
        """

        try:
            normalized_code = ManagementCode(code)

        except (TypeError, ValueError) as exc:
            raise CatalogError(
                f"El código de gestión {code!r} no es válido."
            ) from exc

        try:
            return self._entries_by_code[normalized_code]

        except KeyError as exc:
            raise CatalogError(
                "El código de gestión "
                f"{int(normalized_code)} no existe en el catálogo."
            ) from exc

    def allowed_initial_entries(
        self,
    ) -> tuple[ManagementCatalogEntry, ...]:
        """
        Devuelve las respuestas que el agente puede proponer
        durante el análisis inicial.
        """

        return tuple(
            entry
            for entry in self._entries
            if entry.allowed_as_initial_proposal
        )

    def requires_human_review(
        self,
        code: ManagementCode | int,
    ) -> bool:
        """
        Indica si un código requiere revisión humana obligatoria.
        """

        return self.get(code).human_review_required

    @property
    def entries(
        self,
    ) -> tuple[ManagementCatalogEntry, ...]:
        """
        Devuelve todas las entradas ordenadas por código.
        """

        return self._entries

    def __len__(
        self,
    ) -> int:
        return len(self._entries)


def load_management_catalog(
    path: str | Path | None = None,
) -> ManagementCatalog:
    """
    Función de conveniencia para cargar el catálogo.

    Si no se especifica una ruta, utiliza el archivo predeterminado
    ubicado en data/management_catalog.json.
    """

    if path is None:
        return ManagementCatalog.load_default()

    return ManagementCatalog.from_file(path)