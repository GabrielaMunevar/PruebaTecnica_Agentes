import json
from copy import deepcopy

import pytest

from src.catalog import (
    DEFAULT_MANAGEMENT_CATALOG_PATH,
    ManagementCatalog,
    load_management_catalog,
)
from src.enums import (
    ManagementCode,
    ReportClassification,
)
from src.exceptions import CatalogError


def test_load_complete_management_catalog() -> None:
    catalog = load_management_catalog()

    assert len(catalog) == 11

    entry = catalog.get(
        ManagementCode.SOLUTION_REQUIRES_EVALUATION
    )

    assert (
        entry.management_ds
        == "Se debe evaluar la solución de la vulnerabilidad"
    )

    assert (
        entry.report_classification
        is ReportClassification.POSITIVE
    )

    assert entry.allowed_as_initial_proposal is True
    assert entry.human_review_required is False


def test_catalog_returns_only_allowed_initial_entries() -> None:
    catalog = load_management_catalog()

    allowed_codes = {
        entry.code
        for entry in catalog.allowed_initial_entries()
    }

    assert allowed_codes == {
        ManagementCode.FALSE_POSITIVE,
        ManagementCode.MANAGEMENT_NOT_APPLICABLE,
        ManagementCode.SOFTWARE_NOT_INSTALLED,
        ManagementCode.PLATFORM_OR_VERSION_NOT_AFFECTED,
        ManagementCode.NO_SOLUTION_FOR_PLATFORM,
        ManagementCode.RISK_ACCEPTANCE_REQUIRED,
        ManagementCode.SOLUTION_REQUIRES_EVALUATION,
    }


def test_catalog_rejects_duplicate_codes(
    tmp_path,
) -> None:
    raw_catalog = json.loads(
        DEFAULT_MANAGEMENT_CATALOG_PATH.read_text(
            encoding="utf-8",
        )
    )

    duplicated_catalog = deepcopy(raw_catalog)
    duplicated_catalog.append(
        deepcopy(raw_catalog[0])
    )

    catalog_path = (
        tmp_path
        / "duplicated_catalog.json"
    )

    catalog_path.write_text(
        json.dumps(
            duplicated_catalog,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        CatalogError,
        match="códigos duplicados",
    ):
        ManagementCatalog.from_file(catalog_path)


def test_catalog_rejects_missing_file(
    tmp_path,
) -> None:
    missing_path = (
        tmp_path
        / "catalog_does_not_exist.json"
    )

    with pytest.raises(
        CatalogError,
        match="No se encontró",
    ):
        ManagementCatalog.from_file(missing_path)


def test_catalog_rejects_invalid_json(
    tmp_path,
) -> None:
    invalid_path = (
        tmp_path
        / "invalid_catalog.json"
    )

    invalid_path.write_text(
        "{ esto no es un json válido }",
        encoding="utf-8",
    )

    with pytest.raises(
        CatalogError,
        match="no contiene un JSON válido",
    ):
        ManagementCatalog.from_file(invalid_path)