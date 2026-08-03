from __future__ import annotations

import json

from src.ai_context import build_ai_case_context
from src.demo_data import build_demo_case


def test_ai_context_excludes_host_identifiers() -> None:
    case = build_demo_case()

    context = build_ai_case_context(case)

    serialized_context = json.dumps(
        context,
        ensure_ascii=False,
    )

    assert case.asset.ip not in serialized_context
    assert case.asset.dns not in serialized_context
    assert case.asset.netbios not in serialized_context

    assert "host_id" not in serialized_context
    assert "internal_group" not in serialized_context


def test_ai_context_keeps_relevant_technical_data() -> None:
    case = build_demo_case()

    context = build_ai_case_context(case)

    serialized_context = json.dumps(
        context,
        ensure_ascii=False,
    )

    assert case.vulnerability.qid in serialized_context
    assert case.vulnerability.title in serialized_context
    assert (
        case.technical.operating_system
        in serialized_context
    )
    assert case.asset.environment in serialized_context
    assert case.technical.risk_description in serialized_context