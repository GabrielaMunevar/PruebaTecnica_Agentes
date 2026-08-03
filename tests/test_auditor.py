from __future__ import annotations

import pytest

from src.adapters import row_to_vulnerability_case
from src.agents.auditor import MitigationAuditor
from src.catalog import load_management_catalog
from src.enums import (
    AuditVerdict,
    PolicyDecision,
)
from src.exceptions import (
    AgentExecutionError,
    PolicyValidationError,
    StructuredOutputError,
)
from src.models import (
    AuditResult,
    PolicyEvaluation,
    PolicyFinding,
)
from tests.fakes import FakeStructuredModel
from tests.test_adapters import build_valid_sql_row
from tests.test_planner import build_valid_proposal


def build_approved_audit_result() -> AuditResult:
    return AuditResult(
        vulnerability_id="DEMO-SQL-91721",
        verdict=AuditVerdict.APPROVED,
        summary=(
            "La propuesta es coherente con el caso "
            "y contiene controles operativos adecuados."
        ),
        findings=[],
        evidence_sufficient=True,
        missing_information=[],
        feedback_for_planner=None,
        confidence=0.91,
    )


def build_passed_policy_evaluation() -> PolicyEvaluation:
    return PolicyEvaluation(
        decision=PolicyDecision.PASS,
        findings=[],
        requires_human_review=False,
    )


def test_auditor_returns_structured_result() -> None:
    model = FakeStructuredModel(
        response=build_approved_audit_result(),
    )

    auditor = MitigationAuditor(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    result = auditor.review(
        case=case,
        proposal=build_valid_proposal(),
        policy_evaluation=(
            build_passed_policy_evaluation()
        ),
    )

    assert model.called is True
    assert result.verdict is AuditVerdict.APPROVED
    assert result.evidence_sufficient is True

    assert len(model.last_input) == 2
    assert (
        case.vulnerability_id
        in model.last_input[1].content
    )


def test_auditor_rejects_non_pass_policy() -> None:
    model = FakeStructuredModel(
        response=build_approved_audit_result(),
    )

    auditor = MitigationAuditor(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    policy_evaluation = PolicyEvaluation(
        decision=PolicyDecision.REVISE,
        findings=[
            PolicyFinding(
                code="TEST_FINDING",
                message="La propuesta requiere corrección.",
            )
        ],
        requires_human_review=False,
    )

    with pytest.raises(PolicyValidationError):
        auditor.review(
            case=case,
            proposal=build_valid_proposal(),
            policy_evaluation=policy_evaluation,
        )

    assert model.called is False


def test_auditor_rejects_invalid_output() -> None:
    model = FakeStructuredModel(
        response={
            "verdict": "APPROVED",
        },
    )

    auditor = MitigationAuditor(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(StructuredOutputError):
        auditor.review(
            case=case,
            proposal=build_valid_proposal(),
            policy_evaluation=(
                build_passed_policy_evaluation()
            ),
        )


def test_auditor_wraps_provider_errors() -> None:
    model = FakeStructuredModel(
        error=TimeoutError(
            "Provider timeout"
        ),
    )

    auditor = MitigationAuditor(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(AgentExecutionError) as exc_info:
        auditor.review(
            case=case,
            proposal=build_valid_proposal(),
            policy_evaluation=(
                build_passed_policy_evaluation()
            ),
        )

    assert isinstance(
        exc_info.value.__cause__,
        TimeoutError,
    )


def test_auditor_rejects_mismatched_case_id() -> None:
    result = build_approved_audit_result()
    result.vulnerability_id = "OTHER-CASE"

    model = FakeStructuredModel(
        response=result,
    )

    auditor = MitigationAuditor(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(
        StructuredOutputError,
        match="identificador",
    ):
        auditor.review(
            case=case,
            proposal=build_valid_proposal(),
            policy_evaluation=(
                build_passed_policy_evaluation()
            ),
        )