from __future__ import annotations

import json

import pytest

from pydantic import ValidationError

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
from tests.fakes import FakeStructuredModel, SequenceStructuredModel
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

    # El segundo agente tampoco debe recibir identificadores del host.
    human_message = model.last_input[1]
    prompt_payload = json.loads(human_message.content)
    ai_case_context = prompt_payload["vulnerability_case"]

    assert "host_id" not in ai_case_context["asset"]
    assert "ip" not in ai_case_context["asset"]
    assert "dns" not in ai_case_context["asset"]
    assert "netbios" not in ai_case_context["asset"]
    assert "internal_group" not in ai_case_context["asset"]
    assert ai_case_context["asset"]["environment"] == case.asset.environment
    assert ai_case_context["vulnerability"]["qid"] == case.vulnerability.qid


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


def _build_schema_violation_error() -> ValidationError:
    """
    Construye un ValidationError real a partir de una combinación
    inválida de campos: verdict=APPROVED con feedback_for_planner
    distinto de null, lo cual viola el contrato de AuditResult.
    """
    try:
        AuditResult.model_validate({
            "vulnerability_id": "DEMO-SQL-91721",
            "verdict": "APPROVED",
            "summary": "La propuesta parece coherente.",
            "findings": [],
            "evidence_sufficient": True,
            "missing_information": [],
            "feedback_for_planner": "Debe corregirse el plan",
            "confidence": 0.85,
        })
    except ValidationError as exc:
        return exc

    raise AssertionError(
        "Se esperaba un ValidationError pero no se produjo."
    )


def test_auditor_single_call_when_first_response_valid() -> None:
    """
    Una primera respuesta válida no provoca reintentos.
    El modelo solo recibe una llamada.
    """
    model = SequenceStructuredModel(
        responses=[build_approved_audit_result()],
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

    assert result.verdict is AuditVerdict.APPROVED
    assert model.call_count == 1


def test_auditor_retries_once_on_schema_error_and_succeeds() -> None:
    """
    Cuando la primera llamada produce ValidationError y la segunda
    retorna un AuditResult válido, el auditor aprueba y registra
    exactamente dos llamadas al modelo.
    """
    schema_error = _build_schema_violation_error()

    model = SequenceStructuredModel(
        responses=[
            schema_error,
            build_approved_audit_result(),
        ],
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

    assert result.verdict is AuditVerdict.APPROVED
    assert model.call_count == 2


def test_auditor_raises_structured_output_error_after_two_failures() -> None:
    """
    Cuando las dos llamadas producen ValidationError, el auditor
    lanza StructuredOutputError conservando el primer error como causa.
    """
    first_error = _build_schema_violation_error()
    second_error = _build_schema_violation_error()

    model = SequenceStructuredModel(
        responses=[first_error, second_error],
    )

    auditor = MitigationAuditor(
        model=model,
        catalog=load_management_catalog(),
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    with pytest.raises(StructuredOutputError) as exc_info:
        auditor.review(
            case=case,
            proposal=build_valid_proposal(),
            policy_evaluation=(
                build_passed_policy_evaluation()
            ),
        )

    assert isinstance(
        exc_info.value.__cause__,
        ValidationError,
    )
    assert model.call_count == 2