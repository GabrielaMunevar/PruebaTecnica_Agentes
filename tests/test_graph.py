from __future__ import annotations

from src.adapters import row_to_vulnerability_case
from src.agents.auditor import MitigationAuditor
from src.agents.planner import MitigationPlanner
from src.catalog import load_management_catalog
from src.enums import (
    AuditVerdict,
    ManagementCode,
    WorkflowStatus,
)
from src.graph import build_vulnerability_workflow
from src.models import (
    AuditFinding,
    AuditResult,
)
from tests.fakes import SequenceStructuredModel
from tests.test_adapters import build_valid_sql_row
from tests.test_auditor import (
    build_approved_audit_result,
)
from tests.test_planner import build_valid_proposal


def build_revise_audit_result() -> AuditResult:
    return AuditResult(
        vulnerability_id="DEMO-SQL-91721",
        verdict=AuditVerdict.REVISE,
        summary=(
            "La propuesta no define una validación "
            "suficientemente específica."
        ),
        findings=[
            AuditFinding(
                code="VALIDATION_NOT_SPECIFIC",
                message=(
                    "El plan debe comprobar mediante un "
                    "nuevo escaneo que el QID desapareció."
                ),
                field="full_plan.validation_steps",
                blocking=True,
            )
        ],
        evidence_sufficient=True,
        missing_information=[],
        feedback_for_planner=(
            "Agregar un nuevo escaneo y verificar "
            "que el QID 91721 ya no sea detectado."
        ),
        confidence=0.89,
    )


def build_workflow(
    *,
    planner_responses: list[object],
    auditor_responses: list[object],
    max_attempts: int = 3,
):
    catalog = load_management_catalog()

    planner_model = SequenceStructuredModel(
        planner_responses
    )

    auditor_model = SequenceStructuredModel(
        auditor_responses
    )

    planner = MitigationPlanner(
        model=planner_model,
        catalog=catalog,
    )

    auditor = MitigationAuditor(
        model=auditor_model,
        catalog=catalog,
    )

    workflow = build_vulnerability_workflow(
        planner=planner,
        auditor=auditor,
        catalog=catalog,
        default_max_attempts=max_attempts,
    )

    return (
        workflow,
        planner_model,
        auditor_model,
    )


def test_workflow_approves_valid_proposal() -> None:
    workflow, planner_model, auditor_model = (
        build_workflow(
            planner_responses=[
                build_valid_proposal(),
            ],
            auditor_responses=[
                build_approved_audit_result(),
            ],
        )
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    result = workflow.invoke(
        {
            "case": case,
        }
    )

    assert (
        result["final_status"]
        is WorkflowStatus.APPROVED_DRAFT
    )

    assert result["attempt_count"] == 1
    assert planner_model.call_count == 1
    assert auditor_model.call_count == 1


def test_policy_revision_returns_to_planner() -> None:
    invalid_proposal = build_valid_proposal()

    invalid_proposal.management_code = (
        ManagementCode.RESOURCE_DECOMMISSIONING
    )

    corrected_proposal = build_valid_proposal()

    workflow, planner_model, auditor_model = (
        build_workflow(
            planner_responses=[
                invalid_proposal,
                corrected_proposal,
            ],
            auditor_responses=[
                build_approved_audit_result(),
            ],
        )
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    result = workflow.invoke(
        {
            "case": case,
        }
    )

    assert (
        result["final_status"]
        is WorkflowStatus.APPROVED_DRAFT
    )

    assert result["attempt_count"] == 2
    assert planner_model.call_count == 2
    assert auditor_model.call_count == 1

    second_prompt = (
        planner_model.inputs[1][1].content
    )

    assert "guardrails" in second_prompt
    assert (
        "MANAGEMENT_CODE_NOT_ALLOWED_INITIAL"
        in second_prompt
    )


def test_auditor_revision_returns_to_planner() -> None:
    workflow, planner_model, auditor_model = (
        build_workflow(
            planner_responses=[
                build_valid_proposal(),
                build_valid_proposal(),
            ],
            auditor_responses=[
                build_revise_audit_result(),
                build_approved_audit_result(),
            ],
        )
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    result = workflow.invoke(
        {
            "case": case,
        }
    )

    assert (
        result["final_status"]
        is WorkflowStatus.APPROVED_DRAFT
    )

    assert result["attempt_count"] == 2
    assert planner_model.call_count == 2
    assert auditor_model.call_count == 2

    second_prompt = (
        planner_model.inputs[1][1].content
    )

    assert "VALIDATION_NOT_SPECIFIC" in second_prompt
    assert "nuevo escaneo" in second_prompt


def test_workflow_stops_after_max_attempts() -> None:
    first_invalid = build_valid_proposal()
    first_invalid.management_code = (
        ManagementCode.RESOURCE_DECOMMISSIONING
    )

    second_invalid = build_valid_proposal()
    second_invalid.management_code = (
        ManagementCode.RESOURCE_DECOMMISSIONING
    )

    workflow, planner_model, auditor_model = (
        build_workflow(
            planner_responses=[
                first_invalid,
                second_invalid,
            ],
            auditor_responses=[],
            max_attempts=2,
        )
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    result = workflow.invoke(
        {
            "case": case,
        }
    )

    assert (
        result["final_status"]
        is WorkflowStatus.HUMAN_REVIEW
    )

    assert result["attempt_count"] == 2
    assert result["requires_human_review"] is True
    assert planner_model.call_count == 2
    assert auditor_model.call_count == 0


def test_invalid_case_skips_both_agents() -> None:
    sql_row = build_valid_sql_row()
    sql_row["HOST_GROUP_DS"] = "ND"
    sql_row["HAS_INTERNAL_GROUP_FLG"] = 0

    case = row_to_vulnerability_case(
        sql_row
    )

    workflow, planner_model, auditor_model = (
        build_workflow(
            planner_responses=[],
            auditor_responses=[],
        )
    )

    result = workflow.invoke(
        {
            "case": case,
        }
    )

    assert (
        result["final_status"]
        is WorkflowStatus.DATA_QUALITY_REVIEW
    )

    assert result["attempt_count"] == 0
    assert planner_model.call_count == 0
    assert auditor_model.call_count == 0


def test_provider_error_becomes_processing_error() -> None:
    workflow, planner_model, auditor_model = (
        build_workflow(
            planner_responses=[
                TimeoutError(
                    "Provider timeout"
                ),
            ],
            auditor_responses=[],
        )
    )

    case = row_to_vulnerability_case(
        build_valid_sql_row()
    )

    result = workflow.invoke(
        {
            "case": case,
        }
    )

    assert (
        result["final_status"]
        is WorkflowStatus.PROCESSING_ERROR
    )

    assert result["error_stage"] == "planner"
    assert planner_model.call_count == 1
    assert auditor_model.call_count == 0