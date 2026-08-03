from __future__ import annotations

from typing import Any

import pytest

from src.catalog import load_management_catalog
from src.demo_data import (
    build_demo_approved_audit,
    build_demo_case,
    build_demo_proposal,
)
from src.enums import (
    PolicyDecision,
    WorkflowStatus,
)
from src.exceptions import WorkflowExecutionError
from src.models import PolicyEvaluation
from src.workflow_service import (
    VulnerabilityWorkflowService,
)


class FakeWorkflow:
    """
    Workflow simulado para probar la capa de servicio
    independientemente de LangGraph.
    """

    def __init__(
        self,
        *,
        response: Any = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.last_input: Any = None

    def invoke(
        self,
        input: Any,
        **kwargs: Any,
    ) -> Any:
        self.last_input = input

        if self.error is not None:
            raise self.error

        return self.response


def test_service_builds_controlled_approved_result() -> None:
    case = build_demo_case()
    proposal = build_demo_proposal()

    workflow = FakeWorkflow(
        response={
            "case": case,
            "proposal": proposal,
            "policy_evaluation": PolicyEvaluation(
                decision=PolicyDecision.PASS,
                findings=[],
                requires_human_review=False,
            ),
            "audit_result": (
                build_demo_approved_audit()
            ),
            "attempt_count": 1,
            "max_attempts": 3,
            "requires_human_review": False,
            "final_status": (
                WorkflowStatus.APPROVED_DRAFT
            ),
        }
    )

    service = VulnerabilityWorkflowService(
        workflow=workflow,
        catalog=load_management_catalog(),
    )

    result = service.analyze(case)

    assert (
        result.final_status
        is WorkflowStatus.APPROVED_DRAFT
    )

    assert result.group_ds == (
        "Soporte de Plataformas"
    )

    assert (
        result.management_ds
        == "Se debe evaluar la solución de la vulnerabilidad"
    )

    assert result.observation_ds == (
        proposal.observation_ds
    )


def test_service_builds_data_quality_result() -> None:
    case = build_demo_case(
        has_internal_group=False,
    )

    workflow = FakeWorkflow(
        response={
            "case": case,
            "attempt_count": 0,
            "max_attempts": 3,
            "requires_human_review": True,
            "final_status": (
                WorkflowStatus.DATA_QUALITY_REVIEW
            ),
        }
    )

    service = VulnerabilityWorkflowService(
        workflow=workflow,
        catalog=load_management_catalog(),
    )

    result = service.analyze(case)

    assert (
        result.final_status
        is WorkflowStatus.DATA_QUALITY_REVIEW
    )

    assert result.proposal is None
    assert result.management_ds is None
    assert result.group_ds is None


def test_service_wraps_unexpected_workflow_errors() -> None:
    workflow = FakeWorkflow(
        error=RuntimeError(
            "Unexpected workflow failure"
        )
    )

    service = VulnerabilityWorkflowService(
        workflow=workflow,
        catalog=load_management_catalog(),
    )

    with pytest.raises(
        WorkflowExecutionError
    ) as exc_info:
        service.analyze(
            build_demo_case()
        )

    assert isinstance(
        exc_info.value.__cause__,
        RuntimeError,
    )


def test_service_rejects_invalid_workflow_output() -> None:
    workflow = FakeWorkflow(
        response="invalid result"
    )

    service = VulnerabilityWorkflowService(
        workflow=workflow,
        catalog=load_management_catalog(),
    )

    with pytest.raises(
        WorkflowExecutionError,
        match="formato no reconocido",
    ):
        service.analyze(
            build_demo_case()
        )