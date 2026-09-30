from app.gateway.policy_engine import CheckOutcome, decide
from app.models.verdict import Severity, VerdictType


def test_all_checks_passed_returns_allow():
    outcomes = [
        CheckOutcome("REQUEST_STRUCTURE", passed=True),
        CheckOutcome("TOOL_REGISTRY", passed=True),
    ]
    verdict = decide("support-bot-3", "send_email", outcomes)

    assert verdict.verdict == VerdictType.ALLOW
    assert verdict.rule_id == "BASE-001"
    assert all(c.status == "PASSED" for c in verdict.checks)


def test_one_failed_check_returns_block():
    outcomes = [
        CheckOutcome("REQUEST_STRUCTURE", passed=True),
        CheckOutcome("TOOL_REGISTRY", False, "TOOL-001", "Tool is not registered", Severity.MEDIUM),
    ]
    verdict = decide("support-bot-3", "wipe_disk", outcomes)

    assert verdict.verdict == VerdictType.BLOCK
    assert verdict.checks[-1].status == "FAILED"


def test_failed_check_rule_and_reason_are_preserved():
    outcomes = [
        CheckOutcome("REQUEST_STRUCTURE", passed=True),
        CheckOutcome(
            "AGENT_PERMISSION",
            False,
            "TOOL-003",
            "Agent is not authorized to use this tool",
            Severity.HIGH,
        ),
    ]
    verdict = decide("random-agent", "send_email", outcomes)

    assert verdict.rule_id == "TOOL-003"
    assert verdict.reason == "Agent is not authorized to use this tool"
    assert verdict.severity == Severity.HIGH


def test_multiple_failed_checks_deterministically_use_the_first():
    outcomes = [
        CheckOutcome("REQUEST_STRUCTURE", passed=True),
        CheckOutcome("TOOL_ENABLED", False, "TOOL-002", "Tool is disabled", Severity.MEDIUM),
        CheckOutcome(
            "AGENT_PERMISSION",
            False,
            "TOOL-003",
            "Agent is not authorized to use this tool",
            Severity.HIGH,
        ),
    ]
    verdict = decide("random-agent", "delete_database", outcomes)

    assert verdict.rule_id == "TOOL-002"
    assert verdict.reason == "Tool is disabled"
