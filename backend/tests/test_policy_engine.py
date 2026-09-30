from app.gateway.policy_engine import POLICY_VERSION, CheckOutcome, DecisionContext, decide
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


# --- decision context, fail-closed invariants, explainability ---


def test_failed_check_without_rule_uses_policy_fallback():
    verdict = decide("a", "t", [CheckOutcome("CUSTOM", passed=False)])

    assert verdict.verdict == VerdictType.BLOCK
    assert verdict.rule_id == "POLICY-001"
    assert verdict.severity == Severity.MEDIUM


def test_no_checks_evaluated_fails_closed():
    verdict = decide("a", "t", [])

    assert verdict.verdict == VerdictType.BLOCK
    assert verdict.rule_id == "POLICY-002"


def test_unevaluated_planned_check_fails_closed():
    context = DecisionContext(planned_checks=("REQUEST_STRUCTURE", "TOOL_REGISTRY"))
    verdict = decide("a", "t", [CheckOutcome("REQUEST_STRUCTURE", passed=True)], context)

    assert verdict.verdict == VerdictType.BLOCK
    assert verdict.rule_id == "POLICY-003"
    assert verdict.checks_not_evaluated == ["TOOL_REGISTRY"]


def test_first_failure_wins_and_skipped_checks_are_listed():
    context = DecisionContext(planned_checks=("A", "B", "C"))
    verdict = decide("a", "t", [CheckOutcome("A", True), CheckOutcome("B", False, "X-1", "b failed", Severity.HIGH, "stage-b")], context)

    assert verdict.rule_id == "X-1"
    assert verdict.stage == "stage-b"
    assert verdict.checks_not_evaluated == ["C"]


def test_decision_context_is_carried_into_verdict():
    context = DecisionContext(
        request_id="req_test",
        tool_version="1.0.0",
        tool_manifest_hash="sha256:manifest",
        request_hash="sha256:request",
    )
    verdict = decide("a", "t", [CheckOutcome("A", True)], context)

    assert verdict.request_id == "req_test"
    assert verdict.policy_version == POLICY_VERSION
    assert verdict.tool_version == "1.0.0"
    assert verdict.tool_manifest_hash == "sha256:manifest"
    assert verdict.request_hash == "sha256:request"


def test_request_id_is_generated_when_not_supplied():
    first = decide("a", "t", [CheckOutcome("A", True)])
    second = decide("a", "t", [CheckOutcome("A", True)])
    assert first.request_id != second.request_id


def test_deterministic_core_never_escalates():
    cases = [
        [],
        [CheckOutcome("A", True)],
        [CheckOutcome("A", False, "X-1", "r", Severity.LOW)],
        [CheckOutcome("A", True), CheckOutcome("B", False)],
    ]
    for outcomes in cases:
        assert decide("a", "t", outcomes).verdict in (VerdictType.ALLOW, VerdictType.BLOCK)


def test_any_failed_check_blocks_regardless_of_position():
    for position in range(4):
        outcomes = [CheckOutcome(f"C{i}", i != position, "X-1" if i == position else None) for i in range(4)]
        assert decide("a", "t", outcomes).verdict == VerdictType.BLOCK
