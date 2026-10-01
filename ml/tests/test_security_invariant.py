"""Integration-contract test (plan §28): ML can never change a deterministic BLOCK into ALLOW."""
import itertools

import pytest

from src.inference.gateway_adapter import HIERARCHY, LEVEL, fuse_decision
from src.inference.schema import MLRequest, MLRiskResult


def _ml(fused: float, abstain: bool) -> MLRiskResult:
    return MLRiskResult(p_inject=fused, p_misaligned=fused, anomaly_score=fused, sequence_surprisal=fused,
                        context_shift=fused, fused_risk=fused, risk_vector={}, conformal_abstain=abstain,
                        model_version="t", feature_version="t")


GRID = [i / 20 for i in range(21)]


@pytest.mark.parametrize("binary", [False, True])
def test_block_never_becomes_allow(binary):
    for fused, abstain in itertools.product(GRID, (False, True)):
        assert fuse_decision("BLOCK", _ml(fused, abstain), binary_gateway=binary) == "BLOCK"
    assert fuse_decision("BLOCK", None, binary_gateway=binary) == "BLOCK"


def test_ml_only_escalates():
    for det in HIERARCHY:
        for fused, abstain in itertools.product(GRID, (False, True)):
            final = fuse_decision(det, _ml(fused, abstain))
            assert LEVEL[final] >= LEVEL[det]


def test_decision_monotone_in_risk():
    for det in HIERARCHY:
        levels = [LEVEL[fuse_decision(det, _ml(f, False))] for f in GRID]
        assert levels == sorted(levels)


def test_ml_unavailable_falls_back_to_deterministic():
    assert fuse_decision("ALLOW", None) == "ALLOW"
    assert fuse_decision("STEP_UP", None) == "STEP_UP"


def test_real_model_cannot_unblock(model):
    """Even with the most benign-looking request, a deterministic BLOCK stays BLOCK."""
    r = model.predict(MLRequest(request_id="x", task_text="check balance", tool_name="get_balance",
                                current_observation="Balance: $10"))
    assert fuse_decision("BLOCK", r) == "BLOCK"
    assert fuse_decision("BLOCK", r, binary_gateway=True) == "BLOCK"
    assert not hasattr(r, "execute") and "ALLOW" not in r.to_json()  # ML returns no authorisation
