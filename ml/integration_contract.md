# SATG ML ↔ Gateway Integration Contract

**Audience:** SATG gateway / M7 decision-layer engineers. You do not need to know anything about
sklearn, XGBoost or transformers. You only use three types and one function call.

```
Gateway (Phase 1–5, deterministic, authoritative)
   │  deterministic decision = BLOCK ──────────────────────────────► BLOCK (ML is never consulted)
   │  deterministic decision = ALLOW (or any non-BLOCK level)
   ▼
MLRequest ──► SATGMLModel.predict() ──► MLRiskResult ──► Decision Fusion (fuse_decision) ──► Execution Harness
```

## 1. Rules that never change

1. **ML is advisory intelligence. Deterministic policy stays authoritative.**
2. ML can **escalate** a decision. ML can **never** turn a deterministic `BLOCK` into `ALLOW`
   (enforced by `fuse_decision`, covered by `tests/test_security_invariant.py`).
3. The ML package never executes tools, never returns ALLOW/BLOCK itself, and holds no credentials.
4. If the ML layer is unavailable, times out or raises, keep the deterministic decision
   (`fuse_decision(det, None)` returns `det`).
5. Phase 1–5 rule IDs and logic are untouched. The ML package is self-contained under `ml/`.

## 2. Usage

```python
import sys; sys.path.insert(0, "ml")
from src.inference.engine import SATGMLModel
from src.inference.schema import MLRequest
from src.inference.gateway_adapter import fuse_decision

model = SATGMLModel()
model.load("ml/artifacts")      # once, at start-up (about 10 s); no training code runs
model.warmup()                  # optional: compiles the first inference path

result = model.predict(request)                  # MLRequest -> MLRiskResult
final = fuse_decision(deterministic_decision, result)                        # 6-level hierarchy
final_binary = fuse_decision(deterministic_decision, result, binary_gateway=True)  # ALLOW/BLOCK gateways
```

`predict` also accepts a plain `dict` with the same keys as `MLRequest`.

## 3. Field mapping: gateway → `MLRequest`

| Gateway data | `MLRequest` field | Notes |
|---|---|---|
| `ToolCallEnvelope` task / context (the user's original request) | `task_text: str` | Use the user task, not the agent's reasoning. |
| envelope id / trace id | `request_id: str` | Echoed back in the result. |
| canonical tool name (from Canonicalization) | `tool_name: str` | |
| registered tool description (from Registry) | `tool_description: str` | If empty, a description is derived from the tool name. |
| canonical parameters (from Parameter Validation) | `arguments: dict` | Any JSON-serialisable dict. |
| latest tool output / content entering the agent's context | `current_observation: str` | The observation tied to this call (the response being returned, or the most recent one before the call). |
| earlier calls in the session, oldest first | `previous_steps: list[dict]` | Each item is `{"tool_name", "arguments", "observation"}` (aliases `tool` / `args` / `obs` are accepted). Malformed items are skipped. |
| existing session state | `session_features: dict` | Optional keys below. |

`session_features` optional keys:

| Key | Type | Purpose |
|---|---|---|
| `known_entities` | `{"user", "email", "company", "contacts": [{"name", "email"}], "known_domains": [..]}` | Principal / organisation identity. Lets the model tell internal from external destinations and anonymise identities, as in training. **Strongly recommended.** |
| `domain` | `str` | Agent domain, e.g. `"email"` or `"banking"`. Used for the derived tool description. |

## 4. `MLRiskResult` (all JSON-serialisable; `result.to_dict()` / `result.to_json()`)

| Field | Type | Meaning |
|---|---|---|
| `p_inject` | float [0,1] | Probability that this step is injection-related (injection point or hijacked action). |
| `p_misaligned` | float [0,1] | Probability that the action is semantically inconsistent with the task. |
| `anomaly_score` | float [0,1] | IsolationForest behavioural anomaly: the share of benign training behaviour that is less anomalous. |
| `sequence_surprisal` | float [0,1] | Normalised trigram surprisal of this tool after the previous two. |
| `context_shift` | float [0,1] | Normalised CUSUM of per-step risk over the session (gradual drift). |
| `fused_risk` | float [0,1] | **Calibrated** probability of security risk from monotone XGBoost fusion. |
| `conformal_abstain` | bool | True means the model is not confident (conformal prediction set is not a singleton). Treat as "needs more scrutiny". |
| `risk_vector` | dict | All 11 fusion features, the raw fusion probability, the conformal prediction set, the per-step context-shift history and the runtime backends. |
| `top_risk_features` | list | `[{"feature", "value", "contribution"}]`: the features that pushed risk up most (share of absolute XGBoost contributions). |
| `model_version`, `feature_version` | str | For audit logs. Currently `satg-ml-v0.1` / `1.0`. |
| `request_id` | str | Echo of the request. |
| `latency_ms` | dict | Timings for `preprocess`, `embedding`, `features`, `model` and `total`. |

## 5. Decision fusion (`src/inference/gateway_adapter.py`)

Hierarchy (monotone): `ALLOW < MONITOR < STEP_UP < HUMAN_APPROVAL < QUARANTINE < BLOCK`.

```
if deterministic == BLOCK: return BLOCK                 # hard veto, ML not consulted
ml_level = highest level whose fused_risk threshold is met   (configs/decision_thresholds.json)
if conformal_abstain: ml_level = max(ml_level, STEP_UP)
final = max(deterministic, ml_level)                    # can only increase restriction
binary gateway: BLOCK iff final >= QUARANTINE, else ALLOW
```

Default thresholds: MONITOR 0.20, STEP_UP 0.40, HUMAN_APPROVAL 0.60, QUARANTINE 0.80, BLOCK 0.95. These
are policy settings, not model outputs. Tune them on your own validation traffic, never on the test split.

## 6. Session state and latency

`predict()` is stateless. It recomputes the session's CUSUM from `previous_steps`, so the gateway needs
no ML state. Embeddings are LRU-cached inside the model, so in a live session each observation is
embedded once. Keep one `SATGMLModel` instance per worker process. See `artifacts/metrics.json →
test.latency_ms` for measured p50/p95 (cold and warm cache).

## 7. Versioning

`artifacts/feature_schema.json` fixes the fusion feature order. `SATGMLModel.load` refuses artifacts
whose schema does not match the code. Log `model_version` and `feature_version` with every decision.
