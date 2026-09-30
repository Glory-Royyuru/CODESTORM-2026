"""SATG ML evaluation entry point (plan §27, §29).

Scores the untouched task-disjoint TEST split with the saved artifacts through the inference engine,
reports the AgentDrift-recommended breakdown, and benchmarks single-request latency.
Thresholds are fixed a priori (0.5 on calibrated probabilities) — nothing is tuned on test.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np

from src.config import ARTIFACT_DIR, CACHE_DIR
from src.data.agentdrift_loader import load_split
from src.evaluation.metrics import binary_metrics, calibration_curve_points, trajectory_breakdown
from src.features.pipeline import session_prefix_requests, trajectory_to_requests
from src.inference.engine import SATGMLModel


def latency_benchmark(model: SATGMLModel, trajs, n_values=(1, 10, 100)) -> dict:
    """Per-request latency over realistic mid-session requests (history included)."""
    rng = np.random.default_rng(0)
    pool = []
    for t in trajs:
        reqs = trajectory_to_requests(t)
        pool.append(reqs[rng.integers(len(reqs))])
    model.warmup()
    out = {}
    for n in n_values:
        for mode in ("cold", "warm"):
            comps = {k: [] for k in ("embedding", "features", "model", "total")}
            sample = [pool[i] for i in rng.choice(len(pool), size=n, replace=False)]
            for req in sample:
                model.embedder._lru.clear()        # no cached embeddings for this session
                if mode == "warm" and req.previous_steps:
                    # live session: the previous call already embedded the history; the CURRENT
                    # observation/action are new and must still be embedded in the timed call
                    model.predict(session_prefix_requests(req)[-2])
                r = model.predict(req)
                for k in comps:
                    comps[k].append(r.latency_ms[k])
            out[f"{n}_requests_{mode}"] = {
                k: {"mean": round(float(np.mean(v)), 2), "p50": round(float(np.percentile(v, 50)), 2),
                    "p95": round(float(np.percentile(v, 95)), 2)} for k, v in comps.items()}
    out["cache_modes"] = {"cold": "embedding LRU cleared before every request (worst case)",
                          "warm": "history embedded by the previous call; current observation + action embedded in the timed call (live-session case)"}
    return out


def main():
    ap = argparse.ArgumentParser(description="Evaluate the SATG ML model on the held-out test split")
    ap.add_argument("--artifacts", default=str(ARTIFACT_DIR))
    ap.add_argument("--split", default="test")
    ap.add_argument("--skip-latency", action="store_true")
    args = ap.parse_args()

    model = SATGMLModel().load(args.artifacts)
    trajs, _ = load_split(args.split)
    t0 = time.time()
    res = model.score_trajectories(trajs, corpus_cache=str(CACHE_DIR / f"emb_{args.split}"))
    y_step = np.concatenate([t.step_labels for t in trajs])
    meta = [t.meta() for t in trajs]
    ti = res["traj_idx"]
    # trajectory score = max step risk (a trajectory is flagged if any step is)
    traj_fused = np.array([res["fused_risk"][ti == i].max() for i in range(len(trajs))])
    traj_inject = np.array([res["signals"]["p_inject"][ti == i].max() for i in range(len(trajs))])

    inj = binary_metrics(y_step, res["signals"]["p_inject"])
    mis = binary_metrics(y_step, res["signals"]["p_misaligned"])
    fus = binary_metrics(y_step, res["fused_risk"])
    fus_raw = binary_metrics(y_step, res["fused_raw"])
    traj = trajectory_breakdown(meta, traj_fused)
    traj_inj_only = trajectory_breakdown(meta, traj_inject)
    abst = res["abstain"]
    wrong = (res["fused_risk"] >= 0.5).astype(int) != y_step
    conformal = {
        "abstention_rate": float(abst.mean()),
        "error_rate_when_not_abstaining": float(wrong[~abst].mean()) if (~abst).any() else None,
        "error_rate_when_abstaining": float(wrong[abst].mean()) if abst.any() else None,
        "empirical_coverage": float(np.mean([y in model.conformal.prediction_set(p)
                                             for y, p in zip(y_step, res["fused_risk"])])),
    }
    signal_auc = {k: binary_metrics(y_step, v)["roc_auc"] for k, v in res["signals"].items()}
    lat = {} if args.skip_latency else latency_benchmark(model, trajs)

    report = {
        "split": args.split, "n_trajectories": len(trajs), "n_steps": int(len(y_step)),
        "injection_classifier_step": inj, "misalignment_classifier_step": mis,
        "fusion_step_calibrated": fus, "fusion_step_uncalibrated": fus_raw,
        "signal_roc_auc_step": signal_auc,
        "trajectory_fusion": traj, "trajectory_p_inject_only_baseline": traj_inj_only,
        "calibration_curve_step": calibration_curve_points(y_step, res["fused_risk"]),
        "conformal": conformal, "latency_ms": lat, "backends": model.backends,
        "scoring_seconds": round(time.time() - t0, 1),
    }
    mpath = Path(args.artifacts) / "metrics.json"
    metrics = json.loads(mpath.read_text()) if mpath.exists() else {}
    metrics[args.split] = report
    mpath.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    f = lambda v: "n/a" if v is None else f"{v:.4f}"  # noqa: E731
    print("=== SATG ML EVALUATION ===")
    print(f"(AgentDrift task-disjoint {args.split}: {len(trajs)} trajectories, {len(y_step)} steps)\n")
    print("Injection classifier (step level)")
    for k in ("roc_auc", "pr_auc", "precision", "recall", "f1"):
        print(f"  {k.upper().replace('_', '-') if k.endswith('auc') else k.title()}: {f(inj[k])}")
    print("\nFusion model (step level, calibrated)")
    for k, lab in (("roc_auc", "ROC-AUC"), ("pr_auc", "PR-AUC"), ("brier", "Brier"), ("log_loss", "Log Loss")):
        print(f"  {lab}: {f(fus[k])}")
    print("\nFalse-positive rate (trajectory level, fused_risk >= 0.5)")
    for k, v in traj["false_positive_rate"].items():
        print(f"  {k.replace('_', ' ').title()}: {f(v)}")
    print("\nAttack recall (trajectory level)")
    for k, v in traj["attack_recall"].items():
        print(f"  {k.replace('_', ' ').title()}: {f(v)}")
    print("\nCalibration (step level)")
    print(f"  ECE: {f(fus['ece'])}\n  Brier: {f(fus['brier'])}")
    print("\nConformal")
    print(f"  Abstention rate: {f(conformal['abstention_rate'])}")
    print(f"  Empirical coverage: {f(conformal['empirical_coverage'])}")
    if lat:
        print("\nInference (single request, CPU)")
        for key in ("100_requests_cold", "100_requests_warm"):
            t = lat[key]["total"]
            print(f"  {key}: mean {t['mean']} ms | p50 {t['p50']} ms | P95 latency {t['p95']} ms")
        p95 = lat["100_requests_warm"]["total"]["p95"]
        print(f"  Target p95 <= 35 ms: {'MET' if p95 <= 35 else 'NOT MET'} (warm, {model.backends})")
    print(f"\nFull report written to {mpath}")


if __name__ == "__main__":
    main()
