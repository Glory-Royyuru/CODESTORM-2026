"""SATG ML training entry point (plan §26).

load -> clean -> task-disjoint split -> features -> injection / misalignment / IsolationForest / trigram
-> CUSUM -> XGBoost fusion -> calibration -> conformal -> save artifacts -> validation report.

Leakage control: every signal fed to the fusion model on the training split is OUT-OF-FOLD
(5-fold GroupKFold by task template), so fusion never sees in-sample component predictions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
warnings.filterwarnings("ignore", category=UserWarning)

import joblib
import numpy as np
from sklearn.model_selection import GroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.config import (AGENTDRIFT_SPLIT, ARTIFACT_DIR, CACHE_DIR, CONFORMAL_ALPHA, CONTEXT_FEATURES,
                        EMBEDDING_MODEL, FEATURE_VERSION, FUSION_FEATURES, ISOTONIC_MIN_CAL_SAMPLES,
                        MODEL_VERSION, MODELS_DIR, MONOTONE_CONSTRAINTS, PROCESSED_DIR, SEED, SIGNAL_FEATURES,
                        SPLITS_DIR, STEP_LABEL_MAP)
from src.data.agentdrift_loader import load_split
from src.evaluation.metrics import binary_metrics, calibration_curve_points
from src.features.pipeline import (BEHAVIOR_FEATURES, LEXICAL_FEATURES, SIMILARITY_FEATURES,
                                   compute_from_prepared, injection_matrix, misalignment_matrix, prepare,
                                   sequence_parts, trajectory_to_requests)
from src.features.sequence_features import TrigramModel
from src.features.statistical_features import CusumConfig
from src.features.text_features import Embedder
from src.models.anomaly import AnomalyModel
from src.models.calibration import Calibrator
from src.models.conformal import ConformalAbstainer
from src.models.fusion import train_fusion
from src.models.signals import assemble, compute_signals, cusum_input, run_cusum
from src.models.text_classifiers import make_injection_model, make_misalignment_model, predict_positive


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class SplitData:
    """Step-level view of one split (rows ordered by trajectory, then step)."""

    def __init__(self, name, trajs, embedder):
        self.name = name
        self.trajs = trajs
        self.requests, self.traj_idx, self.labels, self.raw_labels = [], [], [], []
        for ti, t in enumerate(trajs):
            for r, s in zip(trajectory_to_requests(t), t.steps):
                self.requests.append(r)
                self.traj_idx.append(ti)
                self.labels.append(STEP_LABEL_MAP[s.label])
                self.raw_labels.append(s.label)
        self.traj_idx = np.asarray(self.traj_idx)
        self.y = np.asarray(self.labels, dtype=int)
        self.tasks = np.asarray([trajs[i].task_text for i in self.traj_idx])
        self.category = np.asarray([trajs[i].category for i in self.traj_idx])
        log(f"{name}: {len(trajs)} trajectories, {len(self.y)} steps, positives={int(self.y.sum())}")
        self.prepared = [prepare(r) for r in self.requests]
        t0 = time.time()
        self.bf = compute_from_prepared(self.prepared, embedder, None, corpus_cache=str(CACHE_DIR / f"emb_{name}"))
        log(f"{name}: text features ready ({time.time() - t0:.1f}s)")

    def set_trigram(self, trigram):
        self.bf.behaviour, self.bf.context, self.bf.surprisal = sequence_parts(self.prepared, trigram)

    def subset(self, mask):
        return np.where(mask)[0]


def benign_tool_sequences(trajs, idx=None):
    idx = range(len(trajs)) if idx is None else idx
    return [[s.tool for s in trajs[i].steps] for i in idx if trajs[i].category == "benign"]


def split_val_by_task(trajs):
    """Deterministic task-disjoint halves of validation: A = selection + calibration, B = conformal."""
    tasks = sorted({t.task_text for t in trajs})
    part_b = {t for t in tasks if int(hashlib.sha256(t.encode()).hexdigest(), 16) % 2 == 1}
    return np.array([t.task_text not in part_b for t in trajs])


def main():
    ap = argparse.ArgumentParser(description="Train the SATG behavioural ML model")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--artifacts", default=str(ARTIFACT_DIR))
    args = ap.parse_args()
    art = Path(args.artifacts)
    art.mkdir(parents=True, exist_ok=True)
    np.random.seed(SEED)
    T0 = time.time()

    # ---------------------------------------------------------------- 1. load + clean + split
    log(f"Loading AgentDrift ({AGENTDRIFT_SPLIT}) ...")
    splits, reports = {}, {}
    for part in ("train", "val", "test"):
        splits[part], rep = load_split(part)
        reports[part] = rep.to_dict()
        log(f"  {part}: accepted={rep.accepted} rejected={sum(rep.rejected.values())}")
    # leakage check: task-disjointness
    task_sets = {p: {t.task_text for t in splits[p]} for p in splits}
    overlap = {f"{a}-{b}": len(task_sets[a] & task_sets[b]) for a, b in
               [("train", "val"), ("train", "test"), ("val", "test")]}
    assert all(v == 0 for v in overlap.values()), f"task leakage across splits: {overlap}"
    val_a_mask = split_val_by_task(splits["val"])
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)
    (PROCESSED_DIR / "load_report.json").write_text(json.dumps(
        {"reports": reports, "task_overlap": overlap,
         "unique_tasks": {p: len(v) for p, v in task_sets.items()}}, indent=2), encoding="utf-8")
    manifest = {p: [t.trajectory_id for t in splits[p]] for p in splits}
    manifest["val_A_selection_calibration"] = [t.trajectory_id for t, m in zip(splits["val"], val_a_mask) if m]
    manifest["val_B_conformal"] = [t.trajectory_id for t, m in zip(splits["val"], val_a_mask) if not m]
    (SPLITS_DIR / "split_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    log(f"  val A (select+calibrate)={int(val_a_mask.sum())} trajs, val B (conformal)={int((~val_a_mask).sum())}")

    # ---------------------------------------------------------------- 2. features
    embedder = Embedder(EMBEDDING_MODEL)
    data = {p: SplitData(p, splits[p], embedder) for p in ("train", "val", "test")}
    tr = data["train"]

    # ---------------------------------------------------------------- 3. out-of-fold component signals
    log(f"Out-of-fold component models ({args.folds}-fold GroupKFold by task) ...")
    n = len(tr.y)
    oof = {k: np.zeros(n, dtype=np.float32) for k in ("p_inject", "p_misaligned", "anomaly_score", "sequence_surprisal")}
    X_inj_all, X_mis_all = injection_matrix(tr.bf), misalignment_matrix(tr.bf)
    for f, (fit_idx, ho_idx) in enumerate(GroupKFold(n_splits=args.folds).split(X_inj_all, tr.y, groups=tr.tasks)):
        t0 = time.time()
        fit_trajs = np.unique(tr.traj_idx[fit_idx])
        trig = TrigramModel().fit(benign_tool_sequences(tr.trajs, fit_trajs))
        beh, _, sur = sequence_parts(tr.prepared, trig)
        benign_fit = fit_idx[tr.category[fit_idx] == "benign"]
        an = AnomalyModel().fit(beh[benign_fit])
        inj = make_injection_model().fit(X_inj_all[fit_idx], tr.y[fit_idx])
        mis = make_misalignment_model().fit(X_mis_all[fit_idx], tr.y[fit_idx])
        oof["p_inject"][ho_idx] = predict_positive(inj, X_inj_all[ho_idx])
        oof["p_misaligned"][ho_idx] = predict_positive(mis, X_mis_all[ho_idx])
        oof["anomaly_score"][ho_idx] = an.score(beh[ho_idx])
        oof["sequence_surprisal"][ho_idx] = sur[ho_idx]
        log(f"  fold {f + 1}/{args.folds} done ({time.time() - t0:.1f}s)")

    # CUSUM configuration fitted on benign training sessions (OOF inputs)
    x_oof = cusum_input(oof["p_inject"], oof["p_misaligned"])
    benign_sessions = [x_oof[tr.traj_idx == ti].tolist() for ti in range(len(tr.trajs))
                       if tr.trajs[ti].category == "benign"]
    cusum_cfg = CusumConfig.fit(benign_sessions)
    log(f"CUSUM: target={cusum_cfg.target:.4f} drift={cusum_cfg.drift:.4f} h={cusum_cfg.h:.4f}")
    oof_shift = run_cusum(x_oof, tr.traj_idx, cusum_cfg)

    # ---------------------------------------------------------------- 4. final component models (full train)
    log("Fitting final component models on the full training split ...")
    trigram = TrigramModel().fit(benign_tool_sequences(tr.trajs))
    for d in data.values():
        d.set_trigram(trigram)
    anomaly = AnomalyModel().fit(tr.bf.behaviour[tr.category == "benign"])
    inj_model = make_injection_model().fit(X_inj_all, tr.y)
    mis_model = make_misalignment_model().fit(X_mis_all, tr.y)

    X_train = assemble(oof["p_inject"], oof["p_misaligned"], oof["anomaly_score"], oof["sequence_surprisal"],
                       oof_shift, tr.bf.context)
    feats, sigs = {}, {}
    for p in ("val", "test"):
        feats[p], sigs[p] = compute_signals(data[p].bf, data[p].traj_idx, inj_model, mis_model, anomaly, cusum_cfg)
    va = data["val"]
    step_a = val_a_mask[va.traj_idx]
    XA, yA = feats["val"][step_a], va.y[step_a]
    XB, yB = feats["val"][~step_a], va.y[~step_a]

    # ---------------------------------------------------------------- 5. fusion
    log("Training monotone XGBoost fusion (tiny candidate set, selected on val A) ...")
    fusion, cand = train_fusion(X_train, tr.y, XA, yA)
    for c in cand:
        log(f"  {c['params']} -> val PR-AUC {c['val_pr_auc']:.4f}")

    # ---------------------------------------------------------------- 6. calibration
    rawA, rawB = fusion.predict_proba(XA)[:, 1], fusion.predict_proba(XB)[:, 1]
    comparison = {"uncalibrated": binary_metrics(yB, rawB)}
    cals = {}
    for method in ("isotonic", "sigmoid"):
        cals[method] = Calibrator(method).fit(rawA, yA)
        comparison[method] = binary_metrics(yB, cals[method].transform(rawB))
    method = "isotonic" if len(yA) >= ISOTONIC_MIN_CAL_SAMPLES else "sigmoid"
    calibrator = cals[method]
    log(f"Calibration: {method} (n_cal={len(yA)}); val-B Brier raw={comparison['uncalibrated']['brier']:.4f} "
        f"iso={comparison['isotonic']['brier']:.4f} sig={comparison['sigmoid']['brier']:.4f}")

    # ---------------------------------------------------------------- 7. conformal
    pB = calibrator.transform(rawB)
    conformal = ConformalAbstainer(alpha=CONFORMAL_ALPHA).fit(pB, yB)
    abst_B = conformal.abstain(pB)
    log(f"Conformal: q0={conformal.q[0]:.4f} q1={conformal.q[1]:.4f} region={conformal.uncertainty_region()} "
        f"abstain(valB)={abst_B.mean():.3f}")

    # ---------------------------------------------------------------- 8. save artifacts
    log("Saving artifacts ...")
    joblib.dump(inj_model, art / "injection_model.joblib")
    joblib.dump(mis_model, art / "misalignment_model.joblib")
    joblib.dump(anomaly, art / "isolation_forest.joblib")
    trigram.save(art / "trigram_model.json")
    cusum_cfg.save(art / "cusum_config.json")
    fusion.get_booster().feature_names = FUSION_FEATURES
    fusion.save_model(art / "fusion_model.json")
    joblib.dump(calibrator, art / "calibration.joblib")
    joblib.dump(calibrator, art / "calibrated_fusion_model.joblib")  # plan §21 name (calibration map)
    (art / "calibration_metadata.json").write_text(json.dumps({
        "method": method, "rule": f"isotonic if n_cal >= {ISOTONIC_MIN_CAL_SAMPLES} else sigmoid",
        "n_calibration": int(len(yA)), "calibration_set": "validation part A (task-disjoint from val part B)",
        "comparison_on_val_B": comparison,
        "calibration_curve_val_B": calibration_curve_points(yB, pB)}, indent=2), encoding="utf-8")
    conformal.save(art / "conformal_config.json")
    schema = {
        "feature_version": FEATURE_VERSION,
        "fusion_features": FUSION_FEATURES,
        "signal_features": SIGNAL_FEATURES,
        "context_features": CONTEXT_FEATURES,
        "monotone_constraints": dict(zip(FUSION_FEATURES, MONOTONE_CONSTRAINTS)),
        "injection_model_input": {"order": ["emb_observation[384]", "emb_action[384]"] + SIMILARITY_FEATURES
                                  + LEXICAL_FEATURES, "dim": int(X_inj_all.shape[1])},
        "misalignment_model_input": {"order": SIMILARITY_FEATURES + LEXICAL_FEATURES
                                     + ["emb_task*emb_action[384]"], "dim": int(X_mis_all.shape[1])},
        "isolation_forest_input": BEHAVIOR_FEATURES,
        "embedding_model": EMBEDDING_MODEL,
        "cusum_input": cusum_cfg.input_signal,
    }
    (art / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")

    # frozen embedding model saved next to the artifacts for offline inference
    emb_dir = art / "embedding_model"
    if not (emb_dir / "config.json").exists():
        tok, enc = embedder.model
        tok.save_pretrained(emb_dir)
        enc.save_pretrained(emb_dir)
    onnx_status = export_onnx(inj_model, X_inj_all.shape[1], art, embedder)

    # ---------------------------------------------------------------- 9. validation report
    val_metrics = {
        "p_inject_val": binary_metrics(va.y, sigs["val"]["p_inject"]),
        "p_misaligned_val": binary_metrics(va.y, sigs["val"]["p_misaligned"]),
        "fusion_val_B_calibrated": comparison[method],
        "conformal_val_B_abstention_rate": float(abst_B.mean()),
        "oof_train": {k: binary_metrics(tr.y, v) for k, v in oof.items() if k in ("p_inject", "p_misaligned")},
    }
    metadata = {
        "model_version": MODEL_VERSION,
        "dataset": "AgentDrift v2.0 (github.com/Asif-0209/AgentDrift)",
        "split": "task-disjoint",
        "feature_version": FEATURE_VERSION,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "training_seconds": round(time.time() - T0, 1),
        "models": {
            "embedding": f"{EMBEDDING_MODEL} (frozen, mean-pooled, L2-normalised)",
            "injection": "StandardScaler + LogisticRegression(class_weight=balanced) on MiniLM + text features",
            "misalignment": "StandardScaler + LogisticRegression(class_weight=balanced) on semantic alignment features",
            "anomaly": "IsolationForest (benign-only) + empirical-CDF normalisation",
            "sequence": "trigram (interpolated add-k) tool-transition model, benign-only",
            "context_shift": "CUSUM on max(p_inject, p_misaligned)",
            "fusion": f"XGBoost monotone {fusion.get_params()['n_estimators']} trees depth {fusion.get_params()['max_depth']}",
            "calibration": method,
            "conformal": "Mondrian split conformal (LAC)",
        },
        "fusion_candidates": cand,
        "anonymization": "world identities replaced with placeholders (AgentDrift leakage control)",
        "training_rows": {"train_steps": int(len(tr.y)), "val_steps": int(len(va.y)),
                          "val_A_steps": int(step_a.sum()), "val_B_steps": int((~step_a).sum()),
                          "test_steps": int(len(data['test'].y))},
        "onnx": onnx_status,
    }
    (art / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    metrics_path = art / "metrics.json"
    metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}
    metrics["validation"] = val_metrics
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    mirror_to_models_dir(art)

    print("\n=== SATG ML TRAINING REPORT ===")
    print(f"Dataset          : AgentDrift task-disjoint | train {len(tr.trajs)} / val {len(va.trajs)} / "
          f"test {len(data['test'].trajs)} trajectories")
    print(f"Train steps      : {len(tr.y)} (positives {int(tr.y.sum())})")
    print(f"p_inject   (val) : ROC-AUC {val_metrics['p_inject_val']['roc_auc']:.4f}  PR-AUC {val_metrics['p_inject_val']['pr_auc']:.4f}")
    print(f"p_misalign (val) : ROC-AUC {val_metrics['p_misaligned_val']['roc_auc']:.4f}  PR-AUC {val_metrics['p_misaligned_val']['pr_auc']:.4f}")
    fb = comparison[method]
    print(f"Fusion (val B)   : ROC-AUC {fb['roc_auc']:.4f}  PR-AUC {fb['pr_auc']:.4f}  Brier {fb['brier']:.4f}  ECE {fb['ece']:.4f}")
    print(f"Calibration      : {method}")
    print(f"Conformal        : abstention on val B = {abst_B.mean():.3f}")
    print(f"ONNX             : {onnx_status}")
    print(f"Artifacts        : {art}")
    print(f"Total time       : {time.time() - T0:.1f}s")


def export_onnx(inj_model, dim, art: Path, embedder) -> dict:
    """Best-effort ONNX export (plan §14). Never fails the training run."""
    status = {}
    try:
        from skl2onnx import to_onnx
        onx = to_onnx(inj_model, np.zeros((1, dim), dtype=np.float32), options={"zipmap": False},
                      target_opset=17)
        (art / "injection_model.onnx").write_bytes(onx.SerializeToString())
        status["injection_model.onnx"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["injection_model.onnx"] = f"failed: {type(exc).__name__}: {exc}"[:300]
    try:
        import torch
        tok, enc = embedder.model

        class _Wrapper(torch.nn.Module):
            def __init__(self, m):
                super().__init__()
                self.m = m

            def forward(self, input_ids, attention_mask, token_type_ids):
                h = self.m(input_ids=input_ids, attention_mask=attention_mask,
                           token_type_ids=token_type_ids).last_hidden_state
                mask = attention_mask.unsqueeze(-1).to(h.dtype)
                pooled = (h * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
                return torch.nn.functional.normalize(pooled, p=2, dim=1)

        sample = tok(["sample text"], return_tensors="pt")
        torch.onnx.export(_Wrapper(enc).eval(),
                          (sample["input_ids"], sample["attention_mask"], sample["token_type_ids"]),
                          str(art / "embedding_model.onnx"),
                          input_names=["input_ids", "attention_mask", "token_type_ids"],
                          output_names=["sentence_embedding"],
                          dynamic_axes={k: {0: "batch", 1: "seq"} for k in
                                        ["input_ids", "attention_mask", "token_type_ids"]}
                          | {"sentence_embedding": {0: "batch"}},
                          opset_version=17, dynamo=False)
        status["embedding_model.onnx"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["embedding_model.onnx"] = f"failed: {type(exc).__name__}: {exc}"[:300]
    return status


def mirror_to_models_dir(art: Path) -> None:
    """Copies artifacts into the plan's models/<component>/ layout."""
    layout = {
        "injection": ["injection_model.joblib", "injection_model.onnx", "misalignment_model.joblib"],
        "anomaly": ["isolation_forest.joblib"],
        "sequence": ["trigram_model.json", "cusum_config.json"],
        "fusion": ["fusion_model.json"],
        "calibration": ["calibration.joblib", "calibration_metadata.json", "conformal_config.json"],
    }
    for sub, files in layout.items():
        d = MODELS_DIR / sub
        d.mkdir(parents=True, exist_ok=True)
        for f in files:
            if (art / f).exists():
                shutil.copy2(art / f, d / f)


if __name__ == "__main__":
    main()
