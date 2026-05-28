"""
RAMDetect ML Pipeline — model_trainer.py
========================================
Official RAMDetect RF-AE training engine.

This module is intentionally kept separate from train_model.py:
  - train_model.py is the CLI entry point.
  - model_trainer.py contains the reusable training/evaluation logic.

Algorithm
---------
Dai-style RF-AE feature fusion, adapted for RAMDetect:
  1. Load labelled feature dataset.
  2. Select either the original 54 CIC features or the expanded Phase 8 vector
     of 54 CIC + RAMDetect-native memory-artifact features.
  3. Fit FeatureMapper on the selected base vector.
  4. Train AutoencoderModel on CLEAN samples only.
  5. Recalibrate the AE clean-MSE threshold from the selected feature space.
  6. Append raw AE reconstruction MSE as the final fused feature.
  7. Train RandomForestModel on fused features.

No rule-based detection, forensic veto, clean dampener, or malfind spoofing is
implemented here. Native RAMDetect indicators are ML input columns only.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ramdetect.ml.autoencoder_model import AutoencoderModel
from ramdetect.ml.feature_mapper import (
    CANONICAL_FEATURES,
    EXPANDED_NATIVE_FEATURES,
    FeatureMapper,
)
from ramdetect.ml.hybrid_classifier import HybridClassifier
from ramdetect.ml.random_forest_model import DEFAULT_THRESHOLD, RandomForestModel

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_metric(fn, *args, **kwargs) -> Optional[float]:
    try:
        return float(fn(*args, **kwargs))
    except Exception:
        return None


def _evaluate_scores(y_true: np.ndarray, scores: np.ndarray, threshold: float = DEFAULT_THRESHOLD) -> Dict[str, Any]:
    y_true = np.asarray(y_true, dtype=int)
    scores = np.asarray(scores, dtype=float).reshape(-1)
    y_pred = (scores >= threshold).astype(int)

    out: Dict[str, Any] = {
        "threshold": float(threshold),
        "accuracy": _safe_metric(accuracy_score, y_true, y_pred),
        "precision": _safe_metric(precision_score, y_true, y_pred, zero_division=0),
        "recall": _safe_metric(recall_score, y_true, y_pred, zero_division=0),
        "f1": _safe_metric(f1_score, y_true, y_pred, zero_division=0),
        "auc_roc": None,
    }
    if len(set(map(int, y_true))) == 2:
        out["auc_roc"] = _safe_metric(roc_auc_score, y_true, scores)
    try:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        out.update({"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)})
    except Exception:
        pass
    return out


def _rf_scores(rf: RandomForestModel, X: np.ndarray) -> np.ndarray:
    proba = rf.predict_proba(X)
    arr = np.asarray(proba, dtype=float)
    if arr.ndim == 2 and arr.shape[1] >= 2:
        return arr[:, 1]
    return arr.reshape(-1)


def _normalise_label_series(series: pd.Series) -> np.ndarray:
    """Convert common RAMDetect labels to 0/1 integers."""
    if pd.api.types.is_numeric_dtype(series):
        return series.fillna(0).astype(int).to_numpy()

    mapping = {
        "0": 0,
        "clean": 0,
        "benign": 0,
        "normal": 0,
        "false": 0,
        "1": 1,
        "suspicious": 1,
        "malicious": 1,
        "malware": 1,
        "abnormal": 1,
        "true": 1,
    }
    values = []
    bad = []
    for raw in series.fillna("").astype(str):
        key = raw.strip().lower()
        if key not in mapping:
            bad.append(raw)
            values.append(0)
        else:
            values.append(mapping[key])
    if bad:
        raise ValueError(f"Unsupported label values: {sorted(set(bad))[:10]}")
    return np.asarray(values, dtype=int)


def _split_indices(
    y: np.ndarray,
    seed: int,
    test_size: float,
    val_size: float,
    allow_small_sample: bool,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, str]:
    y = np.asarray(y, dtype=int)
    n = len(y)
    min_class = int(min(np.bincount(y, minlength=2))) if n else 0

    if allow_small_sample or n < 30 or min_class < 3:
        idx = np.arange(n)
        return idx, idx, idx, "small_sample_all_rows_used_for_train_val_test"

    all_idx = np.arange(n)
    train_val_idx, test_idx = train_test_split(
        all_idx,
        test_size=test_size,
        random_state=seed,
        stratify=y,
    )
    val_rel = val_size / max(1e-9, (1.0 - test_size))
    train_idx, val_idx = train_test_split(
        train_val_idx,
        test_size=val_rel,
        random_state=seed,
        stratify=y[train_val_idx],
    )
    return train_idx, val_idx, test_idx, "stratified_train_val_test_split"


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TrainerConfig:
    """Hyperparameters and paths for the official Phase 8 trainer."""

    # Data
    data_path: str = "models/experiments/Phase8_expanded_rf_ae/expanded_feature_dataset.csv"
    label_column: str = "Label"
    feature_mode: str = "expanded"  # expanded | canonical54 | auto
    allow_small_sample: bool = False
    test_size: float = 0.15
    val_size: float = 0.15
    random_state: int = 42

    # Output
    models_dir: str = "models"
    rf_filename: str = "random_forest.pkl"
    ae_filename: str = "autoencoder.pkl"
    ae_keras_filename: str = "autoencoder.keras"
    mapper_filename: str = "feature_mapper.pkl"
    report_filename: str = "training_report.json"
    replay_filename: str = "training_replay.csv"
    importance_filename: str = "feature_importances.csv"

    # Random Forest
    rf_n_estimators: int = 300
    rf_max_depth: Optional[int] = None
    rf_min_samples_split: int = 2
    rf_min_samples_leaf: int = 1
    rf_max_features: str = "sqrt"
    rf_n_jobs: int = -1
    rf_class_weight: str = "balanced"

    # Autoencoder
    ae_encoding_dim: int = 16
    ae_hidden_layers: List[int] = field(default_factory=lambda: [64, 32])
    ae_epochs: int = 80
    ae_batch_size: int = 16
    ae_learning_rate: float = 1e-3
    ae_dropout_rate: float = 0.1
    ae_patience: int = 10
    ae_threshold_percentile: float = 99.0

    # Legacy args kept so old CLI calls do not crash; unused in ML-only fusion.
    t1_percentile: float = 90.0
    t2_percentile: float = 75.0

    # Misc
    verbose: int = 1
    save_training_report: bool = True


@dataclass
class TrainingReport:
    started_at: str = ""
    finished_at: str = ""
    total_seconds: float = 0.0

    algorithm: str = "Dai-style RF-AE feature fusion"
    ml_only: bool = True
    no_rule_based_detection: bool = True
    no_malfind_spoofing: bool = True

    data_path: str = ""
    split_mode: str = ""
    feature_mode: str = ""
    n_total: int = 0
    n_train: int = 0
    n_val: int = 0
    n_test: int = 0
    n_features_base: int = 0
    n_features_fused: int = 0
    n_canonical_features: int = 0
    n_native_features: int = 0
    class_balance: Dict[str, int] = field(default_factory=dict)

    ae_threshold: float = 0.0
    ae_threshold_percentile: float = 99.0
    ae_train_seconds: float = 0.0
    rf_train_seconds: float = 0.0

    metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    artefacts: Dict[str, str] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    warning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def pretty(self) -> str:
        lines = [
            "=" * 72,
            "  RAMDetect · Official Phase 8 Expanded RF-AE Training Report",
            "=" * 72,
            f"  Started / Finished : {self.started_at} / {self.finished_at}",
            f"  Duration           : {self.total_seconds:.1f}s",
            f"  Algorithm          : {self.algorithm}",
            f"  ML-only            : {self.ml_only}",
            "",
            "  Dataset",
            f"    Path              : {self.data_path}",
            f"    Split mode        : {self.split_mode}",
            f"    Rows              : {self.n_total:,}",
            f"    Train / Val / Test: {self.n_train:,} / {self.n_val:,} / {self.n_test:,}",
            f"    Feature mode      : {self.feature_mode}",
            f"    Base features     : {self.n_features_base}",
            f"    Fused features    : {self.n_features_fused} (base + AE MSE)",
            f"    Class balance     : {self.class_balance}",
            "",
            "  Autoencoder",
            f"    Threshold pct     : {self.ae_threshold_percentile}",
            f"    Threshold MSE     : {self.ae_threshold:.8f}",
            f"    Train time        : {self.ae_train_seconds:.1f}s",
            "",
            "  Random Forest",
            f"    Train time        : {self.rf_train_seconds:.1f}s",
            f"    RF threshold      : {DEFAULT_THRESHOLD}",
            "",
            "  Metrics",
        ]
        for split, metric in self.metrics.items():
            lines.append(
                f"    {split:<8} acc={metric.get('accuracy')} "
                f"f1={metric.get('f1')} auc={metric.get('auc_roc')}"
            )
        lines.extend(["", "  Saved Artefacts"])
        for name, path in self.artefacts.items():
            lines.append(f"    {name:<24} → {path}")
        if self.warning:
            lines.extend(["", f"  Warning: {self.warning}"])
        lines.append("=" * 72)
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# ModelTrainer
# ─────────────────────────────────────────────────────────────────────────────

class ModelTrainer:
    """Reusable trainer/evaluator for the official Phase 8 RF-AE pipeline."""

    def __init__(
        self,
        data_path: Optional[str] = None,
        config: Optional[TrainerConfig] = None,
        **kwargs: Any,
    ) -> None:
        self.cfg = config or TrainerConfig()
        if data_path:
            self.cfg.data_path = data_path
        for key, val in kwargs.items():
            if not hasattr(self.cfg, key):
                raise ValueError(f"Unknown TrainerConfig field: {key!r}")
            setattr(self.cfg, key, val)

        self._setup_logging()
        self.mapper: Optional[FeatureMapper] = None
        self.rf_model: Optional[RandomForestModel] = None
        self.ae_model: Optional[AutoencoderModel] = None
        self.hybrid: Optional[HybridClassifier] = None
        self.report: Optional[TrainingReport] = None

        # Compatibility with older ModelEvaluator.from_trainer() code. The new
        # train_model.py no longer relies on this attribute, but leaving it here
        # prevents accidental AttributeError in old imports.
        self.loader = None

    def _setup_logging(self) -> None:
        level = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(self.cfg.verbose, logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )

    def _info(self, msg: str) -> None:
        logger.info(msg)
        if self.cfg.verbose >= 1:
            print(f"  ▸ {msg}")

    def _section(self, title: str) -> None:
        logger.info("─── %s", title)
        if self.cfg.verbose >= 1:
            print(f"\n{'─' * 70}\n  {title}\n{'─' * 70}")

    def _models_dir(self) -> Path:
        p = Path(self.cfg.models_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _load_dataframe(self) -> pd.DataFrame:
        path = Path(self.cfg.data_path)
        if not path.is_file():
            raise FileNotFoundError(f"Dataset not found: {path}")
        return pd.read_csv(path)

    def _resolve_label_column(self, df: pd.DataFrame) -> str:
        if self.cfg.label_column in df.columns:
            return self.cfg.label_column
        for candidate in ("Label", "Class", "label", "class"):
            if candidate in df.columns:
                self._info(f"Label column {self.cfg.label_column!r} not found; using {candidate!r}")
                return candidate
        raise ValueError(f"No label column found. Tried {self.cfg.label_column!r}, Label, Class, label, class")

    def _resolve_feature_names(self, df: pd.DataFrame) -> Tuple[str, List[str]]:
        canonical = list(CANONICAL_FEATURES)
        native = list(EXPANDED_NATIVE_FEATURES)
        expanded = canonical + native

        mode = str(self.cfg.feature_mode or "expanded").lower()
        has_expanded = all(c in df.columns for c in expanded)
        has_canonical = all(c in df.columns for c in canonical)

        if mode == "auto":
            if has_expanded:
                return "expanded", expanded
            if has_canonical:
                return "canonical54", canonical
            missing = [c for c in canonical if c not in df.columns]
            raise ValueError(f"Dataset is missing canonical features. Missing {len(missing)}: {missing[:20]}")

        if mode in {"expanded", "phase8"}:
            missing = [c for c in expanded if c not in df.columns]
            if missing:
                raise ValueError(
                    "Expanded Phase 8 training requires 54 CIC features + native RAMDetect features. "
                    f"Missing {len(missing)}: {missing[:30]}"
                )
            return "expanded", expanded

        if mode in {"canonical", "canonical54", "cic", "cic54"}:
            missing = [c for c in canonical if c not in df.columns]
            if missing:
                raise ValueError(f"Canonical training missing {len(missing)} features: {missing[:30]}")
            return "canonical54", canonical

        raise ValueError("feature_mode must be one of: expanded, canonical54, auto")

    def _load_feature_matrix(self) -> Dict[str, Any]:
        self._section("Step 1 / 6 — Load labelled feature dataset")
        df = self._load_dataframe()
        label_col = self._resolve_label_column(df)
        feature_mode, feature_names = self._resolve_feature_names(df)

        y = _normalise_label_series(df[label_col])
        X_raw = df[feature_names].fillna(0.0).astype(float).to_numpy()

        train_idx, val_idx, test_idx, split_mode = _split_indices(
            y=y,
            seed=self.cfg.random_state,
            test_size=self.cfg.test_size,
            val_size=self.cfg.val_size,
            allow_small_sample=self.cfg.allow_small_sample,
        )

        balance = {str(k): int(v) for k, v in pd.Series(y).value_counts().sort_index().to_dict().items()}
        self._info(f"Rows             : {len(df):,}")
        self._info(f"Feature mode     : {feature_mode}")
        self._info(f"Base features    : {len(feature_names)}")
        self._info(f"Split mode       : {split_mode}")
        self._info(f"Class balance    : {balance}")

        return {
            "df": df,
            "label_col": label_col,
            "feature_mode": feature_mode,
            "feature_names": feature_names,
            "X_raw": X_raw,
            "y": y,
            "train_idx": train_idx,
            "val_idx": val_idx,
            "test_idx": test_idx,
            "split_mode": split_mode,
            "balance": balance,
        }

    def _fit_mapper(self, X_train_raw: np.ndarray, feature_names: List[str], feature_mode: str) -> FeatureMapper:
        self._section("Step 2 / 6 — Fit FeatureMapper")
        self.mapper = FeatureMapper(feature_mode=feature_mode)
        self.mapper.fit(X_train_raw, feature_names)
        self._info(f"Mapper feature mode : {getattr(self.mapper, 'feature_mode', feature_mode)}")
        self._info(f"Mapper features     : {getattr(self.mapper, 'n_features', len(feature_names))}")
        return self.mapper

    def _transform_all(self, mapper: FeatureMapper, data: Dict[str, Any]) -> Dict[str, np.ndarray]:
        self._section("Step 3 / 6 — Transform train/val/test/all to model base vector")
        fn = data["feature_names"]
        X = data["X_raw"]
        train_idx, val_idx, test_idx = data["train_idx"], data["val_idx"], data["test_idx"]

        Xt_train = mapper.transform_cic(X[train_idx], fn)
        Xt_val = mapper.transform_cic(X[val_idx], fn)
        Xt_test = mapper.transform_cic(X[test_idx], fn)
        Xt_all = mapper.transform_cic(X, fn)
        self._info(f"Base shapes: train={Xt_train.shape} val={Xt_val.shape} test={Xt_test.shape} all={Xt_all.shape}")
        return {"train": Xt_train, "val": Xt_val, "test": Xt_test, "all": Xt_all}

    def _train_ae(self, Xt: Dict[str, np.ndarray], y_train: np.ndarray, y_val: np.ndarray) -> Tuple[float, AutoencoderModel]:
        self._section("Step 4 / 6 — Train Autoencoder on CLEAN samples only")
        ae_params = {
            "encoding_dims": list(self.cfg.ae_hidden_layers) + [self.cfg.ae_encoding_dim],
            "activation": "relu",
            "dropout_rate": self.cfg.ae_dropout_rate,
            "learning_rate": self.cfg.ae_learning_rate,
            "epochs": self.cfg.ae_epochs,
            "batch_size": self.cfg.ae_batch_size,
            "patience": self.cfg.ae_patience,
        }
        self.ae_model = AutoencoderModel(params=ae_params)
        t0 = time.perf_counter()
        self.ae_model.train(
            Xt["train"],
            Xt["val"],
            y_train=y_train,
            y_val=y_val,
            threshold_percentile=self.cfg.ae_threshold_percentile,
        )
        elapsed = time.perf_counter() - t0
        self._info(f"AE threshold MSE : {float(self.ae_model.threshold):.8f}")
        self._info(f"AE train time    : {elapsed:.1f}s")
        return elapsed, self.ae_model

    def _fuse(self, Xt: Dict[str, np.ndarray]) -> Tuple[Dict[str, np.ndarray], Dict[str, np.ndarray]]:
        self._section("Step 5 / 6 — Feature Fusion: append raw AE reconstruction MSE")
        if self.ae_model is None:
            raise RuntimeError("AE model is not trained")

        mse = {split: self.ae_model._reconstruction_errors(arr) for split, arr in Xt.items()}
        fused = {split: np.column_stack([arr, mse[split]]) for split, arr in Xt.items()}
        self._info(f"Fused shapes: train={fused['train'].shape} val={fused['val'].shape} test={fused['test'].shape}")
        return fused, mse

    def _train_rf(self, fused: Dict[str, np.ndarray], y_train: np.ndarray, y_val: np.ndarray, fused_names: List[str]) -> Tuple[float, RandomForestModel]:
        self._section("Step 6 / 6 — Train RandomForest on fused RF-AE vector")
        n_train = fused["train"].shape[0]
        rf_params = {
            "n_estimators": self.cfg.rf_n_estimators,
            "max_depth": self.cfg.rf_max_depth,
            "min_samples_split": self.cfg.rf_min_samples_split,
            "min_samples_leaf": self.cfg.rf_min_samples_leaf,
            "max_features": self.cfg.rf_max_features,
            "n_jobs": self.cfg.rf_n_jobs,
            "class_weight": None if self.cfg.rf_class_weight == "none" else self.cfg.rf_class_weight,
            "random_state": self.cfg.random_state,
            "oob_score": False if n_train < 10 else True,
        }
        self.rf_model = RandomForestModel(params=rf_params, threshold=DEFAULT_THRESHOLD)
        t0 = time.perf_counter()
        self.rf_model.train(fused["train"], y_train, fused["val"], y_val, feature_names=fused_names)
        elapsed = time.perf_counter() - t0
        self._info(f"RF train time    : {elapsed:.1f}s")
        return elapsed, self.rf_model

    def _save_artefacts(self, fused_names: List[str], data: Dict[str, Any], mse: Dict[str, np.ndarray], scores: Dict[str, np.ndarray]) -> Dict[str, str]:
        self._section("Saving artefacts")
        if self.mapper is None or self.ae_model is None or self.rf_model is None:
            raise RuntimeError("Models are not fully trained")

        out_dir = self._models_dir()
        mapper_path = out_dir / self.cfg.mapper_filename
        ae_path = out_dir / self.cfg.ae_filename
        rf_path = out_dir / self.cfg.rf_filename
        replay_path = out_dir / self.cfg.replay_filename
        importance_path = out_dir / self.cfg.importance_filename

        self.mapper.save(str(mapper_path))
        self.ae_model.save(str(ae_path))
        self.rf_model.save(str(rf_path))

        # Per-row replay for traceability.
        rows = []
        df = data["df"].reset_index(drop=True)
        y_all = data["y"]
        all_scores = scores["all"]
        all_mse = mse["all"]
        for i, row in df.iterrows():
            pred = int(all_scores[i] >= DEFAULT_THRESHOLD)
            rows.append({
                "row_index": int(i),
                "case": row.get("case", f"row_{i}"),
                "session_id": row.get("session_id", ""),
                "true_label": int(y_all[i]),
                "ae_mse": float(all_mse[i]),
                "ae_threshold": float(self.ae_model.threshold),
                "ae_anomalous": bool(all_mse[i] > self.ae_model.threshold),
                "rf_score": float(all_scores[i]),
                "prediction": pred,
                "correct": bool(pred == int(y_all[i])),
            })
        pd.DataFrame(rows).to_csv(replay_path, index=False)

        try:
            importances = pd.DataFrame({
                "feature": fused_names,
                "importance": self.rf_model.feature_importances_.tolist(),
            }).sort_values("importance", ascending=False)
            importances.to_csv(importance_path, index=False)
        except Exception as exc:
            logger.warning("Could not export feature importances: %s", exc)
            pd.DataFrame({"feature": fused_names, "importance": []}).to_csv(importance_path, index=False)

        return {
            "feature_mapper": str(mapper_path),
            "autoencoder_pkl": str(ae_path),
            "autoencoder_keras": str(out_dir / self.cfg.ae_keras_filename),
            "random_forest": str(rf_path),
            "training_replay": str(replay_path),
            "feature_importances": str(importance_path),
        }

    def run(self) -> TrainingReport:
        wall_start = time.perf_counter()
        started_at = _now_utc()

        if self.cfg.verbose >= 1:
            print("\n" + "=" * 72)
            print("  RAMDetect — Official Phase 8 Expanded RF-AE Training")
            print("=" * 72)

        data = self._load_feature_matrix()
        y = data["y"]
        train_idx, val_idx, test_idx = data["train_idx"], data["val_idx"], data["test_idx"]
        y_train, y_val, y_test = y[train_idx], y[val_idx], y[test_idx]

        mapper = self._fit_mapper(data["X_raw"][train_idx], data["feature_names"], data["feature_mode"])
        Xt = self._transform_all(mapper, data)
        ae_secs, _ = self._train_ae(Xt, y_train, y_val)
        fused, mse = self._fuse(Xt)

        base_names = mapper.get_canonical_features()
        fused_names = base_names + ["ae_reconstruction_error"]
        rf_secs, _ = self._train_rf(fused, y_train, y_val, fused_names)

        # Hybrid object is kept for compatibility; final RF-AE decision is RF on fused vector.
        self.hybrid = HybridClassifier()
        self.hybrid.load_models_directly(rf_model=self.rf_model, ae_model=self.ae_model)

        scores = {split: _rf_scores(self.rf_model, arr) for split, arr in fused.items()}
        metrics = {
            "train": _evaluate_scores(y_train, scores["train"]),
            "val": _evaluate_scores(y_val, scores["val"]),
            "test": _evaluate_scores(y_test, scores["test"]),
            "all_rows": _evaluate_scores(y, scores["all"]),
        }

        artefacts = self._save_artefacts(fused_names, data, mse, scores)
        finished_at = _now_utc()
        total_seconds = time.perf_counter() - wall_start

        warning = ""
        if data["split_mode"].startswith("small_sample"):
            warning = (
                "Small-sample mode used; train/val/test metrics are sanity checks, "
                "not final generalisation evidence. Collect more labelled dumps for FYP claims."
            )

        self.report = TrainingReport(
            started_at=started_at,
            finished_at=finished_at,
            total_seconds=round(total_seconds, 2),
            data_path=str(self.cfg.data_path),
            split_mode=data["split_mode"],
            feature_mode=data["feature_mode"],
            n_total=len(y),
            n_train=len(train_idx),
            n_val=len(val_idx),
            n_test=len(test_idx),
            n_features_base=len(base_names),
            n_features_fused=len(fused_names),
            n_canonical_features=len(CANONICAL_FEATURES),
            n_native_features=len(EXPANDED_NATIVE_FEATURES) if data["feature_mode"] == "expanded" else 0,
            class_balance=data["balance"],
            ae_threshold=float(self.ae_model.threshold),
            ae_threshold_percentile=float(self.cfg.ae_threshold_percentile),
            ae_train_seconds=round(ae_secs, 2),
            rf_train_seconds=round(rf_secs, 2),
            metrics=metrics,
            artefacts=artefacts,
            config=dataclasses.asdict(self.cfg),
            warning=warning,
        )

        if self.cfg.save_training_report:
            report_path = Path(self.cfg.models_dir) / self.cfg.report_filename
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(self.report.to_dict(), indent=2), encoding="utf-8")
            self.report.artefacts["training_report"] = str(report_path)
            # Re-write with the report path included.
            report_path.write_text(json.dumps(self.report.to_dict(), indent=2), encoding="utf-8")

        if self.cfg.verbose >= 1:
            print("\n" + self.report.pretty())
        return self.report

    def load_artefacts(self) -> None:
        """Load trained mapper, RF, and AE from models_dir."""
        d = Path(self.cfg.models_dir)
        self.mapper = FeatureMapper.load(str(d / self.cfg.mapper_filename))
        self.rf_model = RandomForestModel.load(str(d / self.cfg.rf_filename))
        self.ae_model = AutoencoderModel.load(str(d / self.cfg.ae_filename))
        self.hybrid = HybridClassifier()
        self.hybrid.load_models_directly(rf_model=self.rf_model, ae_model=self.ae_model)

    def evaluate_dataset(self, data_path: Optional[str] = None, label_column: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate saved artefacts on a labelled dataset without retraining."""
        if data_path:
            self.cfg.data_path = data_path
        if label_column:
            self.cfg.label_column = label_column
        self.load_artefacts()
        if self.mapper is None or self.rf_model is None or self.ae_model is None:
            raise RuntimeError("Artefacts not loaded")

        data = self._load_feature_matrix()
        feature_names = data["feature_names"]
        X = data["X_raw"]
        y = data["y"]
        Xt = self.mapper.transform_cic(X, feature_names)
        mse = self.ae_model._reconstruction_errors(Xt)
        fused = np.column_stack([Xt, mse])
        scores = _rf_scores(self.rf_model, fused)
        metrics = _evaluate_scores(y, scores)

        out_dir = self._models_dir()
        replay_path = out_dir / "evaluation_replay.csv"
        report_path = out_dir / "evaluation_report.json"

        rows = []
        for i, score in enumerate(scores):
            pred = int(score >= DEFAULT_THRESHOLD)
            rows.append({
                "row_index": int(i),
                "true_label": int(y[i]),
                "ae_mse": float(mse[i]),
                "ae_threshold": float(self.ae_model.threshold),
                "rf_score": float(score),
                "prediction": pred,
                "correct": bool(pred == int(y[i])),
            })
        pd.DataFrame(rows).to_csv(replay_path, index=False)

        report = {
            "evaluated_at": _now_utc(),
            "data_path": str(self.cfg.data_path),
            "feature_mode": data["feature_mode"],
            "rows": int(len(y)),
            "base_features": int(Xt.shape[1]),
            "fused_features": int(fused.shape[1]),
            "metrics": metrics,
            "artefacts": {
                "evaluation_replay": str(replay_path),
                "evaluation_report": str(report_path),
            },
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
