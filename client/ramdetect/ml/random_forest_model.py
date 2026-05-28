"""
random_forest_model.py - Random Forest Classifier
==================================================
Phase 5, Module 3/8 — RAMDetect ML Pipeline

Supervised binary classifier: CLEAN (0) vs SUSPICIOUS (1)

CHANGE vs previous version
--------------------------
Decision threshold is fixed at 0.50.

For ML-only RAMDetect classification, the threshold is the final decision
boundary. RAMDetect's current FYP rule fixes this boundary at 0.50. Saved
model metadata, JSON files, and environment variables must not change it.

Usage:
    # Training
    rf = RandomForestModel()
    rf.train(X_train, y_train, X_val, y_val)
    rf.save("models/random_forest.pkl")

    # Inference
    rf = RandomForestModel.load("models/random_forest.pkl")
    result = rf.predict(x)          # {"label": 1, "verdict": "SUSPICIOUS", ...}
    results = rf.predict_batch(X)   # list of result dicts
"""

import json
import logging
import os
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Default hyperparameters
# ─────────────────────────────────────────────

DEFAULT_PARAMS: Dict = {
    "n_estimators":      200,
    "max_depth":         20,
    "min_samples_split": 5,
    "min_samples_leaf":  2,
    "max_features":      "sqrt",
    "class_weight":      "balanced",
    "random_state":      42,
    "n_jobs":            -1,
    "oob_score":         True,
}

# Grid for optional hyperparameter search
PARAM_GRID: Dict = {
    "n_estimators": [100, 200, 300],
    "max_depth":    [10, 20, None],
    "max_features": ["sqrt", "log2"],
}

VERDICT_MAP = {0: "CLEAN", 1: "SUSPICIOUS"}

# ─────────────────────────────────────────────
# Default decision threshold
#
# 0.50 — current RAMDetect FYP ML-only decision boundary.
#
# MASTER RULE: do not modify/tune the threshold during RAMDetect experiments
# or implementation. The RF boundary is fixed at 0.50 unless the user later
# explicitly revokes this rule. Saved model thresholds, JSON configs and
# environment variables must not change it.
# ─────────────────────────────────────────────
DEFAULT_THRESHOLD: float = 0.5

# Legacy threshold-control names are retained only for backward-compatible
# imports. Active RAMDetect inference ignores them and uses DEFAULT_THRESHOLD.
THRESHOLD_ENV_VAR = "RAMDETECT_RF_THRESHOLD"
THRESHOLD_CONFIG_ENV_VAR = "RAMDETECT_THRESHOLD_CONFIG"
THRESHOLD_CONFIG_NAME = "ml_threshold.json"


def _coerce_threshold(value, source: str = "threshold") -> Optional[float]:
    """Convert a threshold-like value to float and validate it is in (0, 1)."""
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        logger.warning("Ignoring invalid RF threshold from %s: %r", source, value)
        return None

    if not (0.0 < threshold < 1.0):
        logger.warning(
            "Ignoring out-of-range RF threshold from %s: %.4f. Expected 0 < threshold < 1.",
            source,
            threshold,
        )
        return None

    return threshold


def _load_threshold_change(model_path: Optional[Union[str, Path]] = None) -> Optional[float]:
    """
    Threshold change disabled by RAMDetect master rule.

    The RF decision threshold is fixed at DEFAULT_THRESHOLD (0.50).
    This function intentionally ignores RAMDETECT_RF_THRESHOLD,
    RAMDETECT_THRESHOLD_CONFIG, saved model metadata, and ml_threshold.json.
    It is retained only for backward-compatible imports.
    """
    if os.getenv(THRESHOLD_ENV_VAR) is not None or os.getenv(THRESHOLD_CONFIG_ENV_VAR) is not None:
        logger.warning(
            "RF threshold change ignored: RAMDetect master rule fixes threshold at %.2f",
            DEFAULT_THRESHOLD,
        )
    return None


class RandomForestModel:
    """
    Random Forest binary classifier for RAM-based malware detection.

    Parameters
    ----------
    params : dict, optional
        Sklearn RandomForestClassifier parameters.
    threshold : float
        Retained for backward compatibility only. Active RAMDetect inference
        always uses DEFAULT_THRESHOLD (0.50).
    """

    def __init__(
        self,
        params: Optional[Dict] = None,
        threshold: float = DEFAULT_THRESHOLD,
    ):
        self.params = params or DEFAULT_PARAMS.copy()
        # Master rule: ignore caller-supplied threshold and keep 0.50 fixed.
        self.threshold = DEFAULT_THRESHOLD
        self.model: Optional[RandomForestClassifier] = None
        self.feature_names: List[str] = []
        self.feature_importances_: Optional[np.ndarray] = None
        self.train_metrics: Dict = {}
        self.val_metrics: Dict = {}
        self._is_trained: bool = False
        self._training_time: float = 0.0

    def set_threshold(self, threshold: float, source: str = "manual") -> "RandomForestModel":
        """Backward-compatible no-op.

        RAMDetect's FYP rule fixes the RF decision threshold at 0.50. Calls to
        this method are logged and ignored so old helper scripts do not silently
        alter inference behaviour.
        """
        logger.warning(
            "Ignoring RF threshold change request from %s: RAMDetect fixes threshold at %.2f",
            source,
            DEFAULT_THRESHOLD,
        )
        self.threshold = DEFAULT_THRESHOLD
        return self

    def get_decision_threshold(self) -> float:
        """Return the active RF decision threshold used by predict()."""
        return float(self.threshold)

    # ─────────────────────────────────────────
    # Training
    # ─────────────────────────────────────────

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val:   Optional[np.ndarray] = None,
        y_val:   Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
    ) -> "RandomForestModel":
        """
        Train the Random Forest classifier.

        Parameters
        ----------
        X_train, y_train : Training data (scaled, from FeatureMapper)
        X_val,   y_val   : Optional validation data for post-train eval
        feature_names    : Column names for feature importance reporting
        """
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_train.shape[1])]

        print("\n" + "=" * 60)
        print("  🌲 TRAINING RANDOM FOREST")
        print("=" * 60)
        print(f"  Training samples  : {len(y_train):,}")
        print(f"  Features          : {X_train.shape[1]}")
        print(f"  Trees             : {self.params['n_estimators']}")
        print(f"  Max depth         : {self.params['max_depth']}")
        print(f"  Decision threshold: {self.threshold}  (≥ this → SUSPICIOUS)")
        print("  Training...")

        self.model = RandomForestClassifier(**self.params)

        t0 = time.time()
        self.model.fit(X_train, y_train)
        self._training_time = time.time() - t0

        self._is_trained = True
        self.feature_importances_ = self.model.feature_importances_

        self.train_metrics = self._evaluate(X_train, y_train, "train")

        if X_val is not None and y_val is not None:
            self.val_metrics = self._evaluate(X_val, y_val, "val")

        self._print_train_summary()
        return self

    def tune_and_train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val:   Optional[np.ndarray] = None,
        y_val:   Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
        cv_folds: int = 3,
    ) -> "RandomForestModel":
        """Run GridSearchCV to find best hyperparameters, then train final model."""
        print("\n" + "=" * 60)
        print("  🔍 HYPERPARAMETER TUNING (GridSearchCV)")
        print("=" * 60)
        print(f"  CV folds : {cv_folds}")
        print(f"  Grid     : {PARAM_GRID}")
        print("  Searching... (this may take a few minutes)")

        base = RandomForestClassifier(
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        search = GridSearchCV(
            base, PARAM_GRID, cv=cv, scoring="f1", n_jobs=-1, verbose=1,
        )
        search.fit(X_train, y_train)

        print(f"\n  Best params : {search.best_params_}")
        print(f"  Best CV F1  : {search.best_score_:.4f}")

        self.params.update(search.best_params_)
        self.params["oob_score"] = True

        return self.train(X_train, y_train, X_val, y_val, feature_names)

    # ─────────────────────────────────────────
    # Inference
    # ─────────────────────────────────────────

    def predict(self, x: np.ndarray) -> Dict:
        """
        Classify a single feature vector.

        Returns
        -------
        {
            "label":           int,   # 0=CLEAN, 1=SUSPICIOUS
            "verdict":         str,
            "suspicion_score": float, # P(SUSPICIOUS) [0,1]
            "confidence":      float,
            "model":           str,
        }
        """
        self._check_trained()
        if x.ndim == 1:
            x = x.reshape(1, -1)

        proba = self.model.predict_proba(x)[0]
        suspicion_score = float(proba[1])
        label = 1 if suspicion_score >= self.threshold else 0
        confidence = suspicion_score if label == 1 else (1.0 - suspicion_score)

        return {
            "label":           label,
            "verdict":         VERDICT_MAP[label],
            "suspicion_score": round(suspicion_score, 4),
            "confidence":      round(confidence, 4),
            "model":           "random_forest",
        }

    def predict_batch(self, X: np.ndarray) -> List[Dict]:
        """Classify a batch of feature vectors."""
        self._check_trained()
        probas = self.model.predict_proba(X)
        results = []
        for proba in probas:
            suspicion_score = float(proba[1])
            label = 1 if suspicion_score >= self.threshold else 0
            confidence = suspicion_score if label == 1 else (1.0 - suspicion_score)
            results.append({
                "label":           label,
                "verdict":         VERDICT_MAP[label],
                "suspicion_score": round(suspicion_score, 4),
                "confidence":      round(confidence, 4),
                "model":           "random_forest",
            })
        return results

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Raw probability array (N, 2) — used by hybrid_classifier.py."""
        self._check_trained()
        return self.model.predict_proba(X)

    # ─────────────────────────────────────────
    # Feature importance
    # ─────────────────────────────────────────

    def get_top_features(self, n: int = 15) -> List[Tuple[str, float]]:
        self._check_trained()
        importances = self.feature_importances_
        indices = np.argsort(importances)[::-1][:n]
        return [
            (self.feature_names[i], round(float(importances[i]), 4))
            for i in indices
        ]

    def print_feature_importance(self, n: int = 15) -> None:
        print(f"\n  🏆 TOP {n} MOST IMPORTANT FEATURES (Random Forest)")
        print("  " + "-" * 50)
        for rank, (name, score) in enumerate(self.get_top_features(n), 1):
            bar = "█" * int(score * 40)
            print(f"  {rank:2d}. {name:<42s} {score:.4f} {bar}")

    # ─────────────────────────────────────────
    # Evaluation
    # ─────────────────────────────────────────

    def _evaluate(self, X: np.ndarray, y: np.ndarray, split_name: str) -> Dict:
        probas = self.model.predict_proba(X)[:, 1]
        preds  = (probas >= self.threshold).astype(int)

        metrics = {
            "accuracy":  round(accuracy_score(y, preds), 4),
            "precision": round(precision_score(y, preds, zero_division=0), 4),
            "recall":    round(recall_score(y, preds, zero_division=0), 4),
            "f1":        round(f1_score(y, preds, zero_division=0), 4),
            "auc_roc":   round(roc_auc_score(y, probas), 4),
        }
        cm = confusion_matrix(y, preds)
        metrics["confusion_matrix"] = cm.tolist()
        metrics["tn"] = int(cm[0, 0])
        metrics["fp"] = int(cm[0, 1])
        metrics["fn"] = int(cm[1, 0])
        metrics["tp"] = int(cm[1, 1])
        return metrics

    def evaluate(self, X: np.ndarray, y: np.ndarray, split_name: str = "test") -> Dict:
        self._check_trained()
        metrics = self._evaluate(X, y, split_name)
        self._print_metrics(metrics, split_name)
        return metrics

    # ─────────────────────────────────────────
    # Save / Load
    # ─────────────────────────────────────────

    def save(self, path: Union[str, Path]) -> None:
        self._check_trained()
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as f:
            pickle.dump({
                "model":               self.model,
                "params":              self.params,
                "threshold":           self.threshold,
                "feature_names":       self.feature_names,
                "feature_importances": self.feature_importances_,
                "train_metrics":       self.train_metrics,
                "val_metrics":         self.val_metrics,
                "training_time":       self._training_time,
                "version":             "1.1",
            }, f)
        logger.info(f"RandomForestModel saved → {out}")
        print(f"  💾 RandomForestModel saved: {out}")

    @classmethod
    def load(cls, path: Union[str, Path]) -> "RandomForestModel":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model not found: {p}")

        # Standard RAMDetect .pkl files are written with pickle. Some offline
        # diagnostic experiments (for example F0 live-observable RF) are saved
        # with joblib as a dict containing a raw sklearn RandomForestClassifier
        # plus feature_names metadata. Support both formats without changing
        # threshold or verdict logic.
        try:
            with open(p, "rb") as f:
                data = pickle.load(f)
            load_format = "pickle"
        except Exception as pickle_exc:
            try:
                import joblib  # local import: only needed for experiment artefacts
                data = joblib.load(p)
                load_format = "joblib"
            except Exception as joblib_exc:
                raise RuntimeError(
                    f"Failed to load RF model {p} as pickle ({pickle_exc}) "
                    f"or joblib ({joblib_exc})"
                ) from joblib_exc

        if not isinstance(data, dict) or "model" not in data:
            raise RuntimeError(
                f"Unsupported RF model format in {p}: expected dict with a 'model' key"
            )

        saved_threshold = data.get("threshold", DEFAULT_THRESHOLD)

        # RAMDetect FYP rule: active inference uses the current ML-only
        # threshold policy by default. Older artefacts may contain thresholds
        # from previous experiments; do not let stale metadata silently control
        # current inference. Runtime changes are not allowed in the final FYP path.
        obj = cls(params=data.get("params", DEFAULT_PARAMS.copy()), threshold=DEFAULT_THRESHOLD)
        obj.model = data["model"]
        obj.feature_names = list(data.get("feature_names", []))

        if "feature_importances" in data:
            obj.feature_importances_ = data["feature_importances"]
        else:
            obj.feature_importances_ = getattr(obj.model, "feature_importances_", None)

        if obj.feature_importances_ is None:
            raise RuntimeError(f"RF model {p} does not expose feature importances")

        obj.train_metrics = data.get("train_metrics", {})
        obj.val_metrics = data.get("val_metrics", {})
        obj._training_time = float(data.get("training_time", 0.0) or 0.0)
        obj._is_trained = True

        # Master rule: active RF threshold is fixed at 0.50.
        _load_threshold_change(p)  # logs/ignores any attempted change.
        obj.threshold = DEFAULT_THRESHOLD
        logger.info(
            "RandomForestModel loaded ← %s (%s) | saved threshold %.4f ignored; active fixed threshold %.4f",
            p,
            load_format,
            float(saved_threshold),
            obj.threshold,
        )

        return obj

    # ─────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────

    def _check_trained(self):
        if not self._is_trained or self.model is None:
            raise RuntimeError("Model not trained. Call .train() first.")

    def _print_train_summary(self):
        oob = getattr(self.model, "oob_score_", None)
        print(f"\n  ✅ Training complete in {self._training_time:.1f}s")
        if oob:
            print(f"  OOB Score  : {oob:.4f}")
        self._print_metrics(self.train_metrics, "train")
        if self.val_metrics:
            self._print_metrics(self.val_metrics, "val")

    def _print_metrics(self, metrics: Dict, split_name: str):
        print(f"\n  [{split_name.upper()}]")
        print(f"  Accuracy  : {metrics['accuracy']:.4f}")
        print(f"  Precision : {metrics['precision']:.4f}")
        print(f"  Recall    : {metrics['recall']:.4f}")
        print(f"  F1 Score  : {metrics['f1']:.4f}")
        print(f"  AUC-ROC   : {metrics['auc_roc']:.4f}")
        print(f"  Confusion Matrix:")
        print(f"    TN={metrics['tn']:,}  FP={metrics['fp']:,}")
        print(f"    FN={metrics['fn']:,}  TP={metrics['tp']:,}")

    def get_model_info(self) -> Dict:
        return {
            "type":          "RandomForest",
            "is_trained":    self._is_trained,
            "n_trees":       self.params.get("n_estimators"),
            "max_depth":     self.params.get("max_depth"),
            "threshold":     self.threshold,
            "n_features":    len(self.feature_names),
            "train_metrics": self.train_metrics,
            "val_metrics":   self.val_metrics,
            "training_time": round(self._training_time, 2),
            "top_features":  self.get_top_features(5) if self._is_trained else [],
        }


# ─────────────────────────────────────────────
# CLI / quick test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

    from ramdetect.ml.dataset_loader import load_cic_malmem
    from ramdetect.ml.feature_mapper import FeatureMapper

    if len(sys.argv) < 2:
        print("Usage: python random_forest_model.py <path/to/CIC-MalMem-2022.csv>")
        sys.exit(1)

    loader, splits = load_cic_malmem(sys.argv[1])
    X_train_raw, y_train = splits["train"]
    X_val_raw,   y_val   = splits["val"]
    X_test_raw,  y_test  = splits["test"]

    mapper = FeatureMapper()
    mapper.fit(X_train_raw, loader.get_feature_names())

    X_train = mapper.transform_cic(X_train_raw, loader.get_feature_names())
    X_val   = mapper.transform_cic(X_val_raw,   loader.get_feature_names())
    X_test  = mapper.transform_cic(X_test_raw,  loader.get_feature_names())

    rf = RandomForestModel()
    rf.train(X_train, y_train, X_val, y_val,
             feature_names=mapper.get_canonical_features())

    print("\n" + "=" * 60)
    print("  🧪 TEST SET EVALUATION")
    print("=" * 60)
    rf.evaluate(X_test, y_test, "test")
    rf.print_feature_importance(n=10)

    result = rf.predict(X_test[0:1])
    actual = "CLEAN" if y_test[0] == 0 else "SUSPICIOUS"
    print(f"\n  Sample prediction : {result['verdict']}  (actual: {actual})")
    print(f"  Suspicion score   : {result['suspicion_score']}")
    print(f"  Confidence        : {result['confidence']}")

    rf.save("models/random_forest.pkl")
    print("\n✅ random_forest_model.py working correctly!")