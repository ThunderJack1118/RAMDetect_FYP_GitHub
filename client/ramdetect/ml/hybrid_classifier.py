"""
hybrid_classifier.py — Feature Fusion Hybrid Classifier
========================================================
Phase 5, Module 5/8 — RAMDetect ML Pipeline

ARCHITECTURE: Feature Fusion (Dai et al. 2024)
─────────────────────────────────────────────────────────────────────
Unified single-step decision at inference time:

    Step 1 (Autoencoder Anomaly Detection):
        e_i = AE.reconstruction_error(x_i)          [MSE]

    Step 2 (Feature Fusion):
        x_fused = concat(x_i, e_i)                  [54 features -> 55 features]

    Step 3 (Random Forest Final Verdict):
        p_i = RF.predict_proba(x_fused)[1]
        if p_i >= RF.threshold → verdict = SUSPICIOUS
        else                   → verdict = CLEAN

Why this is superior to Sequential Filtering:
---------------------------------------------
In sequential filtering, if the RF failed to recognize a zero-day malware 
sample, it exited as CLEAN before the AE ever saw it. 

By fusing the AE's reconstruction error as a 55th feature *before* the RF 
makes its decision, the RF learns to trust the AE's anomaly score when it 
doesn't recognize the standard 54 features. This provides robust zero-day 
coverage without complex threshold calibration.
"""

from __future__ import annotations

import logging
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Union

import numpy as np

try:
    # FYP experiment lock: CIC-MalMem-2022 canonical feature order only.
    from ramdetect.ml.feature_mapper import CANONICAL_FEATURES
except Exception:  # pragma: no cover - defensive fallback for isolated tests
    CANONICAL_FEATURES = []

logger = logging.getLogger(__name__)

VERDICT_MAP = {0: "CLEAN", 1: "SUSPICIOUS"}

# RAMDetect FYP decision policy:
# - ML-only final verdict.
# - CIC-MalMem-2022 canonical 54 features only.
# - AE reconstruction MSE is appended as Feature 55.
# - No forensic veto rules, no clean dampeners, no deterministic overrides.
ML_ONLY_DECISION = True
STRICT_CIC54_EXPERIMENT = True
EXPECTED_BASE_FEATURES = 54
EXPECTED_FUSED_FEATURES = 55

class HybridClassifier:
    """
    Feature Fusion Hybrid: Autoencoder MSE + Random Forest.

    Parameters
    ----------
    rf_path    : Path to saved RandomForestModel (.pkl)
    ae_path    : Path to saved AutoencoderModel (.pkl)
    """

    def __init__(
        self,
        rf_path: str = "models/random_forest.pkl",
        ae_path: str = "models/autoencoder.pkl",
        **kwargs  # Absorb legacy arguments (T1, T2, weights) gracefully
    ):
        self.rf_path = Path(rf_path)
        self.ae_path = Path(ae_path)

        self.rf_model = None
        self.ae_model = None
        self._is_loaded = False

    # ──────────────────────────────────────────────────────────────────────────
    # Load
    # ──────────────────────────────────────────────────────────────────────────

    def load(self) -> "HybridClassifier":
        from ramdetect.ml.random_forest_model import RandomForestModel
        from ramdetect.ml.autoencoder_model   import AutoencoderModel

        print("\n" + "=" * 62)
        print("  🔀 LOADING HYBRID CLASSIFIER  (Dai et al. Feature Fusion)")
        print("=" * 62)
        print(f"  Loading Random Forest  ← {self.rf_path}")
        self.rf_model = RandomForestModel.load(self.rf_path)
        print(f"  Loading Autoencoder    ← {self.ae_path}")
        self.ae_model = AutoencoderModel.load(self.ae_path)

        self._is_loaded = True
        self._print_config()
        print("=" * 62)
        return self

    def load_models_directly(
        self,
        rf_model,
        ae_model,
    ) -> "HybridClassifier":
        """Inject already-loaded model objects (used by ModelTrainer)."""
        self.rf_model = rf_model
        self.ae_model = ae_model
        self._is_loaded = True
        return self

    # ──────────────────────────────────────────────────────────────────────────
    # Core inference helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _ae_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Return per-sample reconstruction MSE from the AE."""
        try:
            return self.ae_model._reconstruction_errors(X)
        except AttributeError:
            ae_p = self.ae_model.predict_proba(X)[:, 1]
            return ae_p

    def _ae_normalized_score(self, X: np.ndarray) -> np.ndarray:
        """
        Return AE anomaly scores in [0, 1] for display.
        Delegates to the AE's own sigmoid-based anomaly_score() so the
        display value uses the same calibrated threshold as the model itself,
        instead of the broken threshold*1.5 heuristic that saturated at 1.0
        for any real-world dump regardless of whether it was clean or malicious.
        """
        try:
            return self.ae_model.anomaly_score(X)
        except AttributeError:
            # Fallback: sigmoid over raw MSE / threshold
            errors = self._ae_reconstruction_errors(X)
            thr = float(getattr(self.ae_model, "threshold", 0.01))
            ratio = errors / (thr + 1e-8)
            return np.clip(1.0 - 1.0 / (1.0 + ratio), 0.0, 1.0).astype(np.float32)

    def _explain(
        self,
        label:         int,
        hybrid_score:  float,
        ae_error:      float,
    ) -> str:
        verdict = VERDICT_MAP[label]
        pct     = round(hybrid_score * 100, 1)
        ae_thr  = getattr(self.ae_model, "threshold", 0.01)

        if label == 1:
            if ae_error > ae_thr:
                return (
                    f"[{verdict} | {pct}%] ML-only RF-AE fusion classified the dump "
                    f"as SUSPICIOUS. The RF score is supported by anomalous AE "
                    f"reconstruction error ({ae_error:.4f} > {ae_thr:.4f})."
                )
            return (
                f"[{verdict} | {pct}%] ML-only RF-AE fusion classified the dump "
                f"as SUSPICIOUS from the fused memory-feature profile plus AE MSE."
            )

        if ae_error > ae_thr:
            return (
                f"[{verdict} | {pct}%] ML-only RF-AE fusion classified the dump as CLEAN, "
                f"although AE reconstruction error is elevated ({ae_error:.4f} > {ae_thr:.4f}). "
                f"Review the explanation panels if analyst triage is required."
            )

        return (
            f"[{verdict} | {pct}%] ML-only RF-AE fusion classified the dump as CLEAN. "
            f"AE reconstruction error ({ae_error:.4f}) is within the learned clean range."
        )

    def _build_rf_input(self, X: np.ndarray, ae_errors: np.ndarray) -> np.ndarray:
        """
        Build the exact RF input matrix required by the loaded RF model.

        Standard Phase 8 production model:
            RF feature_names length = 89
            Input = 88 expanded scaled features + raw AE MSE.

        Backward-compatible canonical model:
            RF feature_names length = 55
            Input = 54 canonical scaled features + raw AE MSE.

        Named subset experiment:
            Input = selected named base features + raw AE MSE,
            in the exact order stored in rf_model.feature_names.

        This is feature selection only. It does not change score, threshold,
        verdict logic, FeatureMapper, AE, or parser behavior.
        """
        if X.ndim == 1:
            X = X.reshape(1, -1)

        ae_errors = np.asarray(ae_errors, dtype=np.float32).reshape(-1)
        if len(ae_errors) != X.shape[0]:
            raise ValueError(
                f"AE error count mismatch: got {len(ae_errors)} errors for {X.shape[0]} samples"
            )

        # FYP experiment lock: only CIC-MalMem-2022 canonical54 + AE MSE is allowed.
        if STRICT_CIC54_EXPERIMENT and X.shape[1] != EXPECTED_BASE_FEATURES:
            raise ValueError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: expected "
                f"{EXPECTED_BASE_FEATURES} base CIC features, got {X.shape[1]}. "
                "Do not use expanded/native RAMDetect features as ML input."
            )

        X_fused_55 = np.column_stack([X, ae_errors]).astype(np.float32)

        rf_feature_names = list(getattr(self.rf_model, "feature_names", []) or [])
        rf_inner = getattr(self.rf_model, "model", None)
        rf_n_features = getattr(rf_inner, "n_features_in_", None)

        expected = EXPECTED_FUSED_FEATURES if STRICT_CIC54_EXPERIMENT else X_fused_55.shape[1]

        if rf_n_features is not None and int(rf_n_features) != expected:
            raise ValueError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: RF model expects "
                f"{rf_n_features} features, but the experiment requires {expected} "
                "(54 CIC features + AE reconstruction error). Retrain/load a CIC54 RF-AE model."
            )

        if rf_feature_names and len(rf_feature_names) != expected:
            raise ValueError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: RF feature_names length is "
                f"{len(rf_feature_names)}, but the experiment requires {expected}. "
                "Expanded/native RF models are not allowed for this run."
            )

        if X_fused_55.shape[1] != expected:
            raise ValueError(
                "EXP_CIC54_ML_ONLY_RF_AE guard failed: fused input length is "
                f"{X_fused_55.shape[1]}, expected {expected}."
            )

        return X_fused_55

    # ──────────────────────────────────────────────────────────────────────────
    # Public inference API
    # ──────────────────────────────────────────────────────────────────────────

    def predict(self, x: np.ndarray, features_dict: Optional[Dict] = None) -> Dict:
        """
        Classify a single 54-feature vector using Dai et al. (2024) RF-AE
        feature fusion.

        Final decision is ML-only when ML_ONLY_DECISION=True: forensic
        indicators are already part of the feature vector and may be shown in
        the report/UI, but they do not override, floor, bump, or dampen the
        RF score.

        Parameters
        ----------
        x             : (54,) or (1, 54) scaled canonical feature vector
        features_dict : optional raw feature name→value dictionary retained
                        for UI/report explainability. It does not affect the
                        verdict in ML-only mode.
        """
        self._check_loaded()
        if x.ndim == 1:
            x = x.reshape(1, -1)

        # 1. Get AE raw reconstruction error, used as Feature 55
        ae_error = float(self._ae_reconstruction_errors(x)[0])

        # 2. Build RF input. The FYP experiment requires exactly 54+AE=55 features.
        x_rf = self._build_rf_input(x, np.array([ae_error], dtype=np.float32))

        # 3. RF decision on the exact feature vector the RF was trained for
        rf_result    = self.rf_model.predict(x_rf)
        ml_label     = rf_result["label"]
        ml_score     = rf_result["suspicion_score"]
        confidence   = rf_result["confidence"]

        # 4. AE display score — use the model's own sigmoid normalization
        #    so it reads as a meaningful [0, 1] value rather than always 1.0
        ae_norm = float(self._ae_normalized_score(x)[0])

        # 5. ML-only decision
        # Final verdict is produced only by the RF over fused features:
        # [base ML features + AE reconstruction MSE].
        # Forensic indicators remain ML input features and explanation signals,
        # but they do NOT override, floor, bump, or dampen the ML score.
        final_score = ml_score
        final_label = ml_label

        return {
            "label":           final_label,
            "verdict":         VERDICT_MAP[final_label],
            "suspicion_score": round(final_score, 4),
            "confidence":      round(final_score * 100, 4),
            "rf_score":        round(ml_score, 4),
            "ae_score":        round(ae_norm, 4),
            "hybrid_score":    round(final_score, 4),
            "ae_error":        round(ae_error, 6),
            "primary_signal":  "ml_only_feature_fusion",
            "decision_mode":   "ml_only",
            "explanation":     self._explain(final_label, final_score, ae_error),
            "model":           "hybrid_dai_fusion",
        }

    def predict_batch(self, X: np.ndarray, features_dicts: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Classify a batch of 54-feature vectors using ML-only RF-AE fusion.

        Parameters
        ----------
        X              : (N, 54) scaled canonical feature matrix
        features_dicts : optional raw feature dictionaries for reporting only.
                         They do not affect verdicts in ML-only mode.
        """
        self._check_loaded()

        # 1. AE raw errors for Feature 55
        ae_errors = self._ae_reconstruction_errors(X)

        # 2. Build exact RF input. The FYP experiment requires 54+AE=55 features.
        X_rf = self._build_rf_input(X, ae_errors)

        # 3. RF decisions
        rf_results = self.rf_model.predict_batch(X_rf)

        # 4. AE display scores (sigmoid-normalized)
        ae_norms = self._ae_normalized_score(X)

        results = []
        for i in range(len(X)):
            res       = rf_results[i]
            ml_label  = res["label"]
            ml_score  = res["suspicion_score"]
            err       = float(ae_errors[i])
            ae_norm   = float(ae_norms[i])

            # 5. ML-only decision per sample
            # Raw feature dictionaries remain available to the report/UI, but
            # they do not modify the classification result.
            final_score = ml_score
            final_label = ml_label

            results.append({
                "label":           final_label,
                "verdict":         VERDICT_MAP[final_label],
                "suspicion_score": round(final_score, 4),
                "confidence":      round(final_score * 100, 4),
                "rf_score":        round(ml_score, 4),
                "ae_score":        round(ae_norm, 4),
                "hybrid_score":    round(final_score, 4),
                "ae_error":        round(err, 6),
                "primary_signal":  "ml_only_feature_fusion",
                "decision_mode":   "ml_only",
                "explanation":     self._explain(final_label, final_score, err),
                "model":           "hybrid_dai_fusion",
            })
        return results

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return (N, 2) probability array."""
        self._check_loaded()
        ae_errors = self._ae_reconstruction_errors(X)
        X_rf = self._build_rf_input(X, ae_errors)
        return self.rf_model.predict_proba(X_rf)

    # ──────────────────────────────────────────────────────────────────────────
    # Evaluation
    # ──────────────────────────────────────────────────────────────────────────

    def evaluate(self, X: np.ndarray, y: np.ndarray, split_name: str = "test") -> Dict:
        self._check_loaded()
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, roc_auc_score, confusion_matrix,
        )

        ae_errors = self._ae_reconstruction_errors(X)
        X_rf = self._build_rf_input(X, ae_errors)
        
        # Evaluate underlying RF on the exact feature vector it was trained for
        metrics = self.rf_model._evaluate(X_rf, y, split_name)
        
        print(f"\n{'=' * 62}")
        print(f"  DAI ET AL. (2024) FUSION EVALUATION  [{split_name.upper()}]")
        print(f"{'=' * 62}")
        print(f"  Accuracy  : {metrics['accuracy']:.4f}")
        print(f"  Precision : {metrics['precision']:.4f}")
        print(f"  Recall    : {metrics['recall']:.4f}")
        print(f"  F1 Score  : {metrics['f1']:.4f}")
        print(f"  AUC-ROC   : {metrics['auc_roc']:.4f}")
        print(f"\n  Confusion Matrix:")
        print(f"    TN={metrics['tn']:,}  FP={metrics['fp']:,}")
        print(f"    FN={metrics['fn']:,}  TP={metrics['tp']:,}")
        print("=" * 62)
        return metrics

    # ──────────────────────────────────────────────────────────────────────────
    # Info / introspection
    # ──────────────────────────────────────────────────────────────────────────

    def get_model_info(self) -> Dict:
        return {
            "type":           "Hybrid_Fusion",
            "architecture":   "ML-only AE MSE Fusion → RF (Dai et al. 2024)",
            "decision_mode":  "ml_only",
            "is_loaded":      self._is_loaded,
            "expected_base_features": EXPECTED_BASE_FEATURES,
            "expected_fused_features": EXPECTED_FUSED_FEATURES,
            "rf_info":        self.rf_model.get_model_info() if self.rf_model else {},
            "ae_info":        self.ae_model.get_model_info() if self.ae_model else {},
        }

    def _print_config(self) -> None:
        print(f"\n  Architecture  : Feature Fusion (54 CIC features + AE Error → RF)")
        print(f"  Experiment    : EXP_CIC54_ML_ONLY_RF_AE")
        print(f"  Decision      : RF.threshold = {self.rf_model.threshold}")
        print(f"  Guards        : base={EXPECTED_BASE_FEATURES}, fused={EXPECTED_FUSED_FEATURES}, ML-only")

    def _check_loaded(self) -> None:
        if not self._is_loaded:
            raise RuntimeError("Models not loaded. Call .load() first.")