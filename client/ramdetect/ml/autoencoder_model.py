"""
autoencoder_model.py - Autoencoder Anomaly Detector
====================================================
Phase 5, Module 4/8 — RAMDetect ML Pipeline

Unsupervised anomaly detection: CLEAN (0) vs SUSPICIOUS (1)

How it works:
  - Trained ONLY on CLEAN samples
  - Learns to compress and reconstruct normal memory feature vectors
  - At inference: high reconstruction error = anomalous = SUSPICIOUS
  - Complements Random Forest (catches zero-day / novel malware RF may miss)

Architecture:
  Input(N)  → Dense(...) encoder
            → Dense(...) decoder → Dense(N)

CHANGE vs previous version
--------------------------
threshold_percentile raised from 95 → 99.

With the 95th percentile, 5 % of clean CIC lab samples already cross the
threshold.  The CIC clean samples come from simple Windows 7 VMs; real
Windows 10/11 dumps look more complex and generate higher reconstruction
errors, making false-positive rates on real systems unacceptably high.

Raising to 99 gives a much tighter "inner fence" — only the top 1 % of
clean CIC errors cross the threshold, providing a much larger margin for
real-world clean dumps that sit above the CIC clean mean but are still
genuinely benign.

Usage:
    # Training (clean samples only)
    ae = AutoencoderModel()
    ae.train(X_train_clean, X_val_clean)
    ae.save("models/autoencoder.pkl")

    # Inference
    ae = AutoencoderModel.load("models/autoencoder.pkl")
    result = ae.predict(x)   # {"verdict": "SUSPICIOUS", "anomaly_score": 0.83}
"""

import logging
import pickle
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np

logger = logging.getLogger(__name__)

VERDICT_MAP = {0: "CLEAN", 1: "SUSPICIOUS"}


# ─────────────────────────────────────────────
# Default hyperparameters
# ─────────────────────────────────────────────

DEFAULT_PARAMS: Dict = {
    "encoding_dims": [32, 16, 8],
    "activation":    "relu",
    "dropout_rate":  0.1,
    "learning_rate": 0.001,
    "epochs":        50,
    "batch_size":    256,
    "patience":      5,
}

# ─────────────────────────────────────────────
# Default anomaly threshold percentile
#
# 99 (raised from 95) — only flag as SUSPICIOUS when reconstruction error
# exceeds the 99th percentile of errors seen on clean CIC training samples.
# This provides much more room for real-world Win10 dumps that look more
# complex than lab VMs but are still genuinely clean.
#
# If you still see false positives, try 99.5.
# If you miss known malware, lower toward 97.
# ─────────────────────────────────────────────
DEFAULT_THRESHOLD_PERCENTILE: float = 99.0


# ─────────────────────────────────────────────────────────────────────────────
# Deployment NumPy runtime for packaged Autoencoder inference
# ─────────────────────────────────────────────────────────────────────────────

class _NumpyAutoencoderRuntime:
    """Small inference-only Dense-network runner exported from autoencoder.keras.

    This is used only in packaged PyInstaller deployment when TensorFlow native
    DLLs cannot initialise. It does not retrain the model or change thresholds;
    it runs the same saved Dense weights with NumPy to compute reconstruction MSE.
    """

    def __init__(self, layers: List[Dict]):
        self.layers = layers

    @staticmethod
    def _activate(x: np.ndarray, name: str) -> np.ndarray:
        name = str(name or "linear").lower()
        if name == "relu":
            return np.maximum(x, 0.0)
        if name == "sigmoid":
            return 1.0 / (1.0 + np.exp(-np.clip(x, -60.0, 60.0)))
        if name in {"linear", "none"}:
            return x
        if name == "tanh":
            return np.tanh(x)
        raise ValueError(f"Unsupported NumPy AE activation: {name}")

    def predict(self, X: np.ndarray, verbose: int = 0) -> np.ndarray:
        out = np.asarray(X, dtype=np.float32)
        for layer in self.layers:
            W = np.asarray(layer["W"], dtype=np.float32)
            b = np.asarray(layer["b"], dtype=np.float32)
            out = out @ W + b
            out = self._activate(out, str(layer.get("activation", "linear")))
        return out.astype(np.float32)


def _numpy_ae_npz_path(pkl_path: Path) -> Path:
    return pkl_path.parent / "autoencoder_numpy_runtime.npz"


def _try_load_numpy_autoencoder_runtime(npz_path: Path):
    if not npz_path.exists():
        return None
    data = np.load(npz_path, allow_pickle=True)
    n_layers = int(data["n_layers"])
    layers: List[Dict] = []
    for i in range(n_layers):
        layers.append({
            "name": str(data[f"layer_{i}_name"]),
            "activation": str(data[f"layer_{i}_activation"]),
            "W": data[f"layer_{i}_W"].astype(np.float32),
            "b": data[f"layer_{i}_b"].astype(np.float32),
        })
    return _NumpyAutoencoderRuntime(layers)

class AutoencoderModel:
    """
    Autoencoder-based anomaly detector for RAM malware detection.

    Parameters
    ----------
    params    : Autoencoder architecture + training hyperparameters
    threshold : Reconstruction error threshold above which = SUSPICIOUS.
                If None, auto-calculated from clean training data (recommended).
    """

    def __init__(
        self,
        params:    Optional[Dict]  = None,
        threshold: Optional[float] = None,
    ):
        self.params    = params or DEFAULT_PARAMS.copy()
        self.threshold = threshold
        self.model     = None
        self.encoder   = None
        self.n_features:       int   = 0
        self.train_metrics:    Dict  = {}
        self.val_metrics:      Dict  = {}
        self._is_trained:      bool  = False
        self._training_time:   float = 0.0
        self._threshold_percentile: float = DEFAULT_THRESHOLD_PERCENTILE
        # Training error distribution — set by _fit_threshold(), used by anomaly_score()
        self.mse_train_max:  float = 0.1
        self.mse_train_mean: float = 0.0
        self.mse_train_std:  float = 0.01

    # ─────────────────────────────────────────
    # Build architecture
    # ─────────────────────────────────────────

    def _build(self, n_features: int):
        """Build encoder-decoder architecture using Keras."""
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers, regularizers
        except ImportError:
            raise ImportError(
                "TensorFlow not installed.\n"
                "Run: pip install tensorflow"
            )

        tf.random.set_seed(42)
        encoding_dims = self.params["encoding_dims"]
        act           = self.params["activation"]
        dropout_rate  = self.params["dropout_rate"]

        # ── Encoder ───────────────────────────────────────────
        inputs = keras.Input(shape=(n_features,), name="input")
        x = inputs
        for i, dim in enumerate(encoding_dims):
            x = layers.Dense(
                dim, activation=act,
                kernel_regularizer=regularizers.l2(1e-4),
                name=f"encoder_{i}",
            )(x)
            if dropout_rate > 0:
                x = layers.Dropout(dropout_rate, name=f"dropout_enc_{i}")(x)

        bottleneck = x

        # ── Decoder ───────────────────────────────────────────
        for i, dim in enumerate(reversed(encoding_dims[:-1])):
            x = layers.Dense(dim, activation=act, name=f"decoder_{i}")(x)
            if dropout_rate > 0:
                x = layers.Dropout(dropout_rate, name=f"dropout_dec_{i}")(x)

        outputs = layers.Dense(n_features, activation="sigmoid", name="output")(x)

        self.model = keras.Model(inputs, outputs, name="autoencoder")
        self.model.compile(
            optimizer=keras.optimizers.Adam(
                learning_rate=self.params["learning_rate"]
            ),
            loss="mse",
            metrics=["mae"],
        )

        self.encoder = keras.Model(inputs, bottleneck, name="encoder")
        logger.info(f"Autoencoder built: {n_features} → {encoding_dims} → {n_features}")

    # ─────────────────────────────────────────
    # Training
    # ─────────────────────────────────────────

    def train(
        self,
        X_train: np.ndarray,
        X_val:   Optional[np.ndarray] = None,
        y_train: Optional[np.ndarray] = None,
        y_val:   Optional[np.ndarray] = None,
        threshold_percentile: float = DEFAULT_THRESHOLD_PERCENTILE,
    ) -> "AutoencoderModel":
        """
        Train autoencoder on CLEAN samples only.

        Parameters
        ----------
        X_train, X_val       : Feature matrices from FeatureMapper
        y_train, y_val       : Labels — if provided, only clean (y=0) samples
                               are used for training (recommended)
        threshold_percentile : Percentile of clean reconstruction errors used
                               to set the anomaly threshold (default 99)
        """
        try:
            from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
        except ImportError:
            raise ImportError("TensorFlow not installed. Run: pip install tensorflow")

        self._threshold_percentile = threshold_percentile
        self.n_features = X_train.shape[1]

        # ── Filter to clean samples only ──────────────────────
        if y_train is not None:
            X_clean = X_train[y_train == 0]
            logger.info(f"Using {len(X_clean):,} clean samples for training "
                        f"(filtered from {len(X_train):,} total)")
        else:
            X_clean = X_train
            logger.info(f"No labels provided — using all {len(X_clean):,} samples")

        X_val_clean = None
        if X_val is not None and y_val is not None:
            X_val_clean = X_val[y_val == 0]
        elif X_val is not None:
            X_val_clean = X_val

        print("\n" + "=" * 60)
        print("  🔮 TRAINING AUTOENCODER")
        print("=" * 60)
        print(f"  Clean training samples  : {len(X_clean):,}")
        print(f"  Features                : {self.n_features}")
        print(f"  Architecture            : {self.n_features} → "
              f"{self.params['encoding_dims']} → {self.n_features}")
        print(f"  Epochs                  : {self.params['epochs']}")
        print(f"  Batch size              : {self.params['batch_size']}")
        print(f"  Early stopping patience : {self.params['patience']}")
        print(f"  Threshold percentile    : {threshold_percentile}th  "
              f"(raised from 95 → {threshold_percentile} to reduce false positives)")
        print("  Training...")

        self._build(self.n_features)

        callbacks = [
            EarlyStopping(
                monitor="val_loss" if X_val_clean is not None else "loss",
                patience=self.params["patience"],
                restore_best_weights=True,
                verbose=1,
            ),
            ReduceLROnPlateau(
                monitor="val_loss" if X_val_clean is not None else "loss",
                factor=0.5,
                patience=3,
                min_lr=1e-6,
                verbose=0,
            ),
        ]

        t0 = time.time()
        validation_data = (X_val_clean, X_val_clean) if X_val_clean is not None else None

        history = self.model.fit(
            X_clean, X_clean,
            epochs=self.params["epochs"],
            batch_size=self.params["batch_size"],
            validation_data=validation_data,
            callbacks=callbacks,
            verbose=1,
        )
        self._training_time = time.time() - t0
        self._is_trained = True

        self._fit_threshold(X_clean, threshold_percentile)

        self.train_metrics = {
            "final_loss": round(float(history.history["loss"][-1]), 6),
            "epochs_run": len(history.history["loss"]),
            "threshold":  round(self.threshold, 6),
        }
        if X_val_clean is not None and "val_loss" in history.history:
            self.train_metrics["final_val_loss"] = round(
                float(history.history["val_loss"][-1]), 6
            )

        self._print_train_summary()
        return self

    def _fit_threshold(self, X_clean: np.ndarray, percentile: float):
        """Set anomaly threshold = Nth percentile of clean reconstruction errors.
        
        Also stores mse_train_max and mse_train_mean so anomaly_score() can
        produce a properly calibrated [0, 1] display value instead of always
        saturating at 1.0 for any real-world dump.
        """
        errors = self._reconstruction_errors(X_clean)
        self.threshold       = float(np.percentile(errors, percentile))
        self.mse_train_max   = float(np.max(errors))
        self.mse_train_mean  = float(np.mean(errors))
        self.mse_train_std   = float(np.std(errors))
        logger.info(
            "Anomaly threshold set to %.6f (%gth pct of clean errors, n=%d)  "
            "mean=%.6f  max=%.6f",
            self.threshold, percentile, len(errors),
            self.mse_train_mean, self.mse_train_max,
        )

    # ─────────────────────────────────────────
    # Inference
    # ─────────────────────────────────────────

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample mean squared reconstruction error."""
        X_reconstructed = self.model.predict(X, verbose=0)
        errors = np.mean(np.square(X - X_reconstructed), axis=1)
        return errors.astype(np.float32)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Return anomaly scores in [0, 1] for a batch.
          0.0 = perfectly reconstructed (CLEAN)
          1.0 = maximum anomaly (SUSPICIOUS)

        Normalization is range-aware: errors at or below the threshold score
        below 0.5, errors well above the training max score near 1.0.  This
        prevents the display from always saturating at 100% for real-world
        dumps that simply have higher ambient complexity than sandbox VMs.

        Sigmoid over (error - threshold) / (train_std + 1e-8) centres the
        decision boundary at the threshold and spreads the scale using the
        natural variance of clean training errors.
        """
        self._check_trained()
        errors = self._reconstruction_errors(X)
        # Centre at threshold; spread by training std so ±2σ maps to ~0.12–0.88
        thr = self.threshold
        std = max(self.mse_train_std, 1e-8)
        z = (errors - thr) / std
        scores = 1.0 / (1.0 + np.exp(-z))   # sigmoid
        return np.clip(scores, 0.0, 1.0).astype(np.float32)

    def predict(self, x: np.ndarray) -> Dict:
        """
        Classify a single feature vector.

        Returns
        -------
        {
            "label":                int,
            "verdict":              str,
            "suspicion_score":      float,
            "recon_error":          float,
            "reconstruction_error": float,   # alias for ml_bridge
            "threshold":            float,
            "error_ratio":          float,
            "model":                str,
        }
        """
        self._check_trained()
        if x.ndim == 1:
            x = x.reshape(1, -1)

        error = float(self._reconstruction_errors(x)[0])
        score = float(self.anomaly_score(x)[0])
        label = 1 if error >= self.threshold else 0

        return {
            "label":                label,
            "verdict":              VERDICT_MAP[label],
            "suspicion_score":      round(score, 4),
            "confidence":           round(score * 100, 4),
            "recon_error":          round(error, 6),
            "reconstruction_error": round(error, 6),
            "threshold":            round(self.threshold, 6),
            "error_ratio":          round(error / (self.threshold + 1e-8), 4),
            "model":                "autoencoder",
        }

    def predict_batch(self, X: np.ndarray) -> List[Dict]:
        """Classify a batch of feature vectors."""
        self._check_trained()
        errors = self._reconstruction_errors(X)
        scores = self.anomaly_score(X)
        results = []
        for error, score in zip(errors, scores):
            label = 1 if error >= self.threshold else 0
            results.append({
                "label":           label,
                "verdict":         VERDICT_MAP[label],
                "suspicion_score": round(float(score), 4),
                "recon_error":     round(float(error), 6),
                "threshold":       round(self.threshold, 6),
                "model":           "autoencoder",
            })
        return results

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return (N, 2) probability-like array for hybrid_classifier.py."""
        self._check_trained()
        suspicious_scores = self.anomaly_score(X)
        clean_scores = 1.0 - suspicious_scores
        return np.column_stack([clean_scores, suspicious_scores]).astype(np.float32)

    def encode(self, X: np.ndarray) -> np.ndarray:
        """Return latent space representation."""
        self._check_trained()
        return self.encoder.predict(X, verbose=0)

    # ─────────────────────────────────────────
    # Evaluation
    # ─────────────────────────────────────────

    def evaluate(self, X: np.ndarray, y: np.ndarray, split_name: str = "test") -> Dict:
        self._check_trained()
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, roc_auc_score, confusion_matrix,
        )

        scores = self.anomaly_score(X)
        preds  = (scores >= 0.5).astype(int)

        metrics = {
            "accuracy":  round(accuracy_score(y, preds), 4),
            "precision": round(precision_score(y, preds, zero_division=0), 4),
            "recall":    round(recall_score(y, preds, zero_division=0), 4),
            "f1":        round(f1_score(y, preds, zero_division=0), 4),
            "auc_roc":   round(roc_auc_score(y, scores), 4),
        }
        cm = confusion_matrix(y, preds)
        metrics.update({
            "confusion_matrix": cm.tolist(),
            "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
            "fn": int(cm[1, 0]), "tp": int(cm[1, 1]),
        })

        print(f"\n  [{split_name.upper()}]")
        print(f"  Accuracy  : {metrics['accuracy']:.4f}")
        print(f"  Precision : {metrics['precision']:.4f}")
        print(f"  Recall    : {metrics['recall']:.4f}")
        print(f"  F1 Score  : {metrics['f1']:.4f}")
        print(f"  AUC-ROC   : {metrics['auc_roc']:.4f}")
        print(f"  Confusion Matrix:")
        print(f"    TN={metrics['tn']:,}  FP={metrics['fp']:,}")
        print(f"    FN={metrics['fn']:,}  TP={metrics['tp']:,}")
        return metrics

    def get_feature_errors(self, x: np.ndarray) -> Dict[str, float]:
        """Per-feature reconstruction error (for explainability)."""
        self._check_trained()
        if x.ndim == 1:
            x = x.reshape(1, -1)
        x_recon = self.model.predict(x, verbose=0)
        per_feature = np.square(x - x_recon)[0]

        try:
            from ramdetect.ml.feature_mapper import CANONICAL_FEATURES, EXPANDED_FEATURES
            if len(EXPANDED_FEATURES) == len(per_feature):
                names = EXPANDED_FEATURES
            elif len(CANONICAL_FEATURES) == len(per_feature):
                names = CANONICAL_FEATURES
            else:
                names = [f"feature_{i}" for i in range(len(per_feature))]
        except ImportError:
            names = [f"feature_{i}" for i in range(len(per_feature))]

        error_dict = {name: round(float(err), 6)
                      for name, err in zip(names, per_feature)}
        return dict(sorted(error_dict.items(), key=lambda kv: kv[1], reverse=True))

    # ─────────────────────────────────────────
    # Save / Load
    # ─────────────────────────────────────────

    def save(self, path: Union[str, Path]) -> None:
        self._check_trained()
        out = Path(path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        # Save keras weights alongside the pkl file.
        # We store ONLY the basename (e.g. "autoencoder.keras"), never an absolute
        # path.  This means the pair can be moved to any directory and load()
        # will still find the weights by resolving relative to the new pkl location.
        keras_path = out.with_suffix(".keras")
        self.model.save(keras_path)

        meta = {
            "params":          self.params,
            "threshold":       self.threshold,
            "n_features":      self.n_features,
            "train_metrics":   self.train_metrics,
            "training_time":   self._training_time,
            "threshold_pct":   self._threshold_percentile,
            "mse_train_max":   self.mse_train_max,
            "mse_train_mean":  self.mse_train_mean,
            "mse_train_std":   self.mse_train_std,
            # Store ONLY the filename so the pair survives being moved.
            # Legacy absolute-path pickles are handled in load() below.
            "keras_filename":  keras_path.name,
            "version":         "1.3",
        }
        with open(out, "wb") as f:
            pickle.dump(meta, f)

        logger.info(f"AutoencoderModel saved → {out}")
        print(f"  💾 AutoencoderModel saved: {out}")
        print(f"  💾 Keras weights saved  : {keras_path}")

    @classmethod
    def load(cls, path: Union[str, Path]) -> "AutoencoderModel":
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Model not found: {p}")

        with open(p, "rb") as f:
            meta = pickle.load(f)

        obj = cls(params=meta["params"], threshold=meta["threshold"])
        obj.n_features            = meta["n_features"]
        obj.train_metrics         = meta["train_metrics"]
        obj._training_time        = meta["training_time"]
        obj._threshold_percentile = meta["threshold_pct"]
        obj.mse_train_max  = float(meta.get("mse_train_max",  obj.threshold * 3))
        obj.mse_train_mean = float(meta.get("mse_train_mean", 0.0))
        obj.mse_train_std  = float(meta.get("mse_train_std",  obj.threshold * 0.5))

        # Deployment fallback: prefer the exported NumPy AE runtime in a frozen
        # PyInstaller application. This avoids TensorFlow native DLL initialisation
        # failures while preserving the same saved AE weights and MSE calculation.
        npz_path = _numpy_ae_npz_path(p)
        force_tf = str(__import__("os").environ.get("RAMDETECT_FORCE_TENSORFLOW_AE", "")).lower() in {"1", "true", "yes", "on"}
        prefer_numpy = str(__import__("os").environ.get("RAMDETECT_AE_NUMPY_RUNTIME", "")).lower() in {"1", "true", "yes", "on"}

        if not force_tf and npz_path.exists():
            try:
                obj.model = _try_load_numpy_autoencoder_runtime(npz_path)
                if obj.model is not None:
                    obj.encoder = None
                    obj._is_trained = True
                    logger.info("AutoencoderModel loaded with NumPy runtime ← %s", npz_path)
                    print(f"  ✅ Autoencoder loaded with NumPy runtime  threshold={obj.threshold:.6f}  "
                          f"({obj._threshold_percentile}th pct)")
                    return obj
            except Exception as exc:
                if prefer_numpy:
                    raise RuntimeError(f"Failed to load NumPy autoencoder runtime: {exc}") from exc
                logger.warning("NumPy autoencoder runtime failed; falling back to TensorFlow: %s", exc)

        # Standard training/development path: use TensorFlow/Keras.
        try:
            import tensorflow as tf
        except Exception as exc:
            raise ImportError(
                "TensorFlow failed to import and no usable NumPy AE runtime was available. "
                f"Expected NumPy runtime file: {npz_path}"
            ) from exc

        # ── Resolve keras weights path ────────────────────────────────────────
        if "keras_filename" in meta:
            keras_path = p.parent / meta["keras_filename"]
        elif "keras_path" in meta:
            abs_path = Path(meta["keras_path"])
            if abs_path.exists():
                keras_path = abs_path
            else:
                keras_path = p.parent / abs_path.name
                logger.warning(
                    "Legacy absolute keras_path '%s' not found; trying '%s' instead.",
                    abs_path, keras_path,
                )
        else:
            keras_path = p.with_suffix(".keras")

        if not keras_path.exists():
            raise FileNotFoundError(
                f"Keras weights not found: {keras_path}\n"
                f"  PKL file location : {p}\n"
                f"  Expected weights  : {keras_path}\n"
                "  Make sure the .keras file is in the same folder as the .pkl."
            )

        obj.model       = tf.keras.models.load_model(keras_path)
        obj._is_trained = True
        obj._rebuild_encoder()
        logger.info(f"AutoencoderModel loaded ← {p}  (threshold={obj.threshold:.6f})")
        print(f"  ✅ Autoencoder loaded  threshold={obj.threshold:.6f}  "
              f"({obj._threshold_percentile}th pct)")
        return obj

    def _rebuild_encoder(self):
        try:
            self.encoder = self.model.get_layer("encoder")
        except ValueError:
            import tensorflow as tf
            bottleneck_layer = None
            for layer in self.model.layers:
                if "encoder_" in layer.name:
                    bottleneck_layer = layer
            if bottleneck_layer:
                self.encoder = tf.keras.Model(
                    self.model.input,
                    bottleneck_layer.output,
                    name="encoder",
                )

    # ─────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────

    def _check_trained(self):
        if not self._is_trained or self.model is None:
            raise RuntimeError("Model not trained. Call .train() first.")

    def _print_train_summary(self):
        m = self.train_metrics
        print(f"\n  ✅ Training complete in {self._training_time:.1f}s")
        print(f"  Epochs run         : {m.get('epochs_run')}")
        print(f"  Final train loss   : {m.get('final_loss'):.6f}")
        if "final_val_loss" in m:
            print(f"  Final val loss     : {m.get('final_val_loss'):.6f}")
        print(f"  Anomaly threshold  : {m.get('threshold'):.6f} "
              f"({self._threshold_percentile}th percentile of clean errors)")

    def get_model_info(self) -> Dict:
        return {
            "type":          "Autoencoder",
            "is_trained":    self._is_trained,
            "architecture":  self.params.get("encoding_dims"),
            "threshold":     self.threshold,
            "threshold_pct": self._threshold_percentile,
            "n_features":    self.n_features,
            "train_metrics": self.train_metrics,
            "training_time": round(self._training_time, 2),
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
        print("Usage: python autoencoder_model.py <path/to/CIC-MalMem-2022.csv>")
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

    ae = AutoencoderModel()
    ae.train(X_train, X_val, y_train=y_train, y_val=y_val)

    print("\n" + "=" * 60)
    print("  🧪 TEST SET EVALUATION")
    print("=" * 60)
    ae.evaluate(X_test, y_test, "test")

    result = ae.predict(X_test[0:1])
    actual = "CLEAN" if y_test[0] == 0 else "SUSPICIOUS"
    print(f"\n  Sample prediction : {result['verdict']}  (actual: {actual})")
    print(f"  Anomaly score     : {result['suspicion_score']}")
    print(f"  Recon error       : {result['recon_error']}")
    print(f"  Threshold         : {result['threshold']}")

    ae.save("models/autoencoder.pkl")
    print("\n✅ autoencoder_model.py working correctly!")
