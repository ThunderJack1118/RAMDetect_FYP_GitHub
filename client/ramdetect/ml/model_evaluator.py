"""
RAMDetect ML Pipeline — model_evaluator.py
===========================================
Official Phase 8 RF-AE evaluation module.

Evaluates RAMDetect's ML-only RF-AE feature-fusion stack:
    base feature vector  -> Autoencoder reconstruction MSE
    fused vector         -> Random Forest final verdict

This evaluator is dimension-aware. It supports both:
    canonical54: 54 base features + AE MSE = 55 fused RF features
    expanded:    88 base features + AE MSE = 89 fused RF features

No sequential filtering, T1/T2 gate, forensic veto, clean dampener, or
rule-based override is used here.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from ramdetect.ml.autoencoder_model import AutoencoderModel
from ramdetect.ml.dataset_loader import DatasetLoader
from ramdetect.ml.feature_mapper import FeatureMapper
from ramdetect.ml.hybrid_classifier import HybridClassifier
from ramdetect.ml.random_forest_model import RandomForestModel

logger = logging.getLogger(__name__)

SHORT_NAMES = ["CLEAN", "SUSPICIOUS"]


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ModelMetrics:
    model_name: str = ""
    split: str = "test"
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    auc_roc: float = 0.0
    confusion_matrix: List[List[int]] = field(default_factory=list)
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    support_per_class: List[int] = field(default_factory=list)
    inference_seconds: float = 0.0
    samples_per_second: float = 0.0
    classification_report: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class EvaluationReport:
    evaluated_at: str = ""
    total_seconds: float = 0.0
    n_samples: int = 0
    base_features: int = 0
    fused_features: int = 0
    feature_mode: str = ""
    class_distribution: Dict[str, int] = field(default_factory=dict)
    random_forest: Optional[ModelMetrics] = None
    autoencoder: Optional[ModelMetrics] = None
    hybrid: Optional[ModelMetrics] = None
    best_model: str = ""
    best_f1: float = 0.0
    best_auc: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def pretty(self) -> str:
        rows = [
            "=" * 72,
            "  RAMDetect — Phase 8 RF-AE Evaluation Report",
            "=" * 72,
            f"  Evaluated       : {self.evaluated_at}",
            f"  Duration        : {self.total_seconds:.2f}s",
            f"  Samples         : {self.n_samples:,}",
            f"  Feature mode    : {self.feature_mode}",
            f"  Base/Fused      : {self.base_features} / {self.fused_features}",
            f"  Class dist      : {self.class_distribution}",
            "",
            f"  {'Model':<18} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8} {'AUC':>8}",
            "  " + "─" * 64,
        ]
        for name, metrics in [
            ("Random Forest", self.random_forest),
            ("Autoencoder", self.autoencoder),
            ("Hybrid", self.hybrid),
        ]:
            if metrics is None:
                rows.append(f"  {name:<18} {'N/A':>9}")
                continue
            rows.append(
                f"  {name:<18} {metrics.accuracy:>9.4f} {metrics.precision:>10.4f} "
                f"{metrics.recall:>8.4f} {metrics.f1:>8.4f} {metrics.auc_roc:>8.4f}"
            )
        rows += [
            "",
            f"  Best model      : {self.best_model}",
            f"  Best F1 / AUC   : {self.best_f1:.4f} / {self.best_auc:.4f}",
            "=" * 72,
        ]
        return "\n".join(rows)


@dataclass
class EvaluatorConfig:
    models_dir: str = "models"
    rf_filename: str = "random_forest.pkl"
    ae_filename: str = "autoencoder.pkl"
    mapper_filename: str = "feature_mapper.pkl"
    report_filename: str = "evaluation_report.json"
    text_report_filename: str = "evaluation_report.txt"
    replay_filename: str = "evaluation_replay.csv"
    save_confusion_matrix_png: bool = True
    cm_png_filename: str = "confusion_matrices.png"
    verbose: int = 1


class ModelEvaluator:
    """Evaluate saved or in-memory RAMDetect RF-AE models."""

    def __init__(self, models_dir: Optional[str] = None, config: Optional[EvaluatorConfig] = None, **kwargs) -> None:
        self.cfg = config or EvaluatorConfig()
        if models_dir:
            self.cfg.models_dir = models_dir
        for key, value in kwargs.items():
            if not hasattr(self.cfg, key):
                raise ValueError(f"Unknown EvaluatorConfig field: {key}")
            setattr(self.cfg, key, value)

        level = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(self.cfg.verbose, logging.INFO)
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")

        self.mapper: Optional[FeatureMapper] = None
        self.rf_model: Optional[RandomForestModel] = None
        self.ae_model: Optional[AutoencoderModel] = None
        self.hybrid: Optional[HybridClassifier] = None
        self.report: Optional[EvaluationReport] = None

    @classmethod
    def from_trainer(cls, trainer: Any) -> "ModelEvaluator":
        obj = cls(models_dir=trainer.cfg.models_dir)
        obj.mapper = trainer.mapper
        obj.rf_model = trainer.rf_model
        obj.ae_model = trainer.ae_model
        obj.hybrid = trainer.hybrid
        return obj

    def _info(self, message: str) -> None:
        logger.info(message)
        if self.cfg.verbose >= 1:
            print(f"  ▸ {message}")

    def _load_artefacts(self) -> None:
        d = Path(self.cfg.models_dir)
        self._info(f"Loading FeatureMapper ← {d / self.cfg.mapper_filename}")
        self.mapper = FeatureMapper.load(d / self.cfg.mapper_filename)
        self._info(f"Loading RandomForestModel ← {d / self.cfg.rf_filename}")
        self.rf_model = RandomForestModel.load(d / self.cfg.rf_filename)
        self._info(f"Loading AutoencoderModel ← {d / self.cfg.ae_filename}")
        self.ae_model = AutoencoderModel.load(d / self.cfg.ae_filename)
        self.hybrid = HybridClassifier()
        self.hybrid.load_models_directly(self.rf_model, self.ae_model)

    @staticmethod
    def _metrics(model_name: str, y_true: np.ndarray, y_pred: np.ndarray, proba_pos: np.ndarray, elapsed: float) -> ModelMetrics:
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = [int(x) for x in cm.ravel()]
        try:
            auc = float(roc_auc_score(y_true, proba_pos))
        except ValueError:
            auc = 0.0
        n = max(len(y_true), 1)
        return ModelMetrics(
            model_name=model_name,
            accuracy=float(accuracy_score(y_true, y_pred)),
            precision=float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
            recall=float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
            f1=float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            auc_roc=auc,
            confusion_matrix=cm.tolist(),
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            true_positives=tp,
            false_positive_rate=float(fp / max(fp + tn, 1)),
            false_negative_rate=float(fn / max(fn + tp, 1)),
            support_per_class=[int(np.sum(y_true == 0)), int(np.sum(y_true == 1))],
            inference_seconds=float(elapsed),
            samples_per_second=float(n / max(elapsed, 1e-9)),
            classification_report=classification_report(
                y_true, y_pred, target_names=SHORT_NAMES, digits=4, zero_division=0
            ),
        )

    def _save_confusion_matrix_png(self, items: List[Tuple[str, ModelMetrics]]) -> Optional[str]:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except Exception:
            self._info("matplotlib unavailable — skipping confusion matrix PNG")
            return None

        fig, axes = plt.subplots(1, len(items), figsize=(6 * len(items), 5))
        if len(items) == 1:
            axes = [axes]
        for ax, (name, metric) in zip(axes, items):
            cm = np.array(metric.confusion_matrix)
            im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
            ax.set_title(name)
            ax.set_xticks([0, 1], SHORT_NAMES)
            ax.set_yticks([0, 1], SHORT_NAMES)
            ax.set_ylabel("True")
            ax.set_xlabel(f"Predicted\nAcc={metric.accuracy:.4f} F1={metric.f1:.4f}")
            threshold = cm.max() / 2.0 if cm.size else 0
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", color="white" if cm[i, j] > threshold else "black")
        fig.suptitle("RAMDetect Phase 8 RF-AE Confusion Matrices")
        plt.tight_layout()
        path = Path(self.cfg.models_dir) / self.cfg.cm_png_filename
        fig.savefig(path, bbox_inches="tight", dpi=150)
        plt.close(fig)
        return str(path)

    def run(self, X_test: np.ndarray, y_test: np.ndarray, feature_names: Optional[List[str]] = None) -> EvaluationReport:
        start = time.perf_counter()
        if self.mapper is None or self.rf_model is None or self.ae_model is None or self.hybrid is None:
            self._load_artefacts()
        assert self.mapper is not None and self.rf_model is not None and self.ae_model is not None and self.hybrid is not None

        if feature_names is not None:
            Xt = self.mapper.transform_cic(X_test, feature_names)
        else:
            Xt = X_test.astype(np.float32)

        ae_mse = self.ae_model._reconstruction_errors(Xt)
        X_fused = np.column_stack([Xt, ae_mse]).astype(np.float32)

        t0 = time.perf_counter()
        rf_results = self.rf_model.predict_batch(X_fused)
        rf_elapsed = time.perf_counter() - t0
        rf_pred = np.array([r["label"] for r in rf_results], dtype=np.int32)
        rf_proba = self.rf_model.predict_proba(X_fused)[:, 1]
        rf_metrics = self._metrics("Random Forest", y_test, rf_pred, rf_proba, rf_elapsed)

        t0 = time.perf_counter()
        ae_results = self.ae_model.predict_batch(Xt)
        ae_elapsed = time.perf_counter() - t0
        ae_pred = np.array([r["label"] for r in ae_results], dtype=np.int32)
        ae_proba = self.ae_model.predict_proba(Xt)[:, 1]
        ae_metrics = self._metrics("Autoencoder", y_test, ae_pred, ae_proba, ae_elapsed)

        t0 = time.perf_counter()
        hyb_results = self.hybrid.predict_batch(Xt)
        hyb_elapsed = time.perf_counter() - t0
        hyb_pred = np.array([r["label"] for r in hyb_results], dtype=np.int32)
        hyb_proba = self.hybrid.predict_proba(Xt)[:, 1]
        hyb_metrics = self._metrics("Hybrid", y_test, hyb_pred, hyb_proba, hyb_elapsed)

        unique, counts = np.unique(y_test, return_counts=True)
        class_dist = {str(int(k)): int(v) for k, v in zip(unique, counts)}
        ranked = sorted(
            [("Random Forest", rf_metrics), ("Autoencoder", ae_metrics), ("Hybrid", hyb_metrics)],
            key=lambda item: (item[1].f1, item[1].auc_roc),
            reverse=True,
        )
        best_name, best_metric = ranked[0]
        self.report = EvaluationReport(
            evaluated_at=_now_utc(),
            total_seconds=round(time.perf_counter() - start, 2),
            n_samples=int(len(y_test)),
            base_features=int(Xt.shape[1]),
            fused_features=int(X_fused.shape[1]),
            feature_mode=str(getattr(self.mapper, "feature_mode", "unknown")),
            class_distribution=class_dist,
            random_forest=rf_metrics,
            autoencoder=ae_metrics,
            hybrid=hyb_metrics,
            best_model=best_name,
            best_f1=round(best_metric.f1, 6),
            best_auc=round(best_metric.auc_roc, 6),
        )

        out = Path(self.cfg.models_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / self.cfg.report_filename).write_text(json.dumps(self.report.to_dict(), indent=2), encoding="utf-8")
        (out / self.cfg.text_report_filename).write_text(self.report.pretty(), encoding="utf-8")

        # Replay CSV for analyst verification.
        try:
            import pandas as pd
            pd.DataFrame({
                "row_index": np.arange(len(y_test)),
                "true_label": y_test.astype(int),
                "rf_score": rf_proba.astype(float),
                "ae_mse": ae_mse.astype(float),
                "ae_threshold": float(self.ae_model.threshold),
                "hybrid_score": hyb_proba.astype(float),
                "rf_pred": rf_pred.astype(int),
                "ae_pred": ae_pred.astype(int),
                "hybrid_pred": hyb_pred.astype(int),
            }).to_csv(out / self.cfg.replay_filename, index=False)
        except Exception as exc:
            self._info(f"Replay CSV skipped: {exc}")

        if self.cfg.save_confusion_matrix_png:
            self._save_confusion_matrix_png([
                ("Random Forest", rf_metrics),
                ("Autoencoder", ae_metrics),
                ("Hybrid", hyb_metrics),
            ])

        if self.cfg.verbose >= 1:
            print("\n" + self.report.pretty())
        return self.report

    def run_from_dataset(
        self,
        data_path: str,
        label_column: str = "Label",
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
    ) -> EvaluationReport:
        loader = DatasetLoader(data_path, verbose=(self.cfg.verbose >= 1))
        loader.load()
        loader.preprocess()
        splits = loader.split(test_size=test_size, val_size=val_size, random_state=random_state)
        X_test, y_test = splits["test"]
        return self.run(X_test=X_test, y_test=y_test, feature_names=loader.feature_names)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="RAMDetect Phase 8 ModelEvaluator")
    p.add_argument("--data", required=True, help="Labelled CSV dataset")
    p.add_argument("--models-dir", default="models")
    p.add_argument("--label-col", default="Label")
    p.add_argument("--test-size", type=float, default=0.15)
    p.add_argument("--val-size", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-cm-png", action="store_true")
    p.add_argument("--verbose", type=int, default=1, choices=[0, 1, 2])
    return p


def main(argv: Optional[List[str]] = None) -> EvaluationReport:
    args = _build_parser().parse_args(argv)
    evaluator = ModelEvaluator(
        config=EvaluatorConfig(
            models_dir=args.models_dir,
            save_confusion_matrix_png=not args.no_cm_png,
            verbose=args.verbose,
        )
    )
    return evaluator.run_from_dataset(
        data_path=args.data,
        label_column=args.label_col,
        test_size=args.test_size,
        val_size=args.val_size,
        random_state=args.seed,
    )


if __name__ == "__main__":
    main()
