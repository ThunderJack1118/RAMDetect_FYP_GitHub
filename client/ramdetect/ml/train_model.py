"""
RAMDetect ML Pipeline — train_model.py
======================================
Official CLI entry point for training/evaluating RAMDetect's Phase 8 RF-AE
model.

The training engine remains in ramdetect.ml.model_trainer.ModelTrainer. This
file should stay as the command-line wrapper only.

Examples
--------
Train RAMDetect RF-AE artefacts into models/:

    python ramdetect/ml/train_model.py full \
        --data models/experiments/Phase8_expanded_rf_ae/expanded_feature_dataset.csv \
        --models-dir models \
        --feature-mode expanded \
        --allow-small-sample \
        --ae-epochs 80 \
        --ae-batch 16

Evaluate existing official artefacts:

    python ramdetect/ml/train_model.py evaluate \
        --data models/experiments/Phase8_expanded_rf_ae/expanded_feature_dataset.csv \
        --models-dir models \
        --feature-mode expanded
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Ensure project root is importable when run as a plain script.
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ramdetect.ml.model_trainer import ModelTrainer, TrainerConfig

logger = logging.getLogger("ramdetect.train_model")

_BANNER = r"""
  ██████╗  █████╗ ███╗   ███╗██████╗ ███████╗████████╗███████╗ ██████╗████████╗
  ██╔══██╗██╔══██╗████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝███████║██╔████╔██║██║  ██║█████╗     ██║   █████╗  ██║        ██║
  ██╔══██╗██╔══██║██║╚██╔╝██║██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║
  ██║  ██║██║  ██║██║ ╚═╝ ██║██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝
       RAMDetect RF-AE Feature Fusion Training CLI
"""


def _print_banner() -> None:
    print(_BANNER)


def _section(title: str, width: int = 72) -> None:
    print(f"\n{'═' * width}\n  {title}\n{'═' * width}")


def _done(msg: str) -> None:
    print(f"\n  ✔  {msg}")


def _fail(msg: str) -> None:
    print(f"\n  ✖  {msg}", file=sys.stderr)


def _check_imports() -> bool:
    ok = True
    packages = {
        "numpy": "numpy",
        "pandas": "pandas",
        "sklearn": "scikit-learn",
        "tensorflow": "tensorflow",
        "joblib": "joblib",
    }
    for mod, display in packages.items():
        try:
            __import__(mod)
            print(f"  ▸ {display:<24} ✔")
        except ImportError:
            _fail(f"Missing required package: {display}")
            ok = False
    return ok


def _preflight(args: argparse.Namespace) -> bool:
    ok = True
    if args.mode in {"train", "full", "evaluate"}:
        data = Path(args.data)
        if not data.is_file():
            _fail(f"Dataset not found: {data}")
            ok = False
        else:
            print(f"  ▸ Dataset       : {data} ({data.stat().st_size / 1_048_576:.2f} MB)")

    if args.mode == "evaluate":
        for name in ("feature_mapper.pkl", "random_forest.pkl", "autoencoder.pkl"):
            p = Path(args.models_dir) / name
            if not p.is_file():
                _fail(f"Required artefact not found: {p}")
                ok = False
            else:
                print(f"  ▸ Artefact      : {p}")

    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        _fail(f"Python 3.10+ required; found {major}.{minor}")
        ok = False
    else:
        print(f"  ▸ Python        : {major}.{minor}.{sys.version_info.micro}")

    ok = _check_imports() and ok
    print(f"  ▸ Models dir    : {args.models_dir}")
    return ok


def _build_config(args: argparse.Namespace) -> TrainerConfig:
    return TrainerConfig(
        data_path=args.data,
        label_column=args.label_col,
        feature_mode=args.feature_mode,
        allow_small_sample=args.allow_small_sample,
        test_size=args.test_size,
        val_size=args.val_size,
        random_state=args.seed,
        models_dir=args.models_dir,
        rf_n_estimators=args.rf_trees,
        rf_max_depth=None if args.rf_max_depth < 0 else args.rf_max_depth,
        rf_max_features=args.rf_max_features,
        rf_min_samples_split=args.rf_min_split,
        rf_min_samples_leaf=args.rf_min_leaf,
        rf_n_jobs=args.rf_jobs,
        rf_class_weight=args.rf_class_weight,
        ae_encoding_dim=args.ae_encoding_dim,
        ae_hidden_layers=args.ae_hidden,
        ae_epochs=args.ae_epochs,
        ae_batch_size=args.ae_batch,
        ae_learning_rate=args.ae_lr,
        ae_dropout_rate=args.ae_dropout,
        ae_patience=args.ae_patience,
        ae_threshold_percentile=args.ae_threshold_pct,
        t1_percentile=args.t1_percentile,
        t2_percentile=args.t2_percentile,
        verbose=args.verbose,
        save_training_report=True,
    )



def _save_confusion_matrix_png_from_replay(
    replay_path: str | Path,
    output_path: str | Path | None = None,
    title: str = "RAMDetect RF-AE Confusion Matrix",
) -> Optional[Path]:
    """Create a confusion-matrix PNG from a replay CSV.

    The replay CSV must contain:
        - true_label: ground-truth class, where 0=CLEAN and 1=SUSPICIOUS
        - prediction: model prediction, where 0=CLEAN and 1=SUSPICIOUS

    This function is used only for training/evaluation reporting. It does not
    change model training, RF thresholding, or RAMDetect's ML-only verdict logic.
    """
    replay = Path(replay_path)
    if not replay.is_file():
        logger.warning("Replay CSV not found; skipping confusion matrix: %s", replay)
        return None

    try:
        import pandas as pd
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import accuracy_score, confusion_matrix
    except Exception as exc:  # pragma: no cover - depends on optional plotting libs
        logger.warning("Could not import confusion-matrix dependencies: %s", exc)
        return None

    df = pd.read_csv(replay)
    required = {"true_label", "prediction"}
    missing = required.difference(df.columns)
    if missing:
        logger.warning("Replay CSV missing required columns %s; skipping confusion matrix", sorted(missing))
        return None

    y_true = df["true_label"].astype(int).to_numpy()
    y_pred = df["prediction"].astype(int).to_numpy()
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    accuracy = accuracy_score(y_true, y_pred)

    out = Path(output_path) if output_path else replay.with_name(f"{replay.stem}_confusion_matrix.png")
    out.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(5.6, 4.8))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)

    labels = ["CLEAN", "SUSPICIOUS"]
    ax.set_title(title)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(labels)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(labels)
    ax.set_xlabel(f"Predicted Label\nAccuracy = {accuracy:.4f}")
    ax.set_ylabel("True Label")

    threshold = cm.max() / 2.0 if cm.size else 0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j,
                i,
                f"{cm[i, j]:,}",
                ha="center",
                va="center",
                color="white" if cm[i, j] > threshold else "black",
                fontsize=12,
                fontweight="bold",
            )

    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out

def run_train(args: argparse.Namespace) -> ModelTrainer:
    _section("Training Pipeline")
    trainer = ModelTrainer(config=_build_config(args))
    report = trainer.run()

    replay = report.artefacts.get("training_replay") if report else None
    if replay:
        cm_path = _save_confusion_matrix_png_from_replay(
            replay,
            title="RAMDetect RF-AE Training Confusion Matrix",
        )
        if cm_path:
            report.artefacts["training_confusion_matrix_png"] = str(cm_path)
            report_path = report.artefacts.get("training_report")
            if report_path:
                import json
                Path(report_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
            print(f"  ▸ Confusion matrix: {cm_path}")

    return trainer


def run_evaluate(args: argparse.Namespace) -> None:
    _section("Evaluation Pipeline")
    trainer = ModelTrainer(config=_build_config(args))
    report = trainer.evaluate_dataset()

    replay = report.get("artefacts", {}).get("evaluation_replay")
    if replay:
        cm_path = _save_confusion_matrix_png_from_replay(
            replay,
            title="RAMDetect RF-AE Evaluation Confusion Matrix",
        )
        if cm_path:
            report["artefacts"]["evaluation_confusion_matrix_png"] = str(cm_path)
            report_path = report.get("artefacts", {}).get("evaluation_report")
            if report_path:
                import json
                Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nEvaluation metrics:")
    for k, v in report["metrics"].items():
        print(f"  {k}: {v}")
    print("\nSaved:")
    for k, v in report["artefacts"].items():
        print(f"  {k}: {v}")


def _build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="train_model.py",
        description="RAMDetect RF-AE training/evaluation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = root.add_subparsers(dest="mode")
    sub.add_parser("train", help="Train RF-AE and save artefacts")
    sub.add_parser("evaluate", help="Evaluate saved artefacts on a labelled dataset")
    sub.add_parser("full", help="Train and write full training report (default)")

    root.add_argument("--data", "-d", default="models/experiments/Phase8_expanded_rf_ae/expanded_feature_dataset.csv")
    root.add_argument("--label-col", default="Label")
    root.add_argument("--feature-mode", default="expanded", choices=["expanded", "canonical54", "auto"])
    root.add_argument("--allow-small-sample", action="store_true", help="Use all rows for train/val/test when dataset is tiny")
    root.add_argument("--test-size", type=float, default=0.15)
    root.add_argument("--val-size", type=float, default=0.15)
    root.add_argument("--seed", "-s", type=int, default=42)
    root.add_argument("--models-dir", "-o", default="models")

    rf = root.add_argument_group("Random Forest")
    rf.add_argument("--rf-trees", type=int, default=300)
    rf.add_argument("--rf-max-depth", type=int, default=-1, help="-1 means None/unlimited")
    rf.add_argument("--rf-max-features", default="sqrt", choices=["sqrt", "log2", "auto"])
    rf.add_argument("--rf-min-split", type=int, default=2)
    rf.add_argument("--rf-min-leaf", type=int, default=1)
    rf.add_argument("--rf-jobs", type=int, default=-1)
    rf.add_argument("--rf-class-weight", default="balanced", choices=["balanced", "balanced_subsample", "none"])

    ae = root.add_argument_group("Autoencoder")
    ae.add_argument("--ae-hidden", type=int, nargs="+", default=[64, 32])
    ae.add_argument("--ae-encoding-dim", type=int, default=16)
    ae.add_argument("--ae-epochs", type=int, default=80)
    ae.add_argument("--ae-batch", type=int, default=16)
    ae.add_argument("--ae-lr", type=float, default=1e-3)
    ae.add_argument("--ae-dropout", type=float, default=0.1)
    ae.add_argument("--ae-patience", type=int, default=10)
    ae.add_argument("--ae-threshold-pct", type=float, default=99.0)

    legacy = root.add_argument_group("Legacy compatibility arguments — unused in ML-only RF-AE fusion")
    legacy.add_argument("--t1-percentile", type=float, default=90.0)
    legacy.add_argument("--t2-percentile", type=float, default=75.0)

    root.add_argument("--verbose", "-v", type=int, default=1, choices=[0, 1, 2])
    root.add_argument("--skip-preflight", action="store_true")
    return root


def _validate_args(args: argparse.Namespace) -> None:
    errors: List[str] = []
    if not 0.0 < args.test_size < 1.0:
        errors.append("--test-size must be in (0, 1)")
    if not 0.0 < args.val_size < 1.0:
        errors.append("--val-size must be in (0, 1)")
    if args.test_size + args.val_size >= 1.0:
        errors.append("--test-size + --val-size must be < 1")
    if args.ae_lr <= 0:
        errors.append("--ae-lr must be positive")
    if not 50.0 <= args.ae_threshold_pct <= 100.0:
        errors.append("--ae-threshold-pct must be in [50, 100]")
    if errors:
        for e in errors:
            _fail(e)
        sys.exit(1)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.mode is None:
        args.mode = "full"

    logging.basicConfig(
        level={0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(args.verbose, logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.verbose >= 1:
        _print_banner()
    print(f"  Mode      : {args.mode.upper()}")
    print(f"  Started   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Data      : {args.data}")
    print(f"  Models dir: {args.models_dir}")
    print(f"  Feature   : {args.feature_mode}")
    print(f"  Seed      : {args.seed}")

    _validate_args(args)
    if not args.skip_preflight:
        _section("Pre-flight Checks")
        if not _preflight(args):
            _fail("Pre-flight checks failed. Aborting.")
            return 1
        _done("All pre-flight checks passed.")

    wall_start = time.perf_counter()
    exit_code = 0
    try:
        if args.mode in {"train", "full"}:
            run_train(args)
            _done("Training complete.")
        elif args.mode == "evaluate":
            run_evaluate(args)
            _done("Evaluation complete.")
        else:
            _fail(f"Unknown mode: {args.mode}")
            exit_code = 1
    except KeyboardInterrupt:
        print("\n\n  ⚠  Interrupted by user.", file=sys.stderr)
        exit_code = 130
    except Exception as exc:  # pylint: disable=broad-except
        _fail(f"Unexpected error: {exc}")
        if args.verbose >= 2:
            traceback.print_exc()
        logger.exception("Unhandled exception in train_model.py")
        exit_code = 1
    finally:
        elapsed = time.perf_counter() - wall_start
        status = "SUCCESS" if exit_code == 0 else "FAILED"
        print(f"\n  {'─' * 66}\n  Status    : {status}\n  Wall time : {elapsed:.1f}s\n  {'─' * 66}\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
