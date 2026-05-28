"""
dataset_loader.py - Universal Dataset Loader (CIC-MalMem-2022 + MemMal-D2024)
==============================================================================
Phase 5, Module 1/8 — RAMDetect ML Pipeline

CHANGES vs CIC-only version
----------------------------
• Auto-detects dataset type (CIC-MalMem-2022 vs MemMal-D2024) from the CSV
  header — no manual flag needed.
• MemMal-D2024 support:
    - Label column: "Label"  (CIC used "Class")
    - Temporal column: "Date" stripped before training
    - Additional malware family keywords (Worm, Backdoor, Miner, etc.)
    - Multiclass labels collapsed to binary (Benign=0, anything else=1)
• Convenience factory: load_malmem_d2024()
• load_cic_malmem() kept for backward compatibility — points to the same
  DatasetLoader, just with CIC-style defaults.
• All print headers updated to show actual dataset name.

CIC-MalMem-2022 Info:
  Source  : Canadian Institute for Cybersecurity
  Samples : ~58,596
  Features: 58 Volatility-based features
  Label   : "Class"  (Benign / Ransomware / Spyware / Trojan)

MemMal-D2024 Info:
  Source  : github.com/mpasco/MemMal-D2024
  Samples : ~178,000+ (temporal splits 2006-2021)
  Features: Same 58 Volatility-based features + "Date" temporal column
  Label   : "Label"  (Benign / Ransomware / Trojan / Worm / Rootkit / …)
  Key advantage: temporal evaluation support (training on older, testing on newer)

Usage:
    # MemMal-D2024 (recommended):
    loader, splits = load_malmem_d2024("datasets/MemMal-D2024-combined.csv")

    # CIC-MalMem-2022 (legacy):
    loader, splits = load_cic_malmem("datasets/CIC-MalMem-2022.csv")

    # Generic (auto-detects):
    loader = DatasetLoader("datasets/MemMal-D2024-combined.csv")
    loader.load().preprocess()
    splits = loader.split()
    X_train, y_train = splits["train"]
"""

import glob
import logging
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=FutureWarning)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Schema definitions
# ─────────────────────────────────────────────────────────────────────────────

# 55 Volatility feature columns shared by both CIC-MalMem-2022 and MemMal-D2024.
# NOTE: devicetree.* columns were removed — they are NOT present in the actual
# MemMal-D2024 CSV files (All Benign Samples + Malware Samples *.csv).
# The DatasetLoader.preprocess() takes whatever numeric columns the CSV contains,
# so this list is used for documentation and VOLATILITY_FEATURE_COLUMNS imports;
# it does not gate what actually enters the model.
VOLATILITY_FEATURE_COLUMNS: List[str] = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads",
    "pslist.nprocs64bit", "pslist.avg_handlers",
    "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc",
    "handles.nport", "handles.nfile", "handles.nevent",
    "handles.ndesktop", "handles.nkey", "handles.nthread",
    "handles.ndirectory", "handles.nsemaphore", "handles.ntimer",
    "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init",
    "ldrmodules.not_in_mem", "ldrmodules.not_in_load_avg",
    "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
    "malfind.ninjections", "malfind.commitCharge",
    "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg", "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg", "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg", "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules",
    "svcscan.nservices", "svcscan.kernel_drivers",
    "svcscan.fs_drivers", "svcscan.process_services",
    "svcscan.shared_process_services", "svcscan.interactive_process_services",
    "svcscan.nactive",
    "callbacks.ncallbacks", "callbacks.nanonymous",
    "callbacks.ngeneric",
]

# Kept for backward compatibility with code that imports CIC_FEATURE_COLUMNS
CIC_FEATURE_COLUMNS: List[str] = VOLATILITY_FEATURE_COLUMNS + ["Class"]

# Columns that are metadata-only and must be dropped before training.
# "Year" is critical: in MemMal-D2024 only malware rows have a Year value,
# so keeping it would give the model a near-perfect target-leakage signal.
METADATA_COLUMNS: List[str] = [
    "Date", "date", "Timestamp", "timestamp", "ID", "id",
    "Year", "year", "Month", "month", "Category", "category",
]

# All known label column names across both datasets
LABEL_COLUMN_ALIASES: List[str] = ["Label", "Class", "label", "class", "category", "Category"]

# Malware keyword → binary 1
# Expanded to cover MemMal-D2024 family names (Worm, Backdoor, Rootkit, etc.)
MALWARE_LABEL_KEYWORDS: List[str] = [
    "ransomware", "spyware", "trojan", "virus", "worm",
    "rootkit", "backdoor", "adware", "malware", "inject",
    "keylogger", "botnet", "miner", "cryptominer", "fileless",
    "dropper", "downloader", "stealer", "rat", "exploit",
]


# ─────────────────────────────────────────────────────────────────────────────
# Dataset auto-detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_dataset_type(df: pd.DataFrame) -> str:
    """
    Infer dataset source from column headers.

    Returns
    -------
    "year_combined"  — User-assembled MemMal-D2024 (has "Year" + "Class")
                       Malware rows have Year values; benign rows have Year=NaN.
    "memmal_d2024"   — Full academic MemMal-D2024 release (has "Label" and/or "Date")
    "cic_malmem"     — CIC-MalMem-2022 (has "Class" only, no temporal column)
    "unknown"        — Unrecognised; will still attempt to load
    """
    cols_lower = {c.strip().lower() for c in df.columns}

    has_label = "label"    in cols_lower
    has_class = "class"    in cols_lower
    has_date  = "date"     in cols_lower
    has_year  = "year"     in cols_lower

    if has_label or has_date:
        return "memmal_d2024"
    if has_year and has_class:
        return "year_combined"   # user-assembled from individual year CSVs
    if has_class:
        return "cic_malmem"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names (do NOT lowercase — schemas are case-sensitive)."""
    df.columns = [c.strip() for c in df.columns]
    return df


def _detect_label_column(df: pd.DataFrame) -> Optional[str]:
    """Return the first matching label column name, or None."""
    for alias in LABEL_COLUMN_ALIASES:
        if alias in df.columns:
            return alias
    # Fallback: last column if it looks categorical
    last = df.columns[-1]
    if df[last].dtype == object or df[last].nunique() < 20:
        logger.warning("Label column not found by name — assuming last column: '%s'", last)
        return last
    return None


def _encode_labels(series: pd.Series) -> np.ndarray:
    """
    Convert raw label strings → binary int array.
      'Benign' / 'benign' / '0'  → 0
      anything else               → 1

    Handles multiclass MemMal-D2024 families (all malware → 1).
    """
    def _map(val):
        val_str = str(val).strip().lower()
        if val_str in ("benign", "0", "clean", "normal", "legitimate", "goodware"):
            return 0
        for kw in MALWARE_LABEL_KEYWORDS:
            if kw in val_str:
                return 1
        try:
            return int(float(val_str))
        except ValueError:
            return 1  # unknown → treat as suspicious

    return np.array([_map(v) for v in series], dtype=np.int32)


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class DatasetLoader:
    """
    Universal loader for CIC-MalMem-2022 and MemMal-D2024.

    Auto-detects which dataset is supplied and adapts accordingly.
    Both datasets share the same 58 Volatility feature columns — only
    the label column name and optional metadata columns differ.

    Parameters
    ----------
    source  : path to a CSV file OR a directory of CSV files
    verbose : print loading statistics
    """

    def __init__(self, source: Union[str, Path], verbose: bool = True):
        self.source  = Path(source)
        self.verbose = verbose

        self._raw_df: Optional[pd.DataFrame] = None
        self._df:     Optional[pd.DataFrame] = None
        self.feature_names:       List[str]      = []
        self.label_column:        Optional[str]  = None
        self.dataset_type:        str            = "unknown"
        self.class_distribution:  Dict[int, int] = {}
        self.dropped_columns:     List[str]      = []
        self.n_samples_original:  int            = 0

    # ──────────────────────────────────────────────────────────────
    # Step 1: Load
    # ──────────────────────────────────────────────────────────────

    def load(self) -> "DatasetLoader":
        """Load CSV file(s) from source path."""
        if self.source.is_dir():
            self._df = self._load_directory(self.source)
        elif self.source.is_file() and self.source.suffix.lower() == ".csv":
            self._df = self._load_single_file(self.source)
        else:
            raise FileNotFoundError(
                f"Source '{self.source}' is neither a CSV file nor a directory."
            )

        self._raw_df             = self._df.copy()
        self.n_samples_original  = len(self._df)

        # Auto-detect dataset type
        self.dataset_type  = _detect_dataset_type(self._df)
        self.label_column  = _detect_label_column(self._df)

        if self.label_column is None:
            raise ValueError(
                "Could not detect a label column. "
                "Expected one of: " + ", ".join(LABEL_COLUMN_ALIASES)
            )

        if self.verbose:
            self._print_load_summary()

        return self

    def _load_single_file(self, path: Path) -> pd.DataFrame:
        logger.info("Loading: %s", path)
        df = pd.read_csv(path, low_memory=False)
        df = _normalize_column_names(df)
        logger.info("  → %d rows, %d columns", len(df), len(df.columns))
        return df

    def _load_directory(self, directory: Path) -> pd.DataFrame:
        """Concatenate all CSVs found in a directory (used for MemMal-D2024 temporal splits)."""
        csv_files = sorted(glob.glob(str(directory / "*.csv")))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in: {directory}")

        logger.info("Found %d CSV file(s) in %s", len(csv_files), directory)
        frames = [self._load_single_file(Path(f)) for f in csv_files]
        combined = pd.concat(frames, ignore_index=True)
        logger.info("Combined: %d total rows", len(combined))
        return combined

    # ──────────────────────────────────────────────────────────────
    # Step 2: Preprocess
    # ──────────────────────────────────────────────────────────────

    def preprocess(
        self,
        drop_constant_cols:  bool  = True,
        drop_high_corr:      bool  = False,
        corr_threshold:      float = 0.98,
        clip_outliers:       bool  = True,
        outlier_percentile:  float = 99.9,
    ) -> "DatasetLoader":
        """
        Clean and prepare the dataset.

        MemMal-D2024 specific:
          - "Date" and other metadata columns are dropped before training.
          - Multiclass labels (Ransomware, Worm, Rootkit …) are all mapped to 1.
        """
        if self._df is None:
            raise RuntimeError("Call .load() before .preprocess()")

        df = self._df.copy()

        # ── 1. Strip metadata columns (Date etc.) ──────────────────────────────
        meta_to_drop = [c for c in df.columns
                        if c in METADATA_COLUMNS or c.lower() in {m.lower() for m in METADATA_COLUMNS}]
        if meta_to_drop:
            logger.info("Dropping metadata columns: %s", meta_to_drop)
            df = df.drop(columns=meta_to_drop)
            self.dropped_columns.extend(meta_to_drop)

        # ── 2. Separate label ───────────────────────────────────────────────────
        y_raw = df[self.label_column].copy()
        df    = df.drop(columns=[self.label_column])

        # ── 3. Drop non-numeric columns ─────────────────────────────────────────
        non_numeric = df.select_dtypes(exclude=[np.number]).columns.tolist()
        if non_numeric:
            logger.info("Dropping non-numeric columns: %s", non_numeric)
            df = df.drop(columns=non_numeric)
            self.dropped_columns.extend(non_numeric)

        # ── 4. Replace inf with NaN then fill ───────────────────────────────────
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        nan_counts    = df.isnull().sum()
        cols_with_nan = nan_counts[nan_counts > 0]
        if len(cols_with_nan):
            logger.info("Filling NaN in %d column(s) with median", len(cols_with_nan))
            df.fillna(df.median(numeric_only=True), inplace=True)

        # ── 5. Clip outliers ────────────────────────────────────────────────────
        if clip_outliers:
            upper = df.quantile(outlier_percentile / 100)
            lower = df.quantile((100 - outlier_percentile) / 100)
            df    = df.clip(lower=lower, upper=upper, axis=1)
            logger.info("Clipped outliers at [%.1f%%, %.1f%%]",
                        100 - outlier_percentile, outlier_percentile)

        # ── 6. Drop constant columns ────────────────────────────────────────────
        if drop_constant_cols:
            constant_cols = [c for c in df.columns if df[c].nunique() <= 1]
            if constant_cols:
                logger.info("Dropping %d constant column(s): %s",
                            len(constant_cols), constant_cols)
                df = df.drop(columns=constant_cols)
                self.dropped_columns.extend(constant_cols)

        # ── 7. Drop highly correlated features ──────────────────────────────────
        if drop_high_corr:
            corr_matrix = df.corr().abs()
            upper_tri   = corr_matrix.where(
                np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
            )
            to_drop = [c for c in upper_tri.columns if (upper_tri[c] > corr_threshold).any()]
            if to_drop:
                logger.info("Dropping %d highly correlated feature(s)", len(to_drop))
                df = df.drop(columns=to_drop)
                self.dropped_columns.extend(to_drop)

        # ── 8. Encode labels (multiclass → binary) ──────────────────────────────
        y = _encode_labels(y_raw)

        # ── 9. Store results ────────────────────────────────────────────────────
        self.feature_names    = df.columns.tolist()
        self._df              = df.copy()
        self._df["__label__"] = y

        unique, counts = np.unique(y, return_counts=True)
        self.class_distribution = {int(k): int(v) for k, v in zip(unique, counts)}

        if self.verbose:
            self._print_preprocess_summary()

        return self

    # ──────────────────────────────────────────────────────────────
    # Step 3: Split
    # ──────────────────────────────────────────────────────────────

    def split(
        self,
        test_size:    float = 0.15,
        val_size:     float = 0.15,
        random_state: int   = 42,
        use_smote:    bool  = False,
        temporal:     bool  = False,
    ) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
        """
        Stratified train / val / test split.

        Parameters
        ----------
        temporal : bool
            If True, use the last N% of rows as test (time-ordered split).
            This is the correct evaluation strategy for MemMal-D2024 and
            simulates detecting malware families that didn't exist at train time.
            If False, use random stratified split (default, same as CIC behaviour).
        """
        if self._df is None or "__label__" not in self._df.columns:
            raise RuntimeError("Call .load() then .preprocess() first.")

        X = self._df.drop(columns=["__label__"]).values.astype(np.float32)
        y = self._df["__label__"].values.astype(np.int32)

        if temporal:
            return self._temporal_split(X, y, test_size, val_size)

        # Standard stratified split
        X_trainval, X_test, y_trainval, y_test = train_test_split(
            X, y,
            test_size=test_size,
            stratify=y,
            random_state=random_state,
        )
        effective_val = val_size / (1.0 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_trainval, y_trainval,
            test_size=effective_val,
            stratify=y_trainval,
            random_state=random_state,
        )

        if use_smote:
            X_train, y_train = self._apply_smote(X_train, y_train, random_state)

        splits = {
            "train": (X_train, y_train),
            "val":   (X_val,   y_val),
            "test":  (X_test,  y_test),
        }

        if self.verbose:
            self._print_split_summary(splits, mode="stratified")

        return splits

    def _temporal_split(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float,
        val_size:  float,
    ) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
        """
        Time-ordered split for MemMal-D2024 temporal evaluation.
        Rows must already be sorted chronologically (the dataset CSV is).
        Train on early samples, validate on middle, test on latest samples.
        """
        n         = len(y)
        test_n    = int(n * test_size)
        val_n     = int(n * val_size)
        train_n   = n - val_n - test_n

        X_train, y_train = X[:train_n],              y[:train_n]
        X_val,   y_val   = X[train_n:train_n+val_n], y[train_n:train_n+val_n]
        X_test,  y_test  = X[train_n+val_n:],        y[train_n+val_n:]

        splits = {
            "train": (X_train, y_train),
            "val":   (X_val,   y_val),
            "test":  (X_test,  y_test),
        }

        if self.verbose:
            self._print_split_summary(splits, mode="temporal")

        return splits

    def _apply_smote(self, X: np.ndarray, y: np.ndarray, seed: int):
        try:
            from imblearn.over_sampling import SMOTE
            sm           = SMOTE(random_state=seed)
            X_res, y_res = sm.fit_resample(X, y)
            logger.info("SMOTE: %d → %d samples (added %d)", len(y), len(y_res),
                        len(y_res) - len(y))
            return X_res, y_res
        except ImportError:
            logger.warning("imbalanced-learn not installed — skipping SMOTE. "
                           "Run: pip install imbalanced-learn")
            return X, y

    # ──────────────────────────────────────────────────────────────
    # Properties / helpers
    # ──────────────────────────────────────────────────────────────

    @property
    def X(self) -> np.ndarray:
        if self._df is None or "__label__" not in self._df.columns:
            raise RuntimeError("Call .load() and .preprocess() first.")
        return self._df.drop(columns=["__label__"]).values.astype(np.float32)

    @property
    def y(self) -> np.ndarray:
        if self._df is None or "__label__" not in self._df.columns:
            raise RuntimeError("Call .load() and .preprocess() first.")
        return self._df["__label__"].values.astype(np.int32)

    @property
    def dataframe(self) -> pd.DataFrame:
        return self._df.copy()

    def get_feature_names(self) -> List[str]:
        return list(self.feature_names)

    def get_class_distribution(self) -> Dict[int, int]:
        return dict(self.class_distribution)

    def save_processed(self, output_path: Union[str, Path]) -> None:
        if self._df is None:
            raise RuntimeError("Nothing to save — run load() and preprocess() first.")
        out = Path(output_path)
        self._df.to_csv(out, index=False)
        logger.info("Saved preprocessed dataset to: %s", out)
        if self.verbose:
            print(f"\n  💾 Saved: {out}  ({len(self._df):,} rows)")

    # ──────────────────────────────────────────────────────────────
    # Pretty-print helpers
    # ──────────────────────────────────────────────────────────────

    def _dataset_display_name(self) -> str:
        names = {
            "year_combined": "MemMal-D2024 (Year-Combined)",
            "memmal_d2024": "MemMal-D2024",
            "cic_malmem":   "CIC-MalMem-2022",
            "unknown":      "Unknown Dataset",
        }
        return names.get(self.dataset_type, "Dataset")

    def _print_load_summary(self):
        name = self._dataset_display_name()
        print("\n" + "=" * 60)
        print(f"  📂 DATASET LOADED — {name}")
        print("=" * 60)
        print(f"  Source         : {self.source}")
        print(f"  Dataset type   : {self.dataset_type}")
        print(f"  Total samples  : {self.n_samples_original:,}")
        print(f"  Total columns  : {len(self._df.columns)}")
        print(f"  Label column   : '{self.label_column}'")
        print(f"  Unique labels  : {sorted(self._df[self.label_column].dropna().unique())}")
        print("=" * 60)

    def _print_preprocess_summary(self):
        total   = sum(self.class_distribution.values())
        benign  = self.class_distribution.get(0, 0)
        malware = self.class_distribution.get(1, 0)
        ratio   = benign / malware if malware > 0 else float("inf")

        print("\n" + "=" * 60)
        print("  🔧 PREPROCESSING COMPLETE")
        print("=" * 60)
        print(f"  Final features     : {len(self.feature_names)}")
        print(f"  Dropped columns    : {len(self.dropped_columns)}")
        print(f"  Total samples      : {total:,}")
        print(f"  ├─ CLEAN      (0)  : {benign:,}  ({100*benign/total:.1f}%)")
        print(f"  └─ SUSPICIOUS (1)  : {malware:,}  ({100*malware/total:.1f}%)")
        print(f"  Class balance ratio: {ratio:.2f}:1")
        if ratio > 5:
            print("  ⚠  Imbalanced dataset — consider use_smote=True in .split()")
        print("=" * 60)

    def _print_split_summary(self, splits: Dict, mode: str = "stratified"):
        print("\n" + "=" * 60)
        print(f"  ✂  TRAIN / VAL / TEST SPLIT  [{mode.upper()}]")
        print("=" * 60)
        for split_name, (X, y) in splits.items():
            n = len(y)
            b = int((y == 0).sum())
            m = int((y == 1).sum())
            print(f"  {split_name:5s}  : {n:6,} samples  (clean={b:,}, suspicious={m:,})")
        print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience factory functions
# ─────────────────────────────────────────────────────────────────────────────

def load_malmem_d2024(
    source:       Union[str, Path],
    test_size:    float = 0.15,
    val_size:     float = 0.15,
    use_smote:    bool  = False,
    temporal:     bool  = False,
    random_state: int   = 42,
    verbose:      bool  = True,
) -> Tuple["DatasetLoader", Dict[str, Tuple[np.ndarray, np.ndarray]]]:
    """
    One-liner for MemMal-D2024: load → preprocess → split.

    Parameters
    ----------
    temporal : bool
        True  → time-ordered split (recommended for MemMal-D2024 papers).
        False → stratified random split (default, matches CIC evaluation).

    Example
    -------
    loader, splits = load_malmem_d2024("datasets/MemMal-D2024-combined.csv")
    X_train, y_train = splits["train"]
    """
    loader = DatasetLoader(source, verbose=verbose)
    loader.load()
    loader.preprocess()
    splits = loader.split(
        test_size=test_size,
        val_size=val_size,
        use_smote=use_smote,
        temporal=temporal,
        random_state=random_state,
    )
    return loader, splits


def load_cic_malmem(
    source:       Union[str, Path],
    test_size:    float = 0.20,
    val_size:     float = 0.10,
    use_smote:    bool  = False,
    random_state: int   = 42,
    verbose:      bool  = True,
) -> Tuple["DatasetLoader", Dict[str, Tuple[np.ndarray, np.ndarray]]]:
    """
    Backward-compatible factory for CIC-MalMem-2022.

    Kept so existing code that calls load_cic_malmem() continues to work
    without modification. Internally uses the same DatasetLoader.
    """
    loader = DatasetLoader(source, verbose=verbose)
    loader.load()
    loader.preprocess()
    splits = loader.split(
        test_size=test_size,
        val_size=val_size,
        use_smote=use_smote,
        temporal=False,
        random_state=random_state,
    )
    return loader, splits


# ─────────────────────────────────────────────────────────────────────────────
# CLI / quick test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dataset_loader.py <path/to/dataset.csv> [--temporal]")
        print("\n  Supports both CIC-MalMem-2022 and MemMal-D2024 (auto-detected).")
        sys.exit(1)

    csv_path = sys.argv[1]
    use_temporal = "--temporal" in sys.argv

    loader, splits = load_malmem_d2024(
        csv_path,
        temporal=use_temporal,
    )

    X_train, y_train = splits["train"]
    X_val,   y_val   = splits["val"]
    X_test,  y_test  = splits["test"]

    print(f"\n✅ Ready for ML training!")
    print(f"   Dataset type  : {loader.dataset_type}")
    print(f"   X_train : {X_train.shape}  y_train : {y_train.shape}")
    print(f"   X_val   : {X_val.shape}    y_val   : {y_val.shape}")
    print(f"   X_test  : {X_test.shape}   y_test  : {y_test.shape}")
    print(f"\n   Feature count : {len(loader.get_feature_names())}")
    print(f"   Features      : {loader.get_feature_names()[:5]} ...")