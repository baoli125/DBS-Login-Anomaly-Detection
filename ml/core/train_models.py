from __future__ import annotations

"""
Training script for brute-force detection ML models (binary + multi-class).

This script expects a Parquet feature dataset produced by `ml.feature_builder`,
with the following columns:
- `timestamp` (datetime-like or string)
- `is_attack_label` (0/1)
- `attack_type_label` (string; e.g. 'benign', 'rapid_bruteforce', ...)
- Feature columns matching `ml.features.get_feature_names()`.

It trains:
- A binary Logistic Regression model predicting `is_attack_label`.
- A multi-class Logistic Regression model predicting `attack_type_label`.

Artifacts written to the output directory:
- `binary_model.joblib`
- `multiclass_model.joblib`
- `scaler.joblib`
- `model_metadata.json`
"""

import argparse
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, TimeSeriesSplit
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ..features.features import get_feature_names


@dataclass
class ThresholdSet:
    """Collection of decision thresholds for the binary model."""

    t_high_recall: float
    t_balanced: float
    t_high_precision: float


def _split_time_series_indices(n_samples: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Split indices into train/val/test by time order (70% / 15% / 15%).
    """
    if n_samples < 10:
        raise ValueError(f"Dataset too small for time-based split (n={n_samples}).")

    train_end = int(n_samples * 0.7)
    val_end = int(n_samples * 0.85)

    indices = np.arange(n_samples)
    train_idx = indices[:train_end]
    val_idx = indices[train_end:val_end]
    test_idx = indices[val_end:]
    return train_idx, val_idx, test_idx


def _select_binary_thresholds(
    y_true: np.ndarray,
    y_scores: np.ndarray,
) -> ThresholdSet:
    """
    Derive a few useful thresholds from the precision-recall curve.

    - t_high_recall: highest threshold with recall >= 0.95 (or max recall-favouring point).
    - t_high_precision: highest threshold with precision >= 0.95 (or max precision-favouring point).
    - t_balanced: threshold that maximizes F1 score.
    """
    # If no positive class in validation set, use reasonable defaults
    if np.sum(y_true) == 0:
        return ThresholdSet(t_high_recall=0.1, t_balanced=0.5, t_high_precision=0.9)

    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)

    # Compute F1 for each threshold-aligned point
    # precision / recall are length N, thresholds length N-1; ignore last p/r.
    p = precision[:-1]
    r = recall[:-1]
    f1 = np.where((p + r) > 0, 2 * p * r / (p + r), 0.0)

    # Balanced (max F1)
    best_f1_idx = int(np.argmax(f1))
    t_balanced = float(thresholds[best_f1_idx])

    # High recall: recall >= 0.95, pick threshold with highest F1 among them
    high_recall_mask = r >= 0.95
    if np.any(high_recall_mask):
        idxs = np.where(high_recall_mask)[0]
        best_idx = idxs[int(np.argmax(f1[idxs]))]
        t_high_recall = float(thresholds[best_idx])
    else:
        # Fallback to threshold with max recall (smallest threshold)
        t_high_recall = float(thresholds[np.argmax(r)])

    # High precision: precision >= 0.95, pick highest threshold satisfying it
    high_prec_mask = p >= 0.95
    if np.any(high_prec_mask):
        idxs = np.where(high_prec_mask)[0]
        # choose the largest threshold index in this group
        best_idx = int(idxs[-1])
        t_high_precision = float(thresholds[best_idx])
    else:
        # Fallback to threshold with max precision (largest threshold)
        t_high_precision = float(thresholds[np.argmax(p)])

    return ThresholdSet(
        t_high_recall=t_high_recall,
        t_balanced=t_balanced,
        t_high_precision=t_high_precision,
    )


def _train_binary_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
) -> GridSearchCV:
    """
    Train a binary Logistic Regression model with a small hyperparameter grid.
    """
    clf = LogisticRegression(
        class_weight="balanced",
        solver="liblinear",
        max_iter=1000,
        random_state=random_state,
    )
    param_grid = {
        "C": [0.1, 1.0, 10.0],
        "penalty": ["l2"],
    }
    tscv = TimeSeriesSplit(n_splits=3)
    search = GridSearchCV(
        clf,
        param_grid=param_grid,
        cv=tscv,
        scoring="f1",
        n_jobs=-1,
        verbose=0,
    )
    search.fit(X_train, y_train)
    return search


def _train_multiclass_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
) -> GridSearchCV:
    """
    Train a multi-class Logistic Regression model with a small hyperparameter grid.
    """
    clf = LogisticRegression(
        class_weight="balanced",
        multi_class="multinomial",
        solver="lbfgs",
        max_iter=1000,
        random_state=random_state,
    )
    param_grid = {
        "C": [0.1, 1.0, 10.0],
    }
    tscv = TimeSeriesSplit(n_splits=3)
    search = GridSearchCV(
        clf,
        param_grid=param_grid,
        cv=tscv,
        scoring="f1_macro",
        n_jobs=-1,
        verbose=0,
    )
    search.fit(X_train, y_train)
    return search


def _compute_binary_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    threshold: float,
) -> Dict[str, Any]:
    """
    Compute standard binary classification metrics at a given threshold.
    """
    y_pred = (y_scores >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="binary",
        zero_division=0,
    )

    # Handle case with only one class
    unique_classes = np.unique(y_true)
    if len(unique_classes) == 1:
        roc_auc = 0.5  # Undefined, set to random baseline
        pr_auc = 0.0 if unique_classes[0] == 0 else 1.0  # If all positive, PR AUC=1; if all negative, 0
    else:
        roc_auc = roc_auc_score(y_true, y_scores)
        pr_auc = average_precision_score(y_true, y_scores)

    return {
        "threshold": float(threshold),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
    }


def _compute_multiclass_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_labels: List[str],
) -> Dict[str, Any]:
    """
    Compute multi-class metrics, including confusion matrix and per-class stats.
    """
    report = classification_report(
        y_true,
        y_pred,
        labels=np.arange(len(class_labels)),
        target_names=class_labels,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=np.arange(len(class_labels)),
    )

    return {
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
        "labels": class_labels,
    }


def train_models(
    input_parquet: str,
    output_dir: str = "models",
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Main training entrypoint.

    Args:
        input_parquet: Path to feature Parquet file.
        output_dir: Directory to write models and metadata.
        random_state: Random seed for reproducibility.

    Returns:
        A dictionary containing summary metadata (also written to JSON).
    """
    if not os.path.exists(input_parquet):
        raise FileNotFoundError(f"Input Parquet file does not exist: {input_parquet}")

    df = pd.read_parquet(input_parquet)
    if df.empty:
        raise ValueError(f"Input Parquet dataset is empty: {input_parquet}")

    # Ensure timestamp is datetime and sort for time-based splits
    if not np.issubdtype(df["timestamp"].dtype, np.datetime64):
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values("timestamp").reset_index(drop=True)

    feature_names = get_feature_names()
    missing_features = [f for f in feature_names if f not in df.columns]
    if missing_features:
        raise ValueError(f"Missing expected feature columns in dataset: {missing_features}")

    if "is_attack_label" not in df.columns or "attack_type_label" not in df.columns:
        raise ValueError("Dataset must contain 'is_attack_label' and 'attack_type_label' columns.")

    X = df[feature_names].to_numpy(dtype=float)
    y_binary = df["is_attack_label"].astype(int).to_numpy()

    attack_labels_raw = df["attack_type_label"].astype(str).fillna("benign").to_numpy()
    label_encoder = LabelEncoder()
    y_multiclass = label_encoder.fit_transform(attack_labels_raw)
    class_labels = list(label_encoder.classes_)

    n_samples = X.shape[0]
    train_idx, val_idx, test_idx = _split_time_series_indices(n_samples)

    X_train, X_val, X_test = X[train_idx], X[val_idx], X[test_idx]
    y_train_bin, y_val_bin, y_test_bin = (
        y_binary[train_idx],
        y_binary[val_idx],
        y_binary[test_idx],
    )
    y_train_multi, y_val_multi, y_test_multi = (
        y_multiclass[train_idx],
        y_multiclass[val_idx],
        y_multiclass[test_idx],
    )

    # Fit scaler on train only
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Binary model
    binary_search = _train_binary_model(
        X_train_scaled,
        y_train_bin,
        random_state=random_state,
    )
    binary_model = binary_search.best_estimator_

    # Multi-class model
    multiclass_search = _train_multiclass_model(
        X_train_scaled,
        y_train_multi,
        random_state=random_state,
    )
    multiclass_model = multiclass_search.best_estimator_

    # Evaluate binary model on test set
    y_test_scores = binary_model.predict_proba(X_test_scaled)[:, 1]
    thresholds = _select_binary_thresholds(y_test_bin, y_test_scores)

    binary_metrics = {
        "default_0_5": _compute_binary_metrics(y_test_bin, y_test_scores, threshold=0.5),
        "t_high_recall": _compute_binary_metrics(
            y_test_bin,
            y_test_scores,
            threshold=thresholds.t_high_recall,
        ),
        "t_balanced": _compute_binary_metrics(
            y_test_bin,
            y_test_scores,
            threshold=thresholds.t_balanced,
        ),
        "t_high_precision": _compute_binary_metrics(
            y_test_bin,
            y_test_scores,
            threshold=thresholds.t_high_precision,
        ),
        "thresholds": asdict(thresholds),
    }

    # Evaluate multi-class model on test set
    y_test_pred_multi = multiclass_model.predict(X_test_scaled)
    multiclass_metrics = _compute_multiclass_metrics(
        y_test_multi,
        y_test_pred_multi,
        class_labels=class_labels,
    )

    os.makedirs(output_dir, exist_ok=True)

    # Persist models and scaler
    binary_model_path = os.path.join(output_dir, "binary_model.joblib")
    multiclass_model_path = os.path.join(output_dir, "multiclass_model.joblib")
    scaler_path = os.path.join(output_dir, "scaler.joblib")

    joblib.dump(binary_model, binary_model_path)
    joblib.dump(multiclass_model, multiclass_model_path)
    joblib.dump(scaler, scaler_path)

    # Collect metadata
    metadata: Dict[str, Any] = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "input_parquet": os.path.abspath(input_parquet),
        "output_dir": os.path.abspath(output_dir),
        "n_samples": int(n_samples),
        "train_size": int(len(train_idx)),
        "val_size": int(len(val_idx)),
        "test_size": int(len(test_idx)),
        "feature_names": feature_names,
        "binary_model": {
            "best_params": binary_search.best_params_,
            "metrics": binary_metrics,
        },
        "multiclass_model": {
            "best_params": multiclass_search.best_params_,
            "metrics": multiclass_metrics,
        },
        "label_encoding": {
            "classes": class_labels,
        },
        "artifacts": {
            "binary_model_path": binary_model_path,
            "multiclass_model_path": multiclass_model_path,
            "scaler_path": scaler_path,
        },
    }

    metadata_path = os.path.join(output_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def _parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train binary and multi-class Logistic Regression models for brute-force detection.",
    )
    parser.add_argument(
        "--input-parquet",
        required=True,
        help="Path to Parquet file produced by `ml.feature_builder.build_dataset_from_ndjson`.",
    )
    parser.add_argument(
        "--output-dir",
        default="models",
        help="Directory to write model artifacts and metadata (default: %(default)s).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for model training (default: %(default)s).",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = _parse_args(argv)
    train_models(
        input_parquet=args.input_parquet,
        output_dir=args.output_dir,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()

