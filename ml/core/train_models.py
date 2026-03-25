from __future__ import annotations


"""
ML Model Training Script (Brute-force Phát hiện)

Script này trains two models for login anomaly phát hiện:
    1. Binary Logistic Regression: Detects if an sự kiện is an tấn công (is_attack_label)
    2. Multi-class Logistic Regression: Classifies tấn công type (attack_type_label)

Expected input: Parquet file with đặc trưng and labels (see below).
Output: Trained models, scaler, and metadata in the output directory.

Demo-friendly: Code is organized and commented for easy explanation and presentation.
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
from ml.core.metrics import (
    load_thresholds,
    compute_binary_metrics,
    compute_multiclass_metrics,
)
from sklearn.model_selection import GridSearchCV
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
    Split indices into train/val/kiểm tra by time order (70% / 15% / 15%).
    Used when stratified split is not possible (e.g., only one class present).
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


def _split_stratified_indices(
    y_labels: np.ndarray,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Stratified split into train/val/kiểm tra by label distribution.
    Ensures each split has similar class proportions (prevents overfitting to rare classes).
    """
    n_samples = len(y_labels)
    if n_samples < 10:
        raise ValueError(f"Dataset too small for stratified split (n={n_samples}).")

    # Bước đầu tách set kiểm tra
    idx = np.arange(n_samples)
    try:
        train_val_idx, test_idx = train_test_split(
            idx,
            test_size=test_size,
            random_state=random_state,
            stratify=y_labels,
        )
    except ValueError:
        # Dùng time-series nếu stratify không khả dụng do thiếu class
        return _split_time_series_indices(n_samples)

    # Sau đó chia train_val thành train và val theo tỷ lệ còn lại
    val_fraction = val_size / (1.0 - test_size)
    try:
        train_idx, val_idx = train_test_split(
            train_val_idx,
            test_size=val_fraction,
            random_state=random_state,
            stratify=y_labels[train_val_idx],
        )
    except ValueError:
        # Dùng time-series nếu stratify thất bại
        return _split_time_series_indices(n_samples)

    return np.array(train_idx), np.array(val_idx), np.array(test_idx)


def _train_binary_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
) -> GridSearchCV:
    """
    Train a binary Logistic Regression model (tấn công vs. benign).
    Sử dụng GridSearchCV để tinh chỉnh regularization (C) và ngăn quá khớp.
    """
    # Regularization and cross-validation to prevent overfitting
    clf = LogisticRegression(
        class_weight="balanced",  # Xử lý lớp mất cân bằng: nếu tấn công ít hơn thì tăng trọng số
        solver="liblinear",  # Thuật toán giải quyết bài toán tối ưu hóa
        max_iter=1000,  # Số lần lặp tối đa để hội tụ
        random_state=random_state,
    )
    # Hyperparameter grid for regularization strength (C)
    param_grid = {
        "C": [0.01, 0.05, 0.1, 0.5],  # C nhỏ = quy chuẩn mạnh (tránh quá khớp), C lớn = quy chuẩn yếu
        "penalty": ["l2"],  # Loại quy chuẩn: L2 làm mịn trọng số
    }
    # TimeSeriesSplit for validation (prevents data leakage)
    # Chia dữ liệu theo thứ tự thời gian: train trước, test sau (như dự đoán thực tế)
    tscv = TimeSeriesSplit(n_splits=3)
    search = GridSearchCV(
        clf,
        param_grid=param_grid,
        cv=tscv,
        scoring="f1",  # Dùng F1 score để đánh giá (cân bằng precision và recall)
        n_jobs=-1,  # Dùng tất cả core CPU
        verbose=1,  # Hiển thị tiến độ
    )
    search.fit(X_train, y_train)
    print(f"[DEBUG] Binary model best params: {search.best_params_}")
    return search


def _train_multiclass_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_state: int = 42,
) -> GridSearchCV:
    """
    Train a multi-class Logistic Regression model (tấn công type classification).
    Sử dụng GridSearchCV để tinh chỉnh regularization (C) và ngăn quá khớp.
    """
    # Regularization and cross-validation to prevent overfitting
    clf = LogisticRegression(
        class_weight="balanced",  # Cân bằng trọng số cho mỗi loại tấn công
        multi_class="multinomial",  # Xử lý nhiều lớp (>2)
        solver="lbfgs",  # Thuật toán cho bài toán đa lớp
        max_iter=1000,
        random_state=random_state,
    )
    # Hyperparameter grid for regularization strength (C)
    param_grid = {
        "C": [0.01, 0.1, 1.0, 10.0],  # Thử nhiều mức quy chuẩn
    }
    # TimeSeriesSplit for validation (prevents data leakage)
    tscv = TimeSeriesSplit(n_splits=3)
    search = GridSearchCV(
        clf,
        param_grid=param_grid,
        cv=tscv,
        scoring="f1_macro",  # F1 macro: trung bình F1 của tất cả các lớp (công bằng cho lớp ít)
        n_jobs=-1,
        verbose=1,
    )
    search.fit(X_train, y_train)
    print(f"[DEBUG] Multiclass model best params: {search.best_params_}")
    return search


## All binary metric computation now in ml.core.metrics


## All multiclass metric computation now in ml.core.metrics


def train_models(
    input_parquet: str,
    output_dir: str = "models",
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Chính training entrypoint for demo.
    Loads data, trains models on all data (no split for demo consistency), evaluates using cross-validation for thresholds.

    Args:
        input_parquet: Path to đặc trưng Parquet file (all data).
        output_dir: Directory to write model artifacts and metadata.
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

    # LabelEncoder: Chuyển đổi tên loại tấn công (string) thành số (0, 1, 2, ...)
    # Ví dụ: "brute_force" → 0, "password_spray" → 1, "benign" → 2
    attack_labels_raw = df["attack_type_label"].astype(str).fillna("benign").to_numpy()
    label_encoder = LabelEncoder()
    y_multiclass = label_encoder.fit_transform(attack_labels_raw)
    class_labels = list(label_encoder.classes_)

    n_samples = X.shape[0]

    # StandardScaler: Chuẩn hóa đặc trưng để tất cả có trung bình = 0, độ lệch chuẩn = 1
    # Lý do: Logistic Regression hoạt động tốt hơn với dữ liệu chuẩn hóa (tránh một đặc trưng chi phối)
    # Công thức: x_scaled = (x - mean) / std
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Binary model - train on all data
    binary_search = _train_binary_model(
        X_scaled,
        y_binary,
        random_state=random_state,
    )
    binary_model = binary_search.best_estimator_

    # Multi-class model - train on all data
    multiclass_search = _train_multiclass_model(
        X_scaled,
        y_multiclass,
        random_state=random_state,
    )
    multiclass_model = multiclass_search.best_estimator_

    # Tải ngưỡng từ file cấu hình (thay vì tính động)
    thresholds = load_thresholds()
    
    # Tính metrics trên toàn bộ dữ liệu với các ngưỡng cố định
    # score: Xác suất dự đoán lớp tấn công (0-1), càng cao càng khả năng là tấn công
    y_scores = binary_model.predict_proba(X_scaled)[:, 1]
    
    binary_metrics = {
        # default_0_5: Mặc định ngưỡng 0.5 (50% xác suất)
        "default_0_5": compute_binary_metrics(y_binary, y_scores, threshold=0.5),
        
        # t_high_recall: Ngưỡng thấp → phát hiện nhiều tấn công nhưng false positive cao
        # Ưu điểm: không bỏ sót tấn công | Nhược điểm: báo động nhiều lần
        "t_high_recall": compute_binary_metrics(
            y_binary,
            y_scores,
            threshold=thresholds["t_high_recall"],
        ),
        
        # t_balanced: Ngưỡng trung bình → cân bằng giữa phát hiện và false positive
        # Ưu điểm: tổng thể tốt nhất | Nhược điểm: không tối ưu cho tiêu chí nào đặc biệt
        "t_balanced": compute_binary_metrics(
            y_binary,
            y_scores,
            threshold=thresholds["t_balanced"],
        ),
        
        # t_high_precision: Ngưỡng cao → ít false positive (báo động chính xác)
        # Ưu điểm: ít báo động sai | Nhược điểm: có thể bỏ sót một số tấn công
        "t_high_precision": compute_binary_metrics(
            y_binary,
            y_scores,
            threshold=thresholds["t_high_precision"],
        ),
        
        "thresholds": thresholds,
    }
    
    # Đánh giá mô hình đa lớp trên toàn bộ dữ liệu
    multiclass_metrics = compute_multiclass_metrics(
        y_multiclass,
        multiclass_model.predict(X_scaled),
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
    print("[INFO] Starting ML model training...")
    train_models(
        input_parquet=args.input_parquet,
        output_dir=args.output_dir,
        random_state=args.random_state,
    )
    print("[INFO] Training complete. Artifacts saved.")


if __name__ == "__main__":
    main()

