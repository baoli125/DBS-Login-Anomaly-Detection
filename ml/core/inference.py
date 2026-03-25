# Sử dụng ml.core.metrics cho toàn bộ logic tính điểm/ngưỡng trong huấn luyện và đánh giá. Code inference nên gọi model.predict_proba và dùng ngưỡng từ metadata, vốn luôn được tính bằng ml.core.metrics.
from __future__ import annotations


"""
Tiện ích Inference ML (Phát hiện Brute-force)

Mô-đun này cung cấp API rõ ràng cho việc tải mô hình đã đào tạo và đưa ra dự đoán.
    - Phát hiện nhị phân: Dự đoán xác suất và nhãn is_attack
    - Phân loại đa lớp: Dự đoán attack_type và xác suất
"""

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import joblib
import numpy as np

from ..features.features import get_feature_names


FeatureInput = Union[Mapping[str, float], Sequence[float], np.ndarray]


@dataclass
class LoadedModels:
    """
    Container chứa tất cả các artifact ML cần thiết tại thời điểm suy luận.

    Thuộc tính:
        binary_model: Bộ phân loại nhị phân đã đào tạo với `predict_proba`.
        multiclass_model: Bộ phân loại đa lớp đã đào tạo với `predict_proba`.
        scaler: Bộ chuẩn hóa sklearn đã fit (StandardScaler).
        metadata: Dict tải từ `model_metadata.json`.
        feature_names: Danh sách đặc trưng theo thứ tự mong đợi của mô hình.
        class_labels: Danh sách nhãn lớp cho mô hình đa lớp.
        thresholds: Dict các ngưỡng nhị phân (ví dụ: t_high_recall, t_balanced, t_high_precision).
    """

    binary_model: Any
    multiclass_model: Any
    scaler: Any
    metadata: Dict[str, Any]
    feature_names: List[str]
    class_labels: List[str]
    thresholds: Dict[str, float]


_MODEL_CACHE: Dict[str, LoadedModels] = {}


def _resolve_models_dir(models_dir: Optional[str]) -> str:
    """
    Giải quyết thư mục mô hình, mặc định là `<project_root>/models`.
    """
    if models_dir:
        return models_dir

    # Default: `<project_root>/models`
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(project_root, "models")


def load_models(models_dir: Optional[str] = None, use_cache: bool = True) -> LoadedModels:
    """
    Tải tất cả artifact ML cần thiết cho suy luận (mô hình nhị phân & đa lớp, scaler, metadata).
    Sử dụng cache để hiệu quả. Thiết kế rõ ràng cho demo và tích hợp.

    Args:
        models_dir: Thư mục chứa artifact mô hình.
        use_cache: Nếu True, cache mô hình trong bộ nhớ để sử dụng lại.

    Returns:
        Instance LoadedModels (xem dataclass ở trên).
    """
    resolved_dir = os.path.abspath(_resolve_models_dir(models_dir))

    if use_cache and resolved_dir in _MODEL_CACHE:
        return _MODEL_CACHE[resolved_dir]

    binary_path = os.path.join(resolved_dir, "binary_model.joblib")
    multiclass_path = os.path.join(resolved_dir, "multiclass_model.joblib")
    scaler_path = os.path.join(resolved_dir, "scaler.joblib")
    metadata_path = os.path.join(resolved_dir, "model_metadata.json")

    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary model not found: {binary_path}")
    if not os.path.exists(multiclass_path):
        raise FileNotFoundError(f"Multiclass model not found: {multiclass_path}")
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler not found: {scaler_path}")
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(f"Metadata JSON not found: {metadata_path}")

    binary_model = joblib.load(binary_path)
    multiclass_model = joblib.load(multiclass_path)
    scaler = joblib.load(scaler_path)

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata: Dict[str, Any] = json.load(f)

    # Danh sách đặc trưng được lưu trong metadata, nhưng chúng ta fallback về schema định nghĩa trong code.
    feature_names_meta = metadata.get("feature_names")
    feature_names = list(feature_names_meta) if feature_names_meta is not None else get_feature_names()

    label_encoding = metadata.get("label_encoding", {})
    class_labels = list(label_encoding.get("classes", []))

    thresholds_dict = {}
    binary_meta = metadata.get("binary_model", {})
    metrics = binary_meta.get("metrics", {})
    thresholds_in_metrics = metrics.get("thresholds")
    if isinstance(thresholds_in_metrics, dict):
        # Mong đợi keys: t_high_recall, t_balanced, t_high_precision
        for k, v in thresholds_in_metrics.items():
            try:
                thresholds_dict[k] = float(v)
            except (TypeError, ValueError):
                continue

    loaded = LoadedModels(
        binary_model=binary_model,
        multiclass_model=multiclass_model,
        scaler=scaler,
        metadata=metadata,
        feature_names=feature_names,
        class_labels=class_labels,
        thresholds=thresholds_dict,
    )

    if use_cache:
        _MODEL_CACHE[resolved_dir] = loaded

    return loaded


def _features_to_array(
    features: FeatureInput,
    feature_names: Optional[Sequence[str]] = None,
) -> np.ndarray:
    """
    Chuyển đổi vector đặc trưng (dict hoặc array) thành numpy array cho đầu vào mô hình.
    Điền đặc trưng thiếu bằng 0.0. Đảm bảo shape đúng cho mô hình sklearn.

    Args:
        đặc trưng: Dict hoặc array giá trị đặc trưng.
        feature_names: Danh sách tên đặc trưng (thứ tự).

    Returns:
        Numpy array có shape (1, n_features).
    """
    if feature_names is None:
        feature_names = get_feature_names()
    feature_names = list(feature_names)

    if isinstance(features, Mapping):
        row = [float(features.get(name, 0.0)) for name in feature_names]
        arr = np.asarray(row, dtype=float).reshape(1, -1)
        return arr

    # Đường dẫn Sequence / ndarray
    arr = np.asarray(features, dtype=float)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    if arr.shape[1] != len(feature_names):
        raise ValueError(
            f"Feature vector has shape {arr.shape}, but expected "
            f"({arr.shape[0]}, {len(feature_names)}) according to feature_names."
        )
    return arr


def predict_attack_from_features(
    features: FeatureInput,
    models_dir: Optional[str] = None,
    threshold: Optional[float] = None,
    threshold_key: str = "t_balanced",
) -> Dict[str, Any]:
    """
    Dự đoán xác suất và nhãn cho is_attack sử dụng mô hình nhị phân.
    Chọn ngưỡng cho quyết định (tùy chỉnh hoặc từ metadata).

    Args:
        đặc trưng: Dict hoặc array giá trị đặc trưng.
        models_dir: Thư mục với artifact mô hình.
        threshold: Ngưỡng tùy chỉnh (ghi đè threshold_key).
        threshold_key: Sử dụng ngưỡng có tên từ metadata (ví dụ: 't_balanced').

    Returns:
        Dict với score, label, threshold sử dụng, và flags cho rõ ràng demo.
    """
    models = load_models(models_dir=models_dir, use_cache=True)
    X = _features_to_array(features, feature_names=models.feature_names)
    X_scaled = models.scaler.transform(X)

    # Xác suất nhị phân (giả định lớp is_attack là cột 1)
    score = float(models.binary_model.predict_proba(X_scaled)[:, 1][0])

    # Quyết định ngưỡng nào để sử dụng
    thresholds = dict(models.thresholds)
    if threshold is not None:
        used_threshold = float(threshold)
        threshold_name = "custom"
    else:
        if threshold_key not in thresholds:
            # Fallback về 0.5 nếu metadata thiếu
            used_threshold = 0.5
        else:
            used_threshold = float(thresholds[threshold_key])
        threshold_name = threshold_key

    label = int(score >= used_threshold)

    # Flags tiện ích liên quan đến ngưỡng đã biết (nếu có)
    t_high_recall = thresholds.get("t_high_recall")
    t_balanced = thresholds.get("t_balanced")
    t_high_precision = thresholds.get("t_high_precision")

    thresholds_flags = {
        "above_high_recall": (score >= float(t_high_recall)) if t_high_recall is not None else False,
        "above_balanced": (score >= float(t_balanced)) if t_balanced is not None else False,
        "above_high_precision": (score >= float(t_high_precision)) if t_high_precision is not None else False,
    }

    return {
        "score": score,
        "label": label,
        "threshold_used": used_threshold,
        "threshold_name": threshold_name,
        "thresholds_flags": thresholds_flags,
        "raw_thresholds": thresholds,
    }


def predict_attack_type_from_features(
    features: FeatureInput,
    models_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dự đoán loại tấn công (đa lớp) cho một vector đặc trưng duy nhất.
    Trả về lớp dự đoán, nhãn, và xác suất cho mỗi lớp.

    Args:
        đặc trưng: Dict hoặc array giá trị đặc trưng.
        models_dir: Thư mục với artifact mô hình.

    Returns:
        Dict với chỉ số lớp, nhãn, và xác suất lớp.
    """
    models = load_models(models_dir=models_dir, use_cache=True)
    X = _features_to_array(features, feature_names=models.feature_names)
    X_scaled = models.scaler.transform(X)

    proba = models.multiclass_model.predict_proba(X_scaled)[0]
    if not models.class_labels:
        # Nếu mã hóa nhãn bị thiếu, index nhãn dưới dạng string
        class_labels = [str(i) for i in range(len(proba))]
    else:
        class_labels = models.class_labels

    class_index = int(np.argmax(proba))
    class_label = class_labels[class_index]
    class_probabilities = {label: float(p) for label, p in zip(class_labels, proba)}

    return {
        "class_index": class_index,
        "class_label": class_label,
        "class_probabilities": class_probabilities,
    }


def predict_attack_and_type(
    features: FeatureInput,
    models_dir: Optional[str] = None,
    threshold: Optional[float] = None,
    threshold_key: str = "t_balanced",
) -> Dict[str, Any]:
    """
    Helper tiện ích trả về cả phát hiện nhị phân và phân loại đa lớp
    cho một vector đặc trưng duy nhất.
    """
    binary = predict_attack_from_features(
        features=features,
        models_dir=models_dir,
        threshold=threshold,
        threshold_key=threshold_key,
    )
    multi = predict_attack_type_from_features(
        features=features,
        models_dir=models_dir,
    )

    return {
        "score": binary["score"],
        "label": binary["label"],
        "threshold_used": binary["threshold_used"],
        "threshold_name": binary["threshold_name"],
        "thresholds_flags": binary["thresholds_flags"],
        "raw_thresholds": binary["raw_thresholds"],
        "attack_type": multi["class_label"],
        "attack_type_index": multi["class_index"],
        "attack_type_probabilities": multi["class_probabilities"],
    }


def extract_features_for_event(
    event: Mapping[str, Any],
    aggregator_state: Any = None,
) -> Dict[str, float]:
    """
    Placeholder cho việc trích xuất đặc trưng thời gian thực cho một sự kiện duy nhất.

    Trong cài đặt offline, chúng ta tính đặc trưng qua `ml.feature_builder` sử dụng
    luồng sự kiện đầy đủ và cửa sổ trượt. Cho suy luận online / thời gian thực,
    chúng ta sẽ cần một thành phần stateful nhẹ (có thể tái sử dụng
    `SimpleAggregator` từ hệ thống dựa trên quy tắc hoặc một aggregator ML
    chuyên dụng) để duy trì thống kê cửa sổ trượt và tạo vector đặc trưng
    khớp với `ml.đặc trưng.ALL_FEATURES`.

    Hàm này được để lại như một placeholder mỏng, rõ ràng:
    - Nó ghi lại hợp đồng mong đợi cho tích hợp Decision Engine.
    - Nó tránh vô tình sử dụng đặc trưng không nhất quán hoặc không đầy đủ.

    Hiện tại, nó raise NotImplementedError để nhấn mạnh rằng trích xuất đặc trưng
    online phải được thiết kế cẩn thận trước khi sử dụng trong production.
    """
    raise NotImplementedError(
        "Trích xuất đặc trưng thời gian thực chưa được triển khai. "
        "Sử dụng đặc trưng offline từ `ml.feature_builder` hiện tại."
    )


__all__ = [
    "LoadedModels",
    "load_models",
    "predict_attack_from_features",
    "predict_attack_type_from_features",
    "predict_attack_and_type",
    "extract_features_for_event",
]

