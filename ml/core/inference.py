from __future__ import annotations

"""
Inference utilities for brute-force detection & attack classification ML models.

This module provides:
- Lazy, cached loading of trained models and scaler from the `models/` directory.
- Helpers to turn a feature vector (dict or array) into model-ready numpy arrays.
- High-level prediction helpers for:
  - Binary detection: P(is_attack=1) + threshold-based labels and flags.
  - Multi-class classification: attack_type label + probability distribution.

The goal is to expose a stable API that can be used by:
- Offline evaluation scripts (`ml.evaluate_ml_vs_rule`).
- Future real-time Decision Engine / web_app integrations.
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
    Container for all ML artifacts needed at inference time.

    Attributes:
        binary_model: Trained binary classifier with `predict_proba`.
        multiclass_model: Trained multi-class classifier with `predict_proba`.
        scaler: Fitted sklearn scaler (StandardScaler).
        metadata: Dict loaded from `model_metadata.json`.
        feature_names: Ordered list of feature names expected by the models.
        class_labels: Ordered list of class labels for the multi-class model.
        thresholds: Dict of binary thresholds (e.g. t_high_recall, t_balanced, t_high_precision).
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
    Resolve the models directory, defaulting to `<project_root>/models`.
    """
    if models_dir:
        return models_dir

    # Default: `<project_root>/models`
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(project_root, "models")


def load_models(models_dir: Optional[str] = None, use_cache: bool = True) -> LoadedModels:
    """
    Load binary & multi-class models, scaler, and metadata from disk.

    Args:
        models_dir: Directory containing:
            - `binary_model.joblib`
            - `multiclass_model.joblib`
            - `scaler.joblib`
            - `model_metadata.json`
          If None, defaults to `<project_root>/models`.
        use_cache: If True, keep a per-directory cache in memory.

    Returns:
        LoadedModels instance.
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

    # Feature list is stored in metadata, but we fall back to the code-defined schema.
    feature_names_meta = metadata.get("feature_names")
    feature_names = list(feature_names_meta) if feature_names_meta is not None else get_feature_names()

    label_encoding = metadata.get("label_encoding", {})
    class_labels = list(label_encoding.get("classes", []))

    thresholds_dict = {}
    binary_meta = metadata.get("binary_model", {})
    metrics = binary_meta.get("metrics", {})
    thresholds_in_metrics = metrics.get("thresholds")
    if isinstance(thresholds_in_metrics, dict):
        # Expect keys: t_high_recall, t_balanced, t_high_precision
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
    Normalize feature input (dict or array-like) into shape (1, n_features).

    Args:
        features:
            - Mapping[str, float]: interpreted as `{feature_name: value}`; missing
              features are filled with 0.0, extras are ignored.
            - Sequence[float] or numpy array: must already be ordered according to
              `feature_names` and have length == len(feature_names).
        feature_names: Feature ordering. If None and `features` is a mapping, we
            use `ml.features.get_feature_names()`. If None and `features` is not a
            mapping, a ValueError is raised.
    """
    if feature_names is None:
        feature_names = get_feature_names()
    feature_names = list(feature_names)

    if isinstance(features, Mapping):
        row = [float(features.get(name, 0.0)) for name in feature_names]
        arr = np.asarray(row, dtype=float).reshape(1, -1)
        return arr

    # Sequence / ndarray path
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
    Predict binary attack score and label from a single feature vector.

    Args:
        features: Single-row feature input (dict or array-like).
        models_dir: Directory containing model artifacts (see `load_models`).
        threshold: Explicit numeric decision threshold. If provided, overrides
            `threshold_key`.
        threshold_key: Name of pre-computed threshold in model metadata:
            - 't_high_recall'
            - 't_balanced' (default)
            - 't_high_precision'

    Returns:
        {
            'score': float,               # P(is_attack=1)
            'label': int,                 # 0 or 1
            'threshold_used': float,
            'threshold_name': str,
            'thresholds_flags': {         # convenience flags vs known thresholds
                'above_high_recall': bool,
                'above_balanced': bool,
                'above_high_precision': bool,
            },
            'raw_thresholds': { ... },    # all thresholds from metadata
        }
    """
    models = load_models(models_dir=models_dir, use_cache=True)
    X = _features_to_array(features, feature_names=models.feature_names)
    X_scaled = models.scaler.transform(X)

    # Binary probability (assume is_attack class is column 1)
    score = float(models.binary_model.predict_proba(X_scaled)[:, 1][0])

    # Decide which threshold to use
    thresholds = dict(models.thresholds)
    if threshold is not None:
        used_threshold = float(threshold)
        threshold_name = "custom"
    else:
        if threshold_key not in thresholds:
            # Fallback to 0.5 if metadata missing
            used_threshold = 0.5
        else:
            used_threshold = float(thresholds[threshold_key])
        threshold_name = threshold_key

    label = int(score >= used_threshold)

    # Convenience flags relative to known thresholds (if present)
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
    Predict attack_type (multi-class) from a single feature vector.

    Args:
        features: Single-row feature input (dict or array-like).
        models_dir: Directory containing model artifacts (see `load_models`).

    Returns:
        {
            'class_index': int,
            'class_label': str,
            'class_probabilities': {label: prob, ...},
        }
    """
    models = load_models(models_dir=models_dir, use_cache=True)
    X = _features_to_array(features, feature_names=models.feature_names)
    X_scaled = models.scaler.transform(X)

    proba = models.multiclass_model.predict_proba(X_scaled)[0]
    if not models.class_labels:
        # If label encoding is missing, index labels as strings
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
    Convenience helper that returns both binary detection and multi-class
    classification for a single feature vector.
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
    Placeholder for real-time feature extraction for a single event.

    In the offline setting we compute features via `ml.feature_builder` using
    full event streams and sliding windows. For online / real-time inference,
    we will need a lightweight stateful component (likely reusing
    `SimpleAggregator` from the rule-based system or a dedicated ML
    aggregator) to maintain sliding-window statistics and produce a feature
    vector matching `ml.features.ALL_FEATURES`.

    This function is intentionally left as a thin, explicit placeholder:
    - It documents the expected contract for Decision Engine integration.
    - It avoids accidentally using inconsistent or partial features.

    For now, it raises NotImplementedError to highlight that online feature
    extraction must be designed carefully before use in production.
    """
    raise NotImplementedError(
        "Real-time feature extraction is not yet implemented. "
        "Use offline features from `ml.feature_builder` for now."
    )


__all__ = [
    "LoadedModels",
    "load_models",
    "predict_attack_from_features",
    "predict_attack_type_from_features",
    "predict_attack_and_type",
    "extract_features_for_event",
]

