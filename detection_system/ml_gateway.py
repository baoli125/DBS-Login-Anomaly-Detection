from __future__ import annotations

"""
ML gateway for the Detection System / Decision Engine.

This module defines a thin, explicit interface for calling the ML models from
the rule-based detection system or the web application.

Design goals:
- Centralize ML model loading & caching (`initialize_ml_models`).
- Provide a simple function `evaluate_event` that:
  - Accepts an event dict (same schema as rule-based system).
  - Optionally accepts a pre-computed ML feature vector.
  - Returns a structured ML decision payload suitable for the Decision Engine.

IMPORTANT: Real-time feature extraction from raw events to ML features is NOT
implemented here yet. For production use, a stateful aggregator (reusing
`SimpleAggregator` or a dedicated ML aggregator) must be used to compute
sliding-window features consistent with `ml.feature_builder` and
`ml.features.ALL_FEATURES`.
"""

import os
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, Mapping, Optional, Union

# Ensure project root is on sys.path so we can import `ml.*`
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.core.inference import (  # type: ignore  # noqa: E402
    LoadedModels,
    load_models,
    predict_attack_and_type,
)
from ml.features import get_feature_names  # type: ignore  # noqa: E402


MLFeatureVector = Union[Mapping[str, float], "list[float]"]


@dataclass
class MLEvaluationResult:
    """
    Normalized output shape for ML decisions.

    Fields are intentionally generic so that a higher-level Decision Engine can
    combine rule-based and ML evidence before choosing an action.
    """

    enabled: bool
    loaded: bool
    score: float
    label: int
    attack_type: Optional[str]
    thresholds: Dict[str, float]
    threshold_used: Optional[float]
    threshold_name: Optional[str]
    attack_type_probabilities: Dict[str, float]
    debug: Dict[str, Any]


_ML_MODELS: Optional[LoadedModels] = None
_ML_ENABLED: bool = False


def initialize_ml_models(models_dir: str = "models") -> bool:
    """
    Load ML models into memory and mark ML as enabled for the gateway.

    This should be called once during application startup (e.g. alongside
    `initialize_detection_system` in the web app).
    """
    global _ML_MODELS, _ML_ENABLED

    try:
        _ML_MODELS = load_models(models_dir=models_dir, use_cache=True)
        _ML_ENABLED = True
        return True
    except Exception as exc:  # pragma: no cover - defensive
        # In production, we might want to log this more formally.
        print(f"[ml_gateway] Failed to load ML models from '{models_dir}': {exc}")
        _ML_MODELS = None
        _ML_ENABLED = False
        return False


def is_ml_enabled() -> bool:
    """
    Return True if ML models have been successfully initialized.
    """
    return _ML_ENABLED and _ML_MODELS is not None


def evaluate_event(
    event: Mapping[str, Any],
    feature_vector: Optional[MLFeatureVector] = None,
) -> MLEvaluationResult:
    """
    Evaluate a single event with ML models, given a pre-computed feature vector.

    Args:
        event: Event dict with fields like `timestamp`, `username`, `src_ip`,
            `success`, `is_attack`, `attack_type`, etc. (same schema used by
            generators and rule-based system). Currently used only for debug
            context; online feature computation is **not** implemented here.
        feature_vector: Either:
            - Mapping[str, float]: `{feature_name: value}`, matching
              `ml.features.get_feature_names()`. Missing values default to 0.0.
            - List[float] / 1D array: already ordered according to
              `ml.features.get_feature_names()`.

    Returns:
        MLEvaluationResult with:
        - enabled / loaded flags (so callers can gracefully handle missing ML).
        - score / label / attack_type.
        - thresholds and debug info for higher-level policies.

    Notes:
        Real-time feature extraction (from raw event + aggregator state) is
        intentionally left to a future component. This gateway focuses only on:
        - model loading
        - prediction
        - output normalization
    """
    if not is_ml_enabled():
        return MLEvaluationResult(
            enabled=False,
            loaded=False,
            score=0.0,
            label=0,
            attack_type=None,
            thresholds={},
            threshold_used=None,
            threshold_name=None,
            attack_type_probabilities={},
            debug={"reason": "ML models not initialized"},
        )

    if feature_vector is None:
        return MLEvaluationResult(
            enabled=True,
            loaded=True,
            score=0.0,
            label=0,
            attack_type=None,
            thresholds={},
            threshold_used=None,
            threshold_name=None,
            attack_type_probabilities={},
            debug={
                "reason": "No feature_vector provided",
                "hint": "Decision Engine should supply ML features matching get_feature_names().",
            },
        )

    assert _ML_MODELS is not None  # for type checkers

    raw = predict_attack_and_type(
        features=feature_vector,
        models_dir=None,  # use already-loaded models via cache
        threshold=None,
        threshold_key="t_balanced",
    )

    return MLEvaluationResult(
        enabled=True,
        loaded=True,
        score=float(raw["score"]),
        label=int(raw["label"]),
        attack_type=str(raw.get("attack_type")) if raw.get("attack_type") is not None else None,
        thresholds={k: float(v) for k, v in (raw.get("raw_thresholds") or {}).items()},
        threshold_used=float(raw.get("threshold_used")) if raw.get("threshold_used") is not None else None,
        threshold_name=str(raw.get("threshold_name")) if raw.get("threshold_name") is not None else None,
        attack_type_probabilities={
            k: float(v) for k, v in (raw.get("attack_type_probabilities") or {}).items()
        },
        debug={
            "thresholds_flags": raw.get("thresholds_flags", {}),
            "event_summary": {
                "username": event.get("username"),
                "src_ip": event.get("src_ip"),
                "timestamp": event.get("timestamp"),
            },
        },
    )


__all__ = [
    "MLEvaluationResult",
    "initialize_ml_models",
    "is_ml_enabled",
    "evaluate_event",
]

