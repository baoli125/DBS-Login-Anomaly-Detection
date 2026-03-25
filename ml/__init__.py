"""
Gói ML cho phát hiện brute-force.

Gói này chứa:
- Đặc trưng definitions and building (`đặc trưng/`)
- Core ML training and inference (`core/`)
- Evaluation utilities (`evaluation/`)
"""

from .features import (
    EntityScope,
    FeatureSpec,
    IP_FEATURES,
    USER_FEATURES,
    PAIR_FEATURES,
    TIME_FEATURES,
    ALL_FEATURES,
    get_feature_names,
)
from .core import train_models, load_models, LoadedModels
from .evaluation import evaluate_ml_vs_rule

__all__ = [
    "EntityScope",
    "FeatureSpec",
    "IP_FEATURES",
    "USER_FEATURES",
    "PAIR_FEATURES",
    "TIME_FEATURES",
    "ALL_FEATURES",
    "get_feature_names",
]

