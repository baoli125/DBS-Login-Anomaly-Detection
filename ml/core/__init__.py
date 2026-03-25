"""
Gói Core ML

Chứa chức năng lõi ML bao gồm đào tạo và suy luận.
"""

from .train_models import train_models
from .inference import load_models, LoadedModels

__all__ = ['train_models', 'load_models', 'LoadedModels']