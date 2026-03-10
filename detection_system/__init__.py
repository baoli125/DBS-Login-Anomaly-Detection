"""
Detection System Package
"""

from detection_system.rule_based import (
    SimpleAggregator, 
    RuleLoader, 
    RuleEvaluator
)

__version__ = "1.0.0"
__all__ = [
    'SimpleAggregator',
    'RuleLoader', 
    'RuleEvaluator'
]