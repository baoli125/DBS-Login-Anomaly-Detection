"""
Rule-based detection system package - UPDATED
"""

from detection_system.rule_based.aggregator import SimpleAggregator
from detection_system.rule_based.rule_loader import RuleLoader
from detection_system.rule_based.rule_evaluator import RuleEvaluator, Decision

__all__ = [
    'SimpleAggregator', 
    'RuleLoader', 
    'RuleEvaluator',
    'Decision'
]