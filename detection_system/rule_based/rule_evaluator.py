"""
Rule Evaluator - SIMPLE VERSION với debug cơ bản
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger('RuleEvaluator')
from detection_system.rule_based.aggregator import SimpleAggregator
from detection_system.rule_based.rule_loader import Rule, RuleLoader

class Decision:
    """Decision object đơn giản"""
    
    def __init__(self, 
                 matched: bool = False,
                 rule_id: str = None,
                 action_suggestion: str = None,
                 evidence: Dict = None,
                 confidence: float = 0.0):
        self.matched = matched
        self.rule_id = rule_id
        self.action_suggestion = action_suggestion
        self.evidence = evidence or {}
        self.confidence = confidence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert sang dict"""
        return {
            'matched': self.matched,
            'rule_id': self.rule_id,
            'action_suggestion': self.action_suggestion,
            'evidence': self.evidence
        }
    
    def __repr__(self) -> str:
        return f"Decision(rule={self.rule_id}, matched={self.matched}, action={self.action_suggestion})"

class RuleEvaluator:
    """
    Rule Evaluator - SIMPLE VERSION với debug cơ bản
    """
    
    PRIORITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    
    def __init__(self, rule_loader: RuleLoader = None, debug_enabled: bool = False):
        """Khởi tạo - NHẬN tham số debug_enabled"""
        self.rule_loader = rule_loader or RuleLoader()
        self.rules = self.rule_loader.rules
        self.debug_enabled = debug_enabled  # Thêm dòng này
        
        if self.debug_enabled:
            logger.debug(f" RuleEvaluator initialized with {len(self.rules)} rules")
    
    def evaluate_condition(self, condition: Dict, metrics: Dict) -> bool:
        """Đánh giá condition với debug đơn giản"""
        condition_type = condition.get('type', 'and')
        
        if self.debug_enabled:
            logger.debug(f"   Evaluating {condition_type} condition")
        
        if condition_type == 'and':
            clauses = condition.get('clauses', [])
            for clause in clauses:
                result = self._evaluate_single_clause(clause, metrics)
                if self.debug_enabled:
                    metric = clause.get('metric')
                    op = clause.get('op')
                    value = clause.get('value')
                    actual = metrics.get(metric, 0)
                    logger.debug(f"    {metric} {op} {value}? Actual: {actual} → {result}")
                if not result:
                    return False
            return True
        
        elif condition_type == 'or':
            clauses = condition.get('clauses', [])
            for clause in clauses:
                if self._evaluate_single_clause(clause, metrics):
                    return True
            return False
        
        else:
            # Single clause
            return self._evaluate_single_clause(condition, metrics)
    
    def _evaluate_single_clause(self, clause: Dict, metrics: Dict) -> bool:
        """Đánh giá single clause"""
        metric_name = clause.get('metric')
        operator = clause.get('op')
        threshold = clause.get('value')
        
        if not metric_name or not operator:
            return False
        
        metric_value = metrics.get(metric_name, 0)
        
        try:
            if operator == '>=':
                return metric_value >= threshold
            elif operator == '>':
                return metric_value > threshold
            elif operator == '<=':
                return metric_value <= threshold
            elif operator == '<':
                return metric_value < threshold
            elif operator == '==':
                return metric_value == threshold
            elif operator == '!=':
                return metric_value != threshold
            else:
                return False
        except (TypeError, ValueError):
            return False
    
    def get_staged_action(self, rule: Rule, metrics: Dict) -> Tuple[str, Dict]:
        """Lấy staged action phù hợp"""
        action_config = rule.action
        
        if not action_config or action_config.get('type') != 'staged':
            action_name = action_config.get('action', 'alert') if action_config else 'alert'
            params = action_config.get('params', {}) if action_config else {}
            return action_name, params
        
        stages = action_config.get('stages', [])
        if not stages:
            return 'alert', {}
        
        # Tìm metric chính cho staging
        staging_metric = None
        for metric in ['failed_attempts_30s', 'failed_attempts_5m', 'unique_users', 'unique_ips']:
            if metric in str(rule.condition):
                staging_metric = metric
                break
        
        if not staging_metric:
            staging_metric = 'failed_attempts_5m'
        
        current_value = metrics.get(staging_metric, 0)
        
        # Tìm stage phù hợp
        selected_stage = stages[0]
        for stage in stages:
            threshold = stage.get('threshold', 0)
            if current_value >= threshold:
                selected_stage = stage
            else:
                break
        
        return selected_stage.get('action', 'alert'), selected_stage.get('params', {})
    
    def evaluate(self, 
                 entity: Dict[str, Any],
                 metrics_snapshot: Dict[str, Any],
                 raw_samples: List[Dict]) -> Decision:
        """
        Main evaluation method
        """
        entity_type = entity.get('type')
        entity_value = entity.get('value')
        
        if not entity_type or not entity_value:
            return Decision(matched=False)
        
        if self.debug_enabled:
            logger.debug(f"\n Evaluating rules for {entity_type}: {entity_value}")
            logger.debug(f"   Metrics: {metrics_snapshot}")
        
        # Lấy rules cho scope này
        scope_rules = self.rule_loader.get_rules_by_scope(entity_type)
        
        for rule in scope_rules:
            if not rule.enabled:
                continue
            
            if rule.in_cooldown(entity_value):
                if self.debug_enabled:
                    logger.debug(f"Rule {rule.id} in cooldown for {entity_value}")
                continue
            
            # Đánh giá condition
            if self.evaluate_condition(rule.condition, metrics_snapshot):
                if self.debug_enabled:
                    logger.debug(f"   Rule matched: {rule.name} ({rule.id})")
                
                # Record trigger
                rule.record_trigger(entity_value)
                
                # Lấy staged action
                action_name, action_params = self.get_staged_action(rule, metrics_snapshot)
                
                # Tạo evidence
                evidence = {
                    'rule_id': rule.id,
                    'rule_name': rule.name,
                    'entity_key': entity_value,
                    'detection_time': datetime.now().isoformat(),
                    'metrics': metrics_snapshot,
                    'action': action_name,
                    'action_params': action_params
                }
                
                return Decision(
                    matched=True,
                    rule_id=rule.id,
                    action_suggestion=action_name,
                    evidence=evidence,
                    confidence=0.9
                )
        
        if self.debug_enabled:
            logger.debug(f"   No rules matched")
        
        return Decision(matched=False)
    
    def evaluate_realtime(self,
                         aggregator: SimpleAggregator,
                         event: Dict[str, Any],
                         debug: bool = False) -> Optional[Decision]:
        """
        Real-time evaluation - THÊM tham số debug
        """
        # Tạm thời set debug mode
        original_debug = self.debug_enabled
        if debug:
            self.debug_enabled = True
        
        try:
            timestamp = event.get('timestamp')
            if isinstance(timestamp, str):
                try:
                    event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    event_time = datetime.now()
            else:
                event_time = timestamp or datetime.now()
            
            decisions = []
            
            # IP scope
            src_ip = event.get('src_ip')
            if src_ip:
                ip_metrics = aggregator.get_metrics_at_event_time('ip', src_ip, event)
                ip_samples = aggregator.get_evidence_samples('ip', src_ip, 5)
                
                if ip_metrics:
                    ip_decision = self.evaluate(
                        entity={'type': 'ip', 'value': src_ip},
                        metrics_snapshot=ip_metrics,
                        raw_samples=ip_samples
                    )
                    
                    if ip_decision.matched:
                        rule = self.rule_loader.get_rule(ip_decision.rule_id)
                        ip_decision._priority = rule.priority if rule else 'medium'
                        decisions.append(ip_decision)
            
            # User scope
            username = event.get('username')
            if username:
                user_metrics = aggregator.get_metrics_at_event_time('user', username, event)
                user_samples = aggregator.get_evidence_samples('user', username, 5)
                
                if user_metrics:
                    user_decision = self.evaluate(
                        entity={'type': 'user', 'value': username},
                        metrics_snapshot=user_metrics,
                        raw_samples=user_samples
                    )
                    
                    if user_decision.matched:
                        rule = self.rule_loader.get_rule(user_decision.rule_id)
                        user_decision._priority = rule.priority if rule else 'medium'
                        decisions.append(user_decision)
            
            # Thêm event vào aggregator
            aggregator.process_event(event)
            
            # Trả về decision có priority cao nhất
            if not decisions:
                return None
            
            decisions.sort(
                key=lambda d: self.PRIORITY_ORDER.get(d._priority, 0),
                reverse=True
            )
            
            return decisions[0]
            
        finally:
            # Khôi phục debug mode
            self.debug_enabled = original_debug