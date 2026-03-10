"""
Rule Loader - Đơn giản, chỉ load 3 rule cốt lõi
"""

import json
import os
import glob
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

class Rule:
    """Rule model đơn giản"""
    
    def __init__(self, rule_dict: Dict):
        # Required fields
        self.id = rule_dict['id']
        self.name = rule_dict['name']
        self.enabled = rule_dict.get('enabled', True)
        self.priority = rule_dict.get('priority', 'medium')
        self.scope = rule_dict.get('scope', 'ip')
        self.entity_key = rule_dict.get('entity_key', 'src_ip')
        self.window = rule_dict.get('window', {'type': 'sliding', 'seconds': 60})
        self.condition = rule_dict.get('condition', {})
        self.action = rule_dict.get('action', {})
        self.severity = rule_dict.get('severity', 'medium')
        
        # Optional fields
        self.cooldown_seconds = rule_dict.get('cooldown_seconds', 300)
        self.ttl_seconds = rule_dict.get('ttl_seconds', 3600)
        self.evidence_fields = rule_dict.get('evidence_fields', [])
        self.test_cases = rule_dict.get('test_cases', [])
        
        # Cooldown tracking
        self.cooldown_until = {}
    
    def in_cooldown(self, entity_value: str) -> bool:
        """Kiểm tra cooldown cho entity"""
        if entity_value in self.cooldown_until:
            return datetime.now() < self.cooldown_until[entity_value]
        return False
    
    def record_trigger(self, entity_value: str):
        """Ghi nhận trigger và set cooldown"""
        self.cooldown_until[entity_value] = datetime.now() + timedelta(
            seconds=self.cooldown_seconds
        )
    
    def to_dict(self) -> Dict:
        """Convert sang dict"""
        return {
            'id': self.id,
            'name': self.name,
            'enabled': self.enabled,
            'priority': self.priority,
            'scope': self.scope,
            'entity_key': self.entity_key,
            'window': self.window,
            'condition': self.condition,
            'action': self.action,
            'severity': self.severity,
            'cooldown_seconds': self.cooldown_seconds,
            'ttl_seconds': self.ttl_seconds,
            'evidence_fields': self.evidence_fields,
            'test_cases': self.test_cases
        }
    
    def __repr__(self) -> str:
        return f"Rule({self.id}, {self.name})"

class RuleLoader:
    """Load 3 rule cốt lõi từ thư mục rules/"""
    
    # Danh sách 3 rule cốt lõi
    CORE_RULES = ['rapid_bruteforce', 'credential_stuffing', 'distributed_attack']
    
    def __init__(self, rules_dir: str = None):
        # Tự detect rules directory
        if rules_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            rules_dir = os.path.join(base_dir, 'detection_system', 'rule_based', 'rules')
        
        self.rules_dir = rules_dir
        self.rules: Dict[str, Rule] = {}
        self.load_core_rules()
    
    def load_core_rules(self) -> Dict[str, Rule]:
        """Chỉ load 3 rule cốt lõi"""
        self.rules = {}
        
        if not os.path.exists(self.rules_dir):
            print(f"WARNING: Rules directory not found: {self.rules_dir}")
            return self.rules
        
        print(f"Loading core rules from: {self.rules_dir}")
        
        for rule_name in self.CORE_RULES:
            json_file = os.path.join(self.rules_dir, f"{rule_name}.json")
            
            if not os.path.exists(json_file):
                print(f" Core rule file not found: {json_file}")
                continue
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    rule_data = json.load(f)
                
                # Validate required fields
                required_fields = ['id', 'name', 'scope', 'condition']
                missing_fields = [f for f in required_fields if f not in rule_data]
                
                if missing_fields:
                    print(f" Rule {rule_name} missing fields: {missing_fields}")
                    continue
                
                rule = Rule(rule_data)
                self.rules[rule.id] = rule
                print(f"Loaded: {rule.name} ({rule.id})")
                
            except json.JSONDecodeError as e:
                print(f" Invalid JSON in {json_file}: {e}")
            except Exception as e:
                print(f" Error loading {json_file}: {e}")
        
        print(f"Total core rules loaded: {len(self.rules)}")
        return self.rules
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get rule by ID"""
        return self.rules.get(rule_id)
    
    def get_enabled_rules(self) -> List[Rule]:
        """Get all enabled rules"""
        return [rule for rule in self.rules.values() if rule.enabled]
    
    def get_rules_by_scope(self, scope: str) -> List[Rule]:
        """Get enabled rules for a specific scope"""
        return [rule for rule in self.get_enabled_rules() if rule.scope == scope]
    
    def reload_rules(self):
        """Hot reload rules"""
        old_count = len(self.rules)
        self.load_core_rules()
        print(f"Rules reloaded: {old_count} -> {len(self.rules)}")