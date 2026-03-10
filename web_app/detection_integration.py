"""
Tích hợp Detection System vào Web App - FIXED VERSION
"""

import sys
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Thêm path để import detection system
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# SỬA phần import trong detection_integration.py
try:
    from detection_system.rule_based.aggregator import SimpleAggregator
    from detection_system.rule_based.rule_evaluator import RuleEvaluator  # SỬA: KHÔNG phải DebugRuleEvaluator
    from detection_system.rule_based.rule_loader import RuleLoader
    
    print(" Detection system modules imported successfully")
    
except ImportError as e:
    print(f" Failed to import detection system: {e}")
    print("  Running in fallback mode without detection")
    
    # Fallback classes
    class SimpleAggregator:
        def __init__(self):
            print("  Using fallback aggregator")
        
        def process_event(self, event):
            pass
        
        def get_metrics_at_event_time(self, scope, entity_key, event):
            return {}
        
        def get_evidence_samples(self, scope, entity_key, limit=5):
            return []
    
    class RuleEvaluator:  # SỬA: Đúng tên class
        def __init__(self, debug_enabled=False):
            print("  Using fallback evaluator")
            self.debug_enabled = debug_enabled
        
        def evaluate_realtime(self, aggregator, event, debug=False):
            return None
        
# Global instances
AGGREGATOR = None
RULE_EVALUATOR = None

def initialize_detection_system(debug_enabled=False):
    """Khởi tạo detection system - FIXED"""
    global AGGREGATOR, RULE_EVALUATOR
    
    try:
        print("\n Initializing Detection System...")
        
        # 1. Khởi tạo aggregator
        AGGREGATOR = SimpleAggregator()
        print(" Aggregator initialized")
        
        # 2. Khởi tạo rule evaluator với debug_enabled - SỬA: Dùng RuleEvaluator
        RULE_EVALUATOR = RuleEvaluator(debug_enabled=debug_enabled)
        print(" Rule Evaluator initialized")
        
        # 3. Load 3 core rules
        rule_loader = RuleLoader()
        print(f" Loaded {len(rule_loader.rules)} core rules")
        
        print(" Detection System READY")
        return True
        
    except Exception as e:
        print(f" Failed to initialize detection system: {e}")
        import traceback
        traceback.print_exc()
        return False

def process_login_event(username: str, src_ip: str, success: bool, user_agent: str = None, debug: bool = False) -> Dict[str, Any]:
    """
    Xử lý một sự kiện đăng nhập với detection system - FIXED
    """
    global AGGREGATOR, RULE_EVALUATOR
    
    result = {
        'should_block': False,
        'block_reason': None,
        'alert_message': None,
        'detection_type': 'none',
        'confidence': 0.0,
        'metrics': {},
        'debug_info': {}
    }
    
    # Nếu detection system không được khởi tạo
    if not AGGREGATOR or not RULE_EVALUATOR:
        result['detection_type'] = 'system_not_initialized'
        return result
    
    try:
        # 1. Tạo event dictionary
        event = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'src_ip': src_ip,
            'success': success,
            'user_agent': user_agent or '',
            'request_path': '/login',
            'http_method': 'POST',
            'http_status': 200 if success else 401,
            'failure_reason': None if success else 'Invalid credentials',
            'is_attack': False,
            'attack_type': None
        }
        
        # 2. Chạy real-time evaluation với debug
        decision = RULE_EVALUATOR.evaluate_realtime(
            aggregator=AGGREGATOR,
            event=event,
            debug=debug  # Truyền tham số debug
        )
        
        # 3. Nếu có decision (rule matched)
        if decision and decision.matched:
            result.update({
                'detection_type': 'rule_based',
                'rule_id': decision.rule_id,
                'action': decision.action_suggestion,
                'confidence': 0.85,
                'debug_info': decision.evidence
            })
            
            # Kiểm tra action type
            action = decision.action_suggestion.lower()
            
            if 'block' in action:
                result['should_block'] = True
                result['block_reason'] = f"Rule triggered: {decision.rule_id}"
                result['alert_message'] = f" IP Blocked: {src_ip} - {decision.rule_id}"
            
            elif 'alert' in action:
                result['alert_message'] = f" Alert: {src_ip} - {decision.rule_id}"
            
            elif 'throttle' in action:
                result['alert_message'] = f"⏱ Throttle: {src_ip} - {decision.rule_id}"
        
        # 4. Lấy metrics cho debugging (nếu debug)
        if debug:
            try:
                ip_metrics = AGGREGATOR.get_metrics_at_event_time('ip', src_ip, event)
                result['metrics'] = {
                    'failed_attempts_30s': ip_metrics.get('failed_attempts_30s', 0),
                    'failed_attempts_5m': ip_metrics.get('failed_attempts_5m', 0),
                    'unique_users': ip_metrics.get('unique_users', 0),
                    'attempts_per_sec_30s': ip_metrics.get('attempts_per_sec_30s', 0)
                }
            except:
                pass
        
    except Exception as e:
        print(f" Error in process_login_event: {e}")
        import traceback
        traceback.print_exc()
        result['detection_type'] = 'error'
        result['error'] = str(e)
    
    return result

def get_blocked_ips() -> list:
    """Lấy danh sách IP bị block từ database"""
    try:
        from .models import Database
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip_address, reason, blocked_at, blocked_until 
            FROM blocked_ips 
            WHERE blocked_until > NOW()
            ORDER BY blocked_at DESC
        ''')
        
        blocked_ips = cursor.fetchall()
        conn.close()
        
        return [dict(ip) for ip in blocked_ips]
        
    except Exception as e:
        print(f"Error getting blocked IPs: {e}")
        return []

def is_ip_blocked(ip_address: str) -> bool:
    """Kiểm tra xem IP có bị block không"""
    try:
        from .models import Database
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) as count 
            FROM blocked_ips 
            WHERE ip_address = %s AND blocked_until > NOW()
        ''', (ip_address,))
        
        count = cursor.fetchone()['count']
        conn.close()
        
        return count > 0
        
    except Exception as e:
        print(f"Error checking IP block status: {e}")
        return False