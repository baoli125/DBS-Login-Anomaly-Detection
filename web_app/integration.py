"""
Complete Web App Integration for EaglePro Detection System
Tích hợp: Rule-Based + ML + Classification + Agent Decision Engine
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import logging

# Logging setup
logger = logging.getLogger('Detection')
logger.setLevel(logging.DEBUG)

# ==================== DETECTION SYSTEM IMPORTS ====================

try:
    from detection_system.rule_based.aggregator import SimpleAggregator
    from detection_system.rule_based.rule_evaluator import RuleEvaluator
    from detection_system.rule_based.rule_loader import RuleLoader
    from agent.core.agent import ResponseAgent
    from classification.core.classifier import EventClassifier
    from ml.core.inference import predict_attack_and_type, load_models
    
    logger.info(" All detection modules imported successfully")
    DETECTION_AVAILABLE = True
except Exception as e:
    logger.warning(f"  Some detection modules not available: {e}")
    DETECTION_AVAILABLE = False

# ==================== GLOBAL INSTANCES ====================

AGGREGATOR = None
RULE_EVALUATOR = None
RESPONSE_AGENT = None
EVENT_CLASSIFIER = None
ML_MODELS = None
ML_MODELS_DIR = None

# In-memory storage for blocked IPs (can be replaced with DB)
BLOCKED_IPS = {}
ACTIVE_ALERTS = []

# ==================== INITIALIZATION ====================

def initialize_detection_system(debug_enabled=False):
    """Initialize complete detection system"""
    global AGGREGATOR, RULE_EVALUATOR, RESPONSE_AGENT, EVENT_CLASSIFIER, ML_MODELS
    
    logger.setLevel(logging.DEBUG if debug_enabled else logging.INFO)
    
    try:
        logger.info(" Initializing Detection System...")
        
        # 1. Rule-Based System
        AGGREGATOR = SimpleAggregator()
        logger.info(" Aggregator initialized")
        
        RULE_EVALUATOR = RuleEvaluator(debug_enabled=debug_enabled)
        logger.info(" Rule Evaluator initialized")
        
        rule_loader = RuleLoader()
        logger.info(f" Loaded {len(rule_loader.rules)} core rules")
        
        # 2. Response Agent
        try:
            RESPONSE_AGENT = ResponseAgent()
            logger.info(" Response Agent initialized")
        except Exception as e:
            logger.warning(f"  Response Agent not available: {e}")
        
        # 3. ML System
        try:
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            models_dir = os.path.join(project_root, "models")
            EVENT_CLASSIFIER = EventClassifier(models_dir=models_dir)
            ML_MODELS = load_models(models_dir=models_dir)
            globals()['ML_MODELS_DIR'] = models_dir
            logger.info(" ML System initialized")
        except Exception as e:
            EVENT_CLASSIFIER = None
            ML_MODELS = None
            logger.warning(f"  ML System not available, running in rule-only mode: {e}")
        
        logger.info(" Detection System READY")
        return True
        
    except Exception as e:
        logger.error(f" Detection system initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# ==================== DETECTION / CLASSIFICATION ====================

def process_login_event(
    username: str,
    src_ip: str,
    success: bool,
    user_agent: str = None,
    debug: bool = False
) -> Dict[str, Any]:
    """
    Process login event with complete detection pipeline
    
    Returns:
        Dict with: should_block, block_reason, alert_message, detection_type, etc.
    """
    
    result = {
        'should_block': False,
        'block_reason': None,
        'alert_message': None,
        'detection_type': 'none',
        'attack_type': 'unknown',
        'confidence': 0.0,
        'risk_score': 0.0,
        'action': 'allow',
        'needs_2fa': False,
        'rule_triggered': None,
        'ml_prediction': {},
        'metrics': {},
    }
    
    if not DETECTION_AVAILABLE:
        return result
    
    try:
        # ==================== RULE-BASED DETECTION ====================
        if AGGREGATOR and RULE_EVALUATOR:
            # Create event
            event = {
                'timestamp': datetime.now(),
                'username': username,
                'src_ip': src_ip,
                'success': success,
                'user_agent': user_agent or '',
                'event_type': 'auth'
            }

            # Process through aggregator
            AGGREGATOR.process_event(event)

            # Evaluate rules
            rule_decision = RULE_EVALUATOR.evaluate_realtime(
                AGGREGATOR, event, debug=debug
            )

            if rule_decision:
                result['rule_triggered'] = rule_decision.rule_id
                result['detection_type'] = 'rule_based'
                result['confidence'] = rule_decision.confidence
                result['metrics'] = rule_decision.evidence or {}
                result['attack_type'] = rule_decision.rule_id or 'rule_based'

                logger.info(f"Rule triggered: {rule_decision.rule_id} for ip={src_ip}, user={username}")
                logger.debug(f"Evidence: {rule_decision.evidence}")

        # ==================== ML DETECTION ====================
        if not success and EVENT_CLASSIFIER and ML_MODELS:
            try:
                # Prepare features for ML based on aggregator window metrics
                features = build_ml_features(event, AGGREGATOR)
                features['username'] = username
                features['src_ip'] = src_ip
                features['user_agent'] = user_agent or ''
                features['timestamp'] = datetime.now().isoformat()

                # ML Inference
                ml_result = predict_attack_and_type(
                    features=features,
                    models_dir=ML_MODELS_DIR
                )

                if ml_result:
                    is_attack_flag = bool(ml_result.get('label', 0))
                    ml_pred_type = ml_result.get('attack_type', 'unknown')
                    result['ml_prediction'] = {
                        'attack_type': ml_pred_type,
                        'score': ml_result.get('score', 0),
                        'is_attack': is_attack_flag,
                        'label': ml_result.get('label'),
                        'threshold_name': ml_result.get('threshold_name'),
                    }

                    # Ensure attack_type reflects ML output when no rule or combined
                    if result['detection_type'] in ('none', 'ml'):
                        result['attack_type'] = ml_pred_type
                    else:
                        # combined (rule + ml) keep rule priority but include ML type as info
                        result['attack_type'] = result.get('attack_type', 'unknown') or ml_pred_type

                    if is_attack_flag:
                        result['detection_type'] = 'ml' if result['detection_type'] == 'none' else 'combined'
                        logger.info(f"ML ALERT: {ml_pred_type} (score={ml_result.get('score'):.2f}) from {src_ip} targeting {username}")

            except Exception as e:
                logger.warning(f"ML detection error: {e}")

        # ==================== AGENT DECISION ENGINE ====================
        if RESPONSE_AGENT:
            try:
                # Determine action based on combined detection
                ml_score = result['ml_prediction'].get('score', 0)
                rule_score = result['confidence']

                # Fixed ML block threshold, up to you to tune
                ml_block_threshold = 0.8

                if rule_score > 0 and ml_score > 0:
                    risk_score = rule_score * 0.6 + ml_score * 0.4
                elif rule_score > 0:
                    risk_score = rule_score
                elif ml_score > 0:
                    risk_score = ml_score
                else:
                    risk_score = 0.0

                # Force ML-heavy block at threshold (ensures ml >= 0.8 is not ignored).
                if ml_score >= ml_block_threshold:
                    risk_score = max(risk_score, ml_score)

                result['risk_score'] = risk_score

                # Decision logic
                if ml_score >= ml_block_threshold:
                    result['action'] = 'block'
                    result['should_block'] = True
                    result['block_reason'] = 'High ML confidence (>=0.8)'
                elif risk_score > 0.85:
                    result['action'] = 'block'
                    result['should_block'] = True
                    result['block_reason'] = 'High risk detected'
                elif risk_score > 0.6:
                    result['action'] = 'throttle'
                    result['needs_2fa'] = True
                elif risk_score > 0.4:
                    result['action'] = 'challenge'
                    result['needs_2fa'] = True
                else:
                    result['action'] = 'allow'

                # Log for agent processing only when action not allow
                if result['action'] != 'allow':
                    logger.info(f"Agent decision: action={result['action']}, risk_score={risk_score:.2f}")
                else:
                    logger.debug(f"Agent decision: allow (risk_score={risk_score:.2f})")

            except Exception as e:
                logger.warning(f"Agent decision error: {e}")
        
        # ==================== CREATE ALERT IF NEEDED ====================
        if result['detection_type'] != 'none':
            alert = {
                'id': len(ACTIVE_ALERTS) + 1,
                'timestamp': datetime.now(),
                'username': username,
                'src_ip': src_ip,
                'alert_type': result['detection_type'],
                'attack_type': result['attack_type'],
                'rule_triggered': result['rule_triggered'],
                'ml_score': result.get('ml_prediction', {}).get('score'),
                'risk_score': result['risk_score'],
                'action': result['action'],
                'status': 'active'
            }

            ACTIVE_ALERTS.append(alert)
            logger.debug(f"Alert queued: {alert}")
        
        # ==================== IP BLOCKING ====================
        if result['should_block']:
            block_duration = 3600  # 1 hour
            BLOCKED_IPS[src_ip] = {
                'blocked_at': datetime.now(),
                'expires_at': datetime.now() + timedelta(seconds=block_duration),
                'reason': result['block_reason'],
                'alert_id': alert['id'] if result['detection_type'] != 'none' else None
            }
            logger.warning(f"BLOCKED: IP {src_ip} for 1 hour (risk={result['risk_score']:.2f})")
        
        return result
        
    except Exception as e:
        logger.error(f"Error processing login event: {e}")
        import traceback
        traceback.print_exc()
        return result

# ==================== HELPER FUNCTIONS ====================

def build_ml_features(event: Dict[str, Any], aggregator: Optional[SimpleAggregator]) -> Dict[str, float]:
    """Build ML features from aggregator statistics for this event."""
    timestamp = event.get('timestamp') or datetime.now()
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except Exception:
            timestamp = datetime.now()

    base = {
        'ip_attempts_1s': 0.0,
        'ip_attempts_5s': 0.0,
        'ip_attempts_30s': 0.0,
        'ip_failed_rate_30s': 0.0,
        'ip_unique_users_5m': 0.0,
        'ip_avg_interarrival_30s': 0.0,
        'user_failed_5m': 0.0,
        'user_unique_ips_5m': 0.0,
        'user_unique_ips_1h': 0.0,
        'user_success_streak': 0.0,
        'pair_attempts_5m': 0.0,
        'pair_success_rate_5m': 0.0,
        'hour_sin': 0.0,
        'hour_cos': 0.0,
        'is_business_hours': 0.0,
    }

    if aggregator is None:
        return base

    src_ip = event.get('src_ip')
    username = event.get('username')
    pair_key = f"{src_ip}:{username}" if src_ip and username else None

    # Load aggregated values from existing state
    if src_ip:
        ip_metrics = aggregator.get_metrics_at_event_time('ip', src_ip, event)
        base['ip_attempts_1s'] = float(ip_metrics.get('total_1s', 0) or 0)
        base['ip_attempts_5s'] = float(ip_metrics.get('total_5s', 0) or 0)
        base['ip_attempts_30s'] = float(ip_metrics.get('total_30s', 0) or 0)
        base['ip_failed_rate_30s'] = float(ip_metrics.get('failed_30s', 0) / ip_metrics.get('total_30s', 1)) if ip_metrics.get('total_30s', 0) > 0 else 0.0
        base['ip_unique_users_5m'] = float(ip_metrics.get('unique_users', 0) or 0)
        base['ip_avg_interarrival_30s'] = float(ip_metrics.get('attempts_per_sec_30s', 0) or 0)

    if username:
        user_metrics = aggregator.get_metrics_at_event_time('user', username, event)
        base['user_failed_5m'] = float(user_metrics.get('failed_5m', 0) or 0)
        base['user_unique_ips_5m'] = float(user_metrics.get('unique_ips_5m', 0) or 0)
        base['user_unique_ips_1h'] = float(user_metrics.get('unique_ips_1h', 0) or 0)
        base['user_success_streak'] = float(user_metrics.get('success_rate', 0) or 0)

    if pair_key:
        pair_metrics = aggregator.get_metrics_at_event_time('pair', pair_key, event)
        base['pair_attempts_5m'] = float(pair_metrics.get('total_5m', 0) or 0)
        base['pair_success_rate_5m'] = float(pair_metrics.get('success_rate', 0) or 0)

    # Time-based features
    hour = timestamp.hour if hasattr(timestamp, 'hour') else datetime.now().hour
    import math
    base['hour_sin'] = math.sin(2 * math.pi * hour / 24)
    base['hour_cos'] = math.cos(2 * math.pi * hour / 24)
    base['is_business_hours'] = 1.0 if 8 <= hour < 18 else 0.0

    return base


def is_ip_blocked(ip: str) -> bool:
    """Check if IP is currently blocked"""
    if ip not in BLOCKED_IPS:
        return False
    
    block_info = BLOCKED_IPS[ip]
    if datetime.now() > block_info['expires_at']:
        del BLOCKED_IPS[ip]
        return False
    
    return True

def get_blocked_ips() -> List[Dict[str, Any]]:
    """Get list of currently blocked IPs"""
    # Clean up expired blocks
    expired = [ip for ip, info in BLOCKED_IPS.items() 
               if datetime.now() > info['expires_at']]
    for ip in expired:
        del BLOCKED_IPS[ip]
    
    return [
        {
            'ip': ip,
            'blocked_at': info['blocked_at'].isoformat(),
            'expires_at': info['expires_at'].isoformat(),
            'reason': info['reason'],
            'alert_id': info.get('alert_id')
        }
        for ip, info in BLOCKED_IPS.items()
    ]

def get_active_alerts(limit: int = 100) -> List[Dict[str, Any]]:
    """Get active/recent alerts"""
    active = [a for a in ACTIVE_ALERTS if a['status'] == 'active']
    return sorted(active, key=lambda x: x['timestamp'], reverse=True)[:limit]

def resolve_alert(alert_id: int, resolution: str = 'resolved'):
    """Mark alert as resolved"""
    for alert in ACTIVE_ALERTS:
        if alert['id'] == alert_id:
            alert['status'] = resolution
            alert['resolved_at'] = datetime.now()
            logger.info(f" Alert {alert_id} marked as {resolution}")
            return True
    return False

def get_detection_stats() -> Dict[str, Any]:
    """Get detection statistics"""
    return {
        'total_alerts': len(ACTIVE_ALERTS),
        'active_alerts': len([a for a in ACTIVE_ALERTS if a['status'] == 'active']),
        'blocked_ips': len(BLOCKED_IPS),
        'rule_based_alerts': len([a for a in ACTIVE_ALERTS if a['alert_type'] == 'rule_based']),
        'ml_alerts': len([a for a in ACTIVE_ALERTS if a['alert_type'] == 'ml']),
        'combined_alerts': len([a for a in ACTIVE_ALERTS if a['alert_type'] == 'combined']),
    }
