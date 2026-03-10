#data_generator/patterns.py

import json
import os

"""
Attack patterns definitions - SIMPLE VERSION
FIXED VERSION: All patterns now have 'ip_pool' key
"""

# Attack pattern configurations - COMPLETE WITH ip_pool
PATTERNS = {
    'normal': {
        'description': 'Normal user behavior',
        'success_rate': 0.7,
        'attempts_per_hour': 10,
        'ip_pool': 'normal',  # ← ĐÃ CÓ
        'distribution': 'random',
        'time_between_attempts': (30, 300),
        'is_attack': False
    },
    
    'weekend': {
        'description': 'Weekend user behavior',
        'success_rate': 0.90,
        'attempts_per_hour': 5,
        'ip_pool': 'normal',  # ← ĐÃ CÓ
        'distribution': 'random',
        'time_between_attempts': (300, 1800),
        'is_attack': False
    },
    
    'rapid_bruteforce': {
        'success_rate': 0.001,
        'attempts_per_second': 15,      
        'duration_seconds': 30,        
        'total_attempts': 360,          
        'attack_type': 'rapid_bruteforce',
        'ip_pool': 'attack',  
        'is_attack': True,   
        'description': 'Rapid brute-force attack'
    },

    'credential_stuffing': {
        'success_rate': 0.05,
        'attempts_per_second': 5,       
        'duration_minutes': 30,
        'total_attempts': 3600,        
        'attack_type': 'credential_stuffing',
        'ip_pool': 'attack',
        'is_attack': True,
        'users_targeted': 'multiple',
        'description': 'Credential stuffing from data breach'
    },
    
    'distributed_attack': {
        'success_rate': 0.0,
        'ips_count': 15,                # THÊM: số IP
        'attempts_per_ip_per_second': 3, # THÊM: mỗi IP 3 attempts/giây
        'duration_seconds': 30,
        'total_attempts': 900,          # 10 × 3 × 30 = 900
        'attack_type': 'distributed_attack',
        'ip_pool': 'attack_multi',
        'is_attack': True,
        'users_targeted': 'single',
        'description': 'Distributed attack from multiple IPs'
    },
    
    'targeted_slow_low': {
        'success_rate': 0.0,
        'attempts_per_minute': 2,       # ĐỔI: từ 3/hour → 2/minute
        'duration_hours': 12,
        'total_attempts': 1440,         # 2 × 60 × 12 = 1440
        'attack_type': 'targeted_slow_low',
        'ip_pool': 'attack',
        'is_attack': True,
        'users_targeted': 'single',
        'description': 'Slow and low targeted attack'
    }
}

def get_pattern(pattern_name):
    """Get pattern configuration"""
    return PATTERNS.get(pattern_name, PATTERNS['normal'])

def is_attack_pattern(pattern_name):
    """Check if pattern is an attack"""
    pattern = PATTERNS.get(pattern_name, {})
    return pattern.get('is_attack', False)

def load_scenario_config(scenario_name):
    """Load scenario from JSON file (simplified)"""
    # This is a simplified version - in reality would load from scenarios/ folder
    return PATTERNS.get(scenario_name, {})