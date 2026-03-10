#data_generator/utils.py
"""
Utility functions for data generation
"""

import random
import hashlib
from datetime import datetime, timedelta

def random_timestamp(start_dt, end_dt):
    """Generate random timestamp between start and end"""
    delta = end_dt - start_dt
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return start_dt + timedelta(seconds=random_seconds)

def random_ip(pool):
    """Get random IP from pool"""
    return random.choice(pool)

def random_user_agent():
    """Get random user agent"""
    from .config import USER_AGENTS
    return random.choice(USER_AGENTS)

def random_geo():
    """Get random country code"""
    from .config import COUNTRIES
    return random.choice(COUNTRIES)

def generate_fingerprint(ip, user_agent, timestamp):
    """Generate simple device fingerprint"""
    data = f"{ip}-{user_agent[:20]}-{timestamp.timestamp():.0f}"
    return hashlib.md5(data.encode()).hexdigest()[:20]

def get_http_status(success):
    """Get HTTP status code"""
    return 200 if success else 401

def get_failure_reason(success):
    """Get failure reason"""
    if success:
        return None
    return random.choice(['Invalid credentials', 'Account locked', 'Password expired'])

def generate_request_duration(success):
    """Generate realistic request duration"""
    if success:
        return random.randint(100, 500)  # 100-500ms for success
    else:
        return random.randint(50, 300)   # 50-300ms for failure