#data_generator/generator.py
"""
Main data generator - SIMPLE VERSION (Fixed for design principles)
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import os

from .config import *
from .utils import *
from ..patterns.patterns import get_pattern, is_attack_pattern, load_scenario_config

class SimpleDataGenerator:
    """Simple data generator for 8-week project"""
    
    def __init__(self, seed=42):
        random.seed(seed)
        self.users = USERS
        self.normal_ips = NORMAL_IPS
        self.attack_ips = ATTACK_IPS
            
    def generate_event(self, 
                    pattern: str,
                    timestamp: datetime,
                    is_attack: bool = False,
                    attack_type: str = None,
                    targeted_user: str = None,
                    fixed_ip: str = None,
                    force_success: Optional[bool] = None) -> Dict[str, Any]:
        
        pattern_config = get_pattern(pattern)
        
        # Select user - FIXED VERSION
        user = None
        if targeted_user:
            # Tìm chính xác user
            for u in self.users:
                if u['username'] == targeted_user:
                    user = u
                    break
            if not user:
                print(f"  WARNING: User '{targeted_user}' not found in user list!")
                print(f"   Available users: {[u['username'] for u in self.users]}")
                user = random.choice(self.users)
        else:
            user = random.choice(self.users)
        
        # Select IP - FIXED
        if fixed_ip:
            src_ip = fixed_ip
        elif pattern_config.get('ip_pool') == 'attack':
            src_ip = random_ip(self.attack_ips)
        elif pattern_config.get('ip_pool') == 'attack_multi':
            target_username = targeted_user or user['username']
            ip_idx = hash(target_username) % len(self.attack_ips)
            src_ip = self.attack_ips[ip_idx]
        else:
            src_ip = random_ip(self.normal_ips)
        
        # Success rate - LUÔN dùng từ pattern (trừ khi force_success được chỉ định)
        success_rate = pattern_config.get('success_rate', 0.7)
        success = force_success if force_success is not None else (random.random() < success_rate)
        
        # Generate event (giữ nguyên)
        event = {
            'timestamp': timestamp.isoformat(),
            'username': user['username'],
            'src_ip': src_ip,
            'success': success,
            'user_agent': random_user_agent(),
            'request_path': '/login',
            'http_method': 'POST',
            'http_status': 200 if success else 401,
            'failure_reason': None if success else random.choice(['Invalid credentials', 'Account locked']),
            'request_duration_ms': random.randint(50, 200) if success else random.randint(20, 100),
            'geo': random_geo(),
            'device_fingerprint': generate_fingerprint(src_ip, random_user_agent(), timestamp),
            'is_attack': is_attack,
            'attack_type': attack_type
        }
        
        return event

    # 2. Thêm hàm generate_attack_with_fixed_ip() cho rapid attack
    def generate_rapid_attack_fixed(self, start_time, duration_seconds=30):
        """Tạo rapid attack ĐÚNG NGHĨA: 1 IP → 1 USER → 400 attempts trong 30s"""
        events = []
        attack_ip = random.choice(self.attack_ips)
        target_user = random.choice(self.users)['username']
        
        # 400 attempts in 30s = ~13.3 attempts/second
        attempts_per_second = 13.3
        total_attempts = int(duration_seconds * attempts_per_second)
        
        for i in range(total_attempts):
            ts = start_time + timedelta(seconds=i/attempts_per_second)
            
            event = {
                'timestamp': ts.isoformat(),
                'username': target_user,  # ← LUÔN CÙNG USER
                'src_ip': attack_ip,      # ← LUÔN CÙNG IP
                'success': False,         # ← 100% failed
                'user_agent': random_user_agent(),
                'request_path': '/login',
                'http_method': 'POST',
                'http_status': 401,
                'failure_reason': 'Invalid credentials',
                'request_duration_ms': random.randint(50, 150),
                'geo': random_geo(),
                'device_fingerprint': generate_fingerprint(attack_ip, random_user_agent(), ts),
                'is_attack': True,
                'attack_type': 'rapid_bruteforce'  # ← ĐÚNG LABEL
            }
            events.append(event)
        
        return events
    
    def generate_normal_traffic(self, start_time, end_time, events_per_hour=50):
        """Phase 1: build schedule, sort by ts, then assign sticky IP in time order (max 1 IP per user per 10min)."""
        duration_hours = (end_time - start_time).total_seconds() / 3600
        total_events = int(duration_hours * events_per_hour)
        burst_multiplier = 1.0
        if random.random() < 0.1:
            burst_multiplier = random.uniform(1.5, 3.0)
        total_events = int(total_events * burst_multiplier)
        schedule = []
        for _ in range(total_events):
            ts = random_timestamp(start_time, end_time)
            user = random.choice(self.users)
            is_success = random.random() < 0.70
            if not is_success and random.random() < 0.15:
                schedule.append((ts, user, False))
                if random.random() < 0.5:
                    schedule.append((ts + timedelta(seconds=2), user, random.random() < 0.70))
            else:
                schedule.append((ts, user, None))
        schedule.sort(key=lambda x: x[0])
        user_sticky = {}
        sticky_minutes = 10

        def get_sticky_ip(username: str, t: datetime) -> str:
            if username in user_sticky:
                ip, expiry = user_sticky[username]
                if t <= expiry:
                    return ip
            ip = random_ip(self.normal_ips)
            user_sticky[username] = (ip, t + timedelta(minutes=sticky_minutes))
            return ip

        events = []
        for ts, user, force_success in schedule:
            ip = get_sticky_ip(user['username'], ts)
            if force_success is None:
                event = self.generate_event(
                    'normal', ts, is_attack=False,
                    targeted_user=user['username'], fixed_ip=ip
                )
            else:
                event = self.generate_event(
                    'normal', ts, is_attack=False,
                    targeted_user=user['username'], fixed_ip=ip,
                    force_success=force_success
                )
            events.append(event)
        return events
    
    def generate_weekend_traffic(self,
                                start_time: datetime,
                                end_time: datetime) -> List[Dict]:
        """Generate weekend traffic (lower volume, higher success rate)"""
        events = []
        duration_hours = (end_time - start_time).total_seconds() / 3600
        total_events = int(duration_hours * 50)  # 50 attempts per hour (vs 100 normal)
        
        for _ in range(total_events):
            ts = random_timestamp(start_time, end_time)
            # Weekend has higher success rate (people remember passwords better?)
            success = random.random() < 0.90  # 90% success rate
            
            user = random.choice(self.users)
            src_ip = random_ip(self.normal_ips)
            
            event = {
                'timestamp': ts.isoformat(),
                'username': user['username'],
                'src_ip': src_ip,
                'success': success,
                'user_agent': random_user_agent(),
                'request_path': '/login',
                'http_method': 'POST',
                'http_status': get_http_status(success),
                'failure_reason': get_failure_reason(success),
                'request_duration_ms': generate_request_duration(success),
                'geo': random_geo(),
                'device_fingerprint': generate_fingerprint(src_ip, random_user_agent(), ts),
                'is_attack': False,
                'attack_type': None
            }
            events.append(event)
        
        return events
    
    def generate_attack_traffic(self,
                            pattern: str,
                            start_time: datetime,
                            end_time: datetime) -> List[Dict]:
        """Generate attack traffic based on pattern - UPDATED VERSION"""
        events = []
        pattern_config = get_pattern(pattern)
        is_attack = pattern_config.get('is_attack', False)
        
        # Xác định thời gian attack
        if 'duration_seconds' in pattern_config:
            attack_duration = timedelta(seconds=pattern_config['duration_seconds'])
        elif 'duration_minutes' in pattern_config:
            attack_duration = timedelta(minutes=pattern_config['duration_minutes'])
        elif 'duration_hours' in pattern_config:
            attack_duration = timedelta(hours=pattern_config['duration_hours'])
        else:
            attack_duration = end_time - start_time
        
        attack_end = start_time + min(attack_duration, end_time - start_time)
        attack_time = start_time
        
        # Tính total attempts dựa trên pattern mới
        if 'attempts_per_second' in pattern_config:
            # Attack nhanh: phân bố đều
            duration_seconds = (attack_end - attack_time).total_seconds()
            total_attempts = int(duration_seconds * pattern_config['attempts_per_second'])
            
            for i in range(total_attempts):
                ts = attack_time + timedelta(seconds=i/pattern_config['attempts_per_second'])
                if ts > attack_end:
                    continue
                    
                event = self.generate_event(
                    pattern, 
                    ts, 
                    is_attack=is_attack,
                    attack_type=pattern_config.get('attack_type')
                )
                events.append(event)
        
        elif 'attempts_per_minute' in pattern_config:
            # Attack trung bình
            duration_minutes = (attack_end - attack_time).total_seconds() / 60
            total_attempts = int(duration_minutes * pattern_config['attempts_per_minute'])
            
            # Phân bố đều nếu thời gian ngắn (< 10 phút), ngẫu nhiên nếu dài
            if pattern_config.get('duration_minutes', 0) < 10:
                for i in range(total_attempts):
                    ts = attack_time + timedelta(minutes=i/pattern_config['attempts_per_minute'])
                    if ts > attack_end:
                        continue
                        
                    event = self.generate_event(
                        pattern, 
                        ts, 
                        is_attack=is_attack,
                        attack_type=pattern_config.get('attack_type')
                    )
                    events.append(event)
            else:
                for _ in range(total_attempts):
                    ts = random_timestamp(attack_time, attack_end)
                    event = self.generate_event(
                        pattern, 
                        ts, 
                        is_attack=is_attack,
                        attack_type=pattern_config.get('attack_type')
                    )
                    events.append(event)
        
        elif 'attempts_per_hour' in pattern_config:
            # Attack chậm: phân bố ngẫu nhiên
            duration_hours = (attack_end - attack_time).total_seconds() / 3600
            total_attempts = int(duration_hours * pattern_config['attempts_per_hour'])
            
            for _ in range(total_attempts):
                ts = random_timestamp(attack_time, attack_end)
                event = self.generate_event(
                    pattern, 
                    ts, 
                    is_attack=is_attack,
                    attack_type=pattern_config.get('attack_type')
                )
                events.append(event)
        
        else:
            # Fallback: dùng logic cũ
            if 'attempts_per_minute' in pattern_config:
                duration_minutes = (attack_end - attack_time).total_seconds() / 60
                total_attempts = int(duration_minutes * pattern_config['attempts_per_minute'])
            else:
                duration = (attack_end - attack_time).total_seconds() / 3600
                total_attempts = int(duration * pattern_config.get('attempts_per_hour', 1))
            
            for i in range(total_attempts):
                if 'duration_minutes' in pattern_config:
                    ts = attack_time + timedelta(seconds=i * 60 / pattern_config['attempts_per_minute'])
                else:
                    ts = random_timestamp(attack_time, attack_end)
                
                event = self.generate_event(
                    pattern, 
                    ts, 
                    is_attack=is_attack,
                    attack_type=pattern_config.get('attack_type')
                )
                events.append(event)
        
        return events

    def generate_rapid_attack(self, start_time, duration_seconds=30, attempts_per_second=12):
        """Tạo rapid attack chính xác theo seconds"""
        events = []
        attack_ip = random.choice(self.attack_ips)
        target_user = random.choice(self.users)['username']
        
        for i in range(int(duration_seconds * attempts_per_second)):
            # Phân bố đều trong khoảng thời gian
            ts = start_time + timedelta(seconds=i/attempts_per_second)
            
            event = {
                'timestamp': ts.isoformat(),
                'username': target_user,
                'src_ip': attack_ip,
                'success': random.random() < 0.001,  # 0.1% success
                'user_agent': random_user_agent(),
                'request_path': '/login',
                'http_method': 'POST',
                'http_status': 401,
                'failure_reason': 'Invalid credentials',
                'request_duration_ms': random.randint(50, 150),
                'geo': random_geo(),
                'device_fingerprint': generate_fingerprint(attack_ip, random_user_agent(), ts),
                'is_attack': True,
                'attack_type': 'rapid_bruteforce'
            }
            events.append(event)
        
        return events

    def generate_distributed_burst_attack(self, start_time, end_time):
        """Generate distributed attack - FIXED VERSION"""
        events = []
        target_user = random.choice(self.users)['username']
        
        # 10 IPs, mỗi IP 30 attempts trong 30s = 1 attempt/giây
        attack_ips = random.sample(self.attack_ips, min(10, len(self.attack_ips)))
        
        for ip_idx, ip in enumerate(attack_ips):
            # Mỗi IP bắt đầu tại thời điểm hơi khác nhau (0-5 giây)
            ip_start = start_time + timedelta(seconds=random.uniform(0, 5))
            
            # Mỗi IP thực hiện 30 attempts trong 30s
            for attempt in range(30):
                # Phân bố đều: mỗi giây 1 attempt
                ts = ip_start + timedelta(seconds=attempt)
                
                if ts > end_time:
                    continue
                    
                event = {
                    'timestamp': ts.isoformat(),
                    'username': target_user,
                    'src_ip': ip,
                    'success': False,
                    'user_agent': random_user_agent(),
                    'request_path': '/login',
                    'http_method': 'POST',
                    'http_status': 401,
                    'failure_reason': 'Invalid credentials',
                    'request_duration_ms': random.randint(100, 300),
                    'geo': random_geo(),
                    'device_fingerprint': generate_fingerprint(ip, random_user_agent(), ts),
                    'is_attack': True,
                    'attack_type': 'distributed_attack'
                }
                events.append(event)
        
        return events
        
    def generate_targeted_slow_low_attack(self, start_time, end_time):
        """Generate targeted slow-low attack pattern"""
        events = []
        duration_hours = (end_time - start_time).total_seconds() / 3600
        
        # Pick a specific target (admin or high-value user)
        target_users = [u for u in self.users if u['username'] in ['admin', 'HusThien_IA']]
        if not target_users:
            target_users = self.users
        target_user = random.choice(target_users)
        
        # Total attempts: 3 per hour (very slow)
        total_attempts = int(duration_hours * 3)
        
        # Use single IP
        attack_ip = random.choice(self.attack_ips)
        
        for i in range(total_attempts):
            # Random time between 15-90 minutes
            time_offset = random.uniform(i * 900, i * 5400)  # 15-90 minutes
            ts = start_time + timedelta(seconds=time_offset)
            
            if ts > end_time:
                break
                
            event = {
                'timestamp': ts.isoformat(),
                'username': target_user['username'],
                'src_ip': attack_ip,
                'success': False,
                'user_agent': random_user_agent(),
                'request_path': '/login',
                'http_method': 'POST',
                'http_status': 401,
                'failure_reason': 'Invalid credentials',
                'request_duration_ms': random.randint(200, 800),  # Slower to mimic human
                'geo': random_geo(),
                'device_fingerprint': generate_fingerprint(attack_ip, random_user_agent(), ts),
                'is_attack': True,
                'attack_type': 'targeted_slow_low'
            }
            events.append(event)
        
        return events
    
    def generate_scenario(self,
                        scenario_name: str,
                        start_time: datetime,
                        end_time: datetime,
                        attack_ratio: float = 0.1) -> List[Dict]:
        """Generate mixed scenario (normal + attack) - SIMPLIFIED VERSION"""
        all_events = []
        
        # Scenario mapping
        scenarios = {
            'normal_heavy': {
                'normal_rate': 200,  # events per hour
                'attack_pattern': None
            },
            'weekend': {
                'normal_rate': 50,   # lower rate
                'attack_pattern': None
            },
            'rapid_bruteforce': {
                'normal_rate': 100,
                'attack_pattern': 'rapid_bruteforce',
                'attack_duration_ratio': 0.05  # 5% of total time
            },
            'credential_stuffing': {
                'normal_rate': 150,
                'attack_pattern': 'credential_stuffing',
                'attack_duration_ratio': 0.5   # 50% of total time
            },
            'distributed_attack': {
                'normal_rate': 100,
                'attack_pattern': 'distributed_attack',
                'attack_duration_ratio': 0.25  # 25% of total time
            },
            'targeted_slow_low': {
                'normal_rate': 150,
                'attack_pattern': 'targeted_slow_low',
                'attack_duration_ratio': 1.0   # entire period
            },
            'mixed': {
                'normal_rate': 120,
                'attack_patterns': ['rapid_bruteforce', 'distributed_attack', 'credential_stuffing'],
                'attack_count': 3
            }
        }
        
        config = scenarios.get(scenario_name, scenarios['normal_heavy'])
        
        # Generate normal traffic
        normal_events = self.generate_normal_traffic(start_time, end_time, config['normal_rate'])
        all_events.extend(normal_events)
        
        # Generate attack traffic if specified
        if config.get('attack_pattern'):
            attack_duration_ratio = config.get('attack_duration_ratio', 0.1)
            attack_duration = (end_time - start_time) * attack_duration_ratio
            
            # Place attack in middle of period
            attack_start = start_time + (end_time - start_time) * (0.5 - attack_duration_ratio/2)
            attack_end = attack_start + attack_duration
            
            if config['attack_pattern'] == 'distributed_attack':
                attack_events = self.generate_distributed_burst_attack(attack_start, attack_end)
            elif config['attack_pattern'] == 'rapid_bruteforce':
                # GỌI HÀM MỚI cho rapid attack
                attack_events = self.generate_rapid_attack_fixed(attack_start, 30)
            else:
                attack_events = self.generate_attack_traffic(
                    config['attack_pattern'], 
                    attack_start, 
                    attack_end
                )

            all_events.extend(attack_events)
        
        # For mixed scenario: generate multiple attack types
        elif scenario_name == 'mixed':
            for i, pattern in enumerate(config['attack_patterns']):
                attack_duration = (end_time - start_time) / config['attack_count']
                attack_start = start_time + attack_duration * i
                attack_end = attack_start + attack_duration
                
                if pattern == 'distributed_attack':
                    attack_events = self.generate_distributed_burst_attack(attack_start, attack_end)
                else:
                    attack_events = self.generate_attack_traffic(pattern, attack_start, attack_end)
                
                all_events.extend(attack_events)
        
        # Sort by timestamp
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events
    
        # Tạo dataset đặc biệt cho rule testing
    def generate_rule_test_dataset():
        gen = SimpleDataGenerator(seed=42)
        
        # 1. CLEAR CASE: Rapid attack (400 attempts in 2 minutes)
        rapid = gen.generate_scenario('rapid_bruteforce', ...)
        
        # 2. BORDERLINE CASE: 95 attempts in 30s (dưới threshold 100)
        borderline = gen.generate_custom_attack(attempts=95, duration=30)
        
        # 3. DISTRIBUTED: 10 IPs, mỗi IP 15 attempts in 30s (tổng 150)
        distributed = gen.generate_distributed_attack(ips=10, attempts_per_ip=15, duration=30)
        
        # 4. NORMAL: 50 attempts in 30s (all successes)
        normal = gen.generate_normal(attempts=50, duration=30, success_rate=0.9)
        
    # ==================== FIX 3: UNIFIED API ====================
    
    def generate(self, 
                seed: int = 42,
                start_ts: datetime = None,
                duration: float = 24,
                volume_per_minute: float = 5,
                attack_mix: float = 0.1,
                scenario: str = "mixed") -> List[Dict]:
        """
        Unified API according to design specification
        
        Args:
            seed: Random seed for reproducibility
            start_ts: Start timestamp (default: 24 hours ago)
            duration: Duration in hours
            volume_per_minute: Events per minute (overall volume)
            attack_mix: Ratio of attack events (0.0 to 1.0)
            scenario: Scenario name or "mixed" for mixed attack types
        
        Returns:
            List of event dictionaries
        """
        # Set seed
        random.seed(seed)
        
        # Default start time
        if start_ts is None:
            start_ts = datetime.now() - timedelta(hours=duration)
        
        end_ts = start_ts + timedelta(hours=duration)
        
        # If specific scenario requested
        scenario_names = ['normal_heavy', 'weekend', 'rapid_bruteforce',
                        'credential_stuffing', 'distributed_attack', 
                        'targeted_slow_low', 'mixed', 'rule_test']
        
        if scenario in scenario_names:
            if scenario == 'rule_test':
                return self.generate_rule_test_cases()
            else:
                return self.generate_scenario(scenario, start_ts, end_ts, attack_mix)
        
        # Default: mixed scenario with specified volume and attack mix
        events = []
        total_minutes = duration * 60
        total_events = int(total_minutes * volume_per_minute)
        attack_events_count = int(total_events * attack_mix)
        normal_events_count = total_events - attack_events_count
        
        # Generate normal events
        normal_start = start_ts
        normal_end = end_ts
        normal_per_minute = normal_events_count / total_minutes
        normal_events = self.generate_normal_traffic(normal_start, normal_end, normal_per_minute * 60)
        events.extend(normal_events)
        
        # Generate attack events
        if attack_events_count > 0:
            # Chia đều các loại attack
            attack_types = ['rapid_bruteforce', 'distributed_attack', 'credential_stuffing', 'targeted_slow_low']
            attacks_per_type = max(1, attack_events_count // len(attack_types))
            
            for attack_type in attack_types:
                # Random attack window trong khoảng thời gian
                attack_duration_hours = min(1.0, duration * 0.2)  # Tối đa 1 giờ hoặc 20% duration
                attack_start = random_timestamp(start_ts, end_ts - timedelta(hours=attack_duration_hours))
                attack_end = attack_start + timedelta(hours=attack_duration_hours)
                
                if attack_type == 'distributed_attack':
                    attack_events = self.generate_distributed_burst_attack(attack_start, attack_end)
                else:
                    attack_events = self.generate_attack_traffic(attack_type, attack_start, attack_end)
                
                # Giới hạn số lượng attack events
                if len(attack_events) > attacks_per_type:
                    attack_events = random.sample(attack_events, attacks_per_type)
                
                events.extend(attack_events)
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        
        # Đảm bảo tổng số events không vượt quá yêu cầu
        if len(events) > total_events:
            events = random.sample(events, total_events)
            events.sort(key=lambda x: x['timestamp'])
        
        return events
    
    # ==================== FIX 4: SCENARIO LOADER ====================
    
    def generate_from_config(self, config_path: str) -> List[Dict]:
        """
        Generate events from JSON config file
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            scenario_name = config.get('name', 'normal_heavy')
            start_ts = datetime.fromisoformat(config.get('start_time', 
                                                       (datetime.now() - timedelta(days=1)).isoformat()))
            duration_hours = config.get('duration_hours', 24)
            attack_ratio = config.get('attack_ratio', 0.1)
            
            end_ts = start_ts + timedelta(hours=duration_hours)
            
            return self.generate_scenario(scenario_name, start_ts, end_ts, attack_ratio)
            
        except Exception as e:
            print(f" Error loading config {config_path}: {e}")
            return []
    
    def save_to_ndjson(self, events: List[Dict], filename: str):
        """Save events to NDJSON file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            for event in events:
                f.write(json.dumps(event) + '\n')
        
        print(f" Saved {len(events)} events to {filename}")
        
    def save_to_database(self, events: List[Dict]):
        """Save events to database (optional)"""
        try:
            import pymysql
            from .config import DB_CONFIG
            
            conn = pymysql.connect(**DB_CONFIG)
            cursor = conn.cursor()
            
            insert_sql = """
            INSERT INTO auth_logs 
            (username, src_ip, success, user_agent, request_path, 
             http_method, http_status, failure_reason, request_duration_ms,
             geo, device_fingerprint, is_attack, attack_type, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            for event in events:
                cursor.execute(insert_sql, (
                    event['username'],
                    event['src_ip'],
                    event['success'],
                    event['user_agent'],
                    event['request_path'],
                    event['http_method'],
                    event['http_status'],
                    event['failure_reason'],
                    event['request_duration_ms'],
                    event['geo'],
                    event['device_fingerprint'],
                    event['is_attack'],
                    event['attack_type'],
                    event['timestamp']
                ))
            
            conn.commit()
            print(f" Inserted {len(events)} events into database")
            
        except ImportError:
            print("  pymysql not installed, skipping database insert")
        except Exception as e:
            print(f" Database error: {e}")