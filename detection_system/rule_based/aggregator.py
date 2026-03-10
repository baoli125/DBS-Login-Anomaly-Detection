"""
Simple Aggregator - FIXED VERSION
Tính toán chính xác sliding windows cho 3 rule cốt lõi
"""

import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Any
import json

class TimeWindowCounter:
    """Counter chính xác cho từng time window"""
    
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.events = deque()  # (timestamp, data)
        self.lock = threading.RLock()
    
    def add_event(self, timestamp: datetime, data: Dict):
        """Thêm event và tự động cleanup"""
        with self.lock:
            self.events.append((timestamp, data))
            # Cleanup old events
            cutoff = timestamp - timedelta(seconds=self.window_seconds)
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()
    
    def get_metrics_at(self, current_time: datetime) -> Dict[str, Any]:
        """Tính metrics tại thời điểm hiện tại (KHÔNG bao gồm event hiện tại)"""
        with self.lock:
            cutoff = current_time - timedelta(seconds=self.window_seconds)
            
            # Đếm events trong window
            total = 0
            failed = 0
            success = 0
            unique_users = set()
            unique_ips = set()
            
            # CHỈ đếm events TRƯỚC current_time
            for ts, data in self.events:
                if cutoff <= ts < current_time:  # KHÔNG bao gồm current_time
                    total += 1
                    if data.get('success', False):
                        success += 1
                    else:
                        failed += 1
                    
                    if 'username' in data:
                        unique_users.add(data['username'])
                    if 'src_ip' in data:
                        unique_ips.add(data['src_ip'])
            
            # Tính metrics
            metrics = {
                'total': total,
                'failed': failed,
                'success': success,
                'unique_users': len(unique_users),
                'unique_ips': len(unique_ips)
            }
            
            if total > 0:
                metrics['success_rate'] = success / total
                metrics['attempts_per_sec'] = total / self.window_seconds
            else:
                metrics['success_rate'] = 0.0
                metrics['attempts_per_sec'] = 0.0
            
            return metrics

class EntityAggregator:
    """Quản lý metrics cho một entity (IP hoặc User)"""
    
    def __init__(self, entity_key: str):
        self.entity_key = entity_key
        
        # 3 windows cho 3 rule
        self.windows = {
            '30s': TimeWindowCounter(30),    # Rapid brute-force
            '5m': TimeWindowCounter(300),     # Credential stuffing & Distributed attack
            '1h': TimeWindowCounter(3600)     # Long-term baseline
        }
        
        # Lưu events gần đây cho evidence
        self.recent_events = deque(maxlen=50)
        self.lock = threading.RLock()
    
    def add_event(self, event: Dict):
        """Thêm event vào tất cả windows"""
        timestamp = self._parse_timestamp(event.get('timestamp'))
        
        with self.lock:
            # Thêm vào các windows
            for counter in self.windows.values():
                counter.add_event(timestamp, event)
            
            # Lưu event gần đây
            self.recent_events.append({
                'timestamp': timestamp,
                'event': event
            })
    
    def get_metrics_at_time(self, event_time: datetime) -> Dict[str, Any]:
        """Lấy tất cả metrics tại thời điểm event_time"""
        with self.lock:
            metrics = {'entity_key': self.entity_key}
            
            # Lấy metrics từ từng window
            for name, counter in self.windows.items():
                window_metrics = counter.get_metrics_at(event_time)
                
                # Đặt tên metrics theo pattern: metric_window
                for metric_name, value in window_metrics.items():
                    if metric_name in ['total', 'failed', 'success']:
                        metrics[f'{metric_name}_{name}'] = value
                    elif name == '30s' and metric_name == 'attempts_per_sec':
                        metrics['attempts_per_sec_30s'] = value
                    elif name == '5m':
                        if metric_name == 'success_rate':
                            metrics['success_rate'] = value
                        if metric_name == 'unique_users':
                            metrics['unique_users'] = value
                        if metric_name == 'unique_ips':
                            metrics['unique_ips'] = value
            
            # Aliases cho rule (giữ backward compatibility)
            metrics['failed_attempts_30s'] = metrics.get('failed_30s', 0)
            metrics['failed_attempts_5m'] = metrics.get('failed_5m', 0)
            metrics['unique_users_5m'] = metrics.get('unique_users', 0)
            metrics['unique_ips_5m'] = metrics.get('unique_ips', 0)
            
            return metrics
    
    def get_recent_events(self, limit: int = 5) -> List[Dict]:
        """Lấy events gần đây cho evidence"""
        with self.lock:
            return [e['event'] for e in list(self.recent_events)[-limit:]]
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp từ nhiều định dạng"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            try:
                if timestamp.endswith('Z'):
                    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return datetime.fromisoformat(timestamp)
            except:
                return datetime.now()
        else:
            return datetime.now()

class SimpleAggregator:
    """Main aggregator - quản lý metrics cho tất cả entities"""
    
    def __init__(self):
        # Storage: scope -> entity_key -> EntityAggregator
        self.storage = {
            'ip': defaultdict(lambda: None),
            'user': defaultdict(lambda: None),
            'pair': defaultdict(lambda: None)
        }
        self.lock = threading.RLock()
    
    def process_event(self, event: Dict):
        """Xử lý một event - cập nhật metrics cho tất cả scopes"""
        with self.lock:
            timestamp = self._parse_timestamp(event.get('timestamp'))
            event['_processed_timestamp'] = timestamp
            
            # IP scope
            src_ip = event.get('src_ip')
            if src_ip:
                if self.storage['ip'][src_ip] is None:
                    self.storage['ip'][src_ip] = EntityAggregator(src_ip)
                self.storage['ip'][src_ip].add_event(event)
            
            # User scope
            username = event.get('username')
            if username:
                if self.storage['user'][username] is None:
                    self.storage['user'][username] = EntityAggregator(username)
                self.storage['user'][username].add_event(event)
            
            # IP-User pair scope (optional)
            if src_ip and username:
                pair_key = f"{src_ip}:{username}"
                if self.storage['pair'][pair_key] is None:
                    self.storage['pair'][pair_key] = EntityAggregator(pair_key)
                self.storage['pair'][pair_key].add_event(event)
    
    def get_metrics_at_event_time(self, scope: str, entity_key: str, event: Dict) -> Dict:
        """
        Lấy metrics snapshot tại thời điểm của event
        QUAN TRỌNG: Metrics KHÔNG bao gồm event hiện tại
        """
        with self.lock:
            aggregator = self.storage[scope].get(entity_key)
            if not aggregator:
                return {}
            
            event_time = self._parse_timestamp(event.get('timestamp'))
            return aggregator.get_metrics_at_time(event_time)
    
    def get_evidence_samples(self, scope: str, entity_key: str, limit: int = 5) -> List[Dict]:
        """Lấy mẫu events gần đây cho evidence"""
        with self.lock:
            aggregator = self.storage[scope].get(entity_key)
            if not aggregator:
                return []
            return aggregator.get_recent_events(limit)
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp nhất quán"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            try:
                if timestamp.endswith('Z'):
                    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return datetime.fromisoformat(timestamp)
            except:
                return datetime.now()
        else:
            return datetime.now()
    
    def clear_old_data(self, older_than_hours: int = 24):
        """Dọn dẹp data cũ (stub - production cần implement thực)"""
        pass