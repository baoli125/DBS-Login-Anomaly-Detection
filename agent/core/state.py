
"""
Quản lý Trạng thái Phản hồi

Quản lý trạng thái của các phản hồi: IP bị khóa, yêu cầu 2FA, cảnh báo, mục tiêu giám sát.
Code được tổ chức và comment rõ ràng để dễ hiểu và trình diễn demo.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Set


class ResponseState:
    """
    Quản lý tất cả trạng thái phản hồi cho agent.
    Theo dõi IP bị khóa, 2FA, cảnh báo, giám sát, và trạng thái xử lý sự kiện.
    Được thiết kế để rõ ràng và dễ giải thích trong demo.
    """

    def __init__(self):
        # Trạng thái phản hồi
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> thời gian mở khóa
        self.users_requiring_2fa: Set[str] = set()
        self.active_alerts: Dict[str, Dict[str, Any]] = {}  # alert_id -> thông tin cảnh báo
        self.monitoring_targets: Dict[str, datetime] = {}  # mục tiêu -> thời gian kết thúc

        # Trạng thái xử lý sự kiện
        self.last_processed_timestamp: datetime = datetime.min
        self.processed_event_hashes: Set[str] = set()  # Tránh xử lý lại

    def add_blocked_ip(self, ip: str, duration: timedelta) -> None:
        """Thêm IP vào danh sách bị khóa."""
        unblock_time = datetime.now() + duration
        self.blocked_ips[ip] = unblock_time

    def add_2fa_requirement(self, username: str) -> None:
        """Thêm user vào danh sách yêu cầu 2FA."""
        self.users_requiring_2fa.add(username)

    def add_alert(self, alert_id: str, alert_info: Dict[str, Any]) -> None:
        """Thêm một cảnh báo đang hoạt động."""
        self.active_alerts[alert_id] = alert_info

    def add_monitoring_target(self, target: str, duration: timedelta) -> None:
        """Thêm một mục tiêu giám sát."""
        end_time = datetime.now() + duration
        self.monitoring_targets[target] = end_time

    def update_last_processed_timestamp(self, timestamp: datetime) -> None:
        """Cập nhật timestamp đã xử lý cuối cùng."""
        self.last_processed_timestamp = timestamp

    def add_processed_event_hash(self, event_hash: str) -> None:
        """Thêm hash sự kiện vào tập đã xử lý."""
        self.processed_event_hashes.add(event_hash)

    def cleanup_expired_responses(self) -> None:
        """Dọn dẹp các phản hồi đã hết hạn (khóa, giám sát, cảnh báo)."""
        now = datetime.now()

        # Dọn dẹp blocked IPs
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if now >= unblock_time]
        for ip in expired_ips:
            del self.blocked_ips[ip]
            print(f" IP {ip} unblocked (block expired)")

        # Dọn dẹp giám sát
        expired_targets = [target for target, end_time in self.monitoring_targets.items() if now >= end_time]
        for target in expired_targets:
            del self.monitoring_targets[target]

        # Dọn dẹp old alerts (keep last 24 hours)
        cutoff = now - timedelta(hours=24)
        expired_alerts = [aid for aid, alert in self.active_alerts.items()
                         if alert['start_time'] < cutoff]
        for aid in expired_alerts:
            del self.active_alerts[aid]

    def get_status_summary(self) -> Dict[str, Any]:
        """Lấy tóm tắt trạng thái hiện tại."""
        return {
            'blocked_ips_count': len(self.blocked_ips),
            'users_requiring_2fa_count': len(self.users_requiring_2fa),
            'active_alerts_count': len(self.active_alerts),
            'monitoring_targets_count': len(self.monitoring_targets),
            'last_processed_timestamp': self.last_processed_timestamp
        }