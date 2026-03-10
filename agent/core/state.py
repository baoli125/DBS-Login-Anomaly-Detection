"""
Response State Management

Manages the state of responses: blocked IPs, 2FA requirements, alerts, monitoring targets.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Set


class ResponseState:
    """Manages all response state for the agent."""

    def __init__(self):
        # Response state
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> unblock_time
        self.users_requiring_2fa: Set[str] = set()
        self.active_alerts: Dict[str, Dict[str, Any]] = {}  # alert_id -> alert_info
        self.monitoring_targets: Dict[str, datetime] = {}  # target -> end_time

        # Event processing state
        self.last_processed_timestamp: datetime = datetime.min
        self.processed_event_hashes: Set[str] = set()  # Avoid reprocessing

    def add_blocked_ip(self, ip: str, duration: timedelta) -> None:
        """Add an IP to blocked list."""
        unblock_time = datetime.now() + duration
        self.blocked_ips[ip] = unblock_time

    def add_2fa_requirement(self, username: str) -> None:
        """Add user to 2FA requirement list."""
        self.users_requiring_2fa.add(username)

    def add_alert(self, alert_id: str, alert_info: Dict[str, Any]) -> None:
        """Add an active alert."""
        self.active_alerts[alert_id] = alert_info

    def add_monitoring_target(self, target: str, duration: timedelta) -> None:
        """Add a monitoring target."""
        end_time = datetime.now() + duration
        self.monitoring_targets[target] = end_time

    def update_last_processed_timestamp(self, timestamp: datetime) -> None:
        """Update the last processed timestamp."""
        self.last_processed_timestamp = timestamp

    def add_processed_event_hash(self, event_hash: str) -> None:
        """Add an event hash to processed set."""
        self.processed_event_hashes.add(event_hash)

    def cleanup_expired_responses(self) -> None:
        """Clean up expired blocks, monitoring, etc."""
        now = datetime.now()

        # Clean up blocked IPs
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if now >= unblock_time]
        for ip in expired_ips:
            del self.blocked_ips[ip]
            print(f" IP {ip} unblocked (block expired)")

        # Clean up monitoring
        expired_targets = [target for target, end_time in self.monitoring_targets.items() if now >= end_time]
        for target in expired_targets:
            del self.monitoring_targets[target]

        # Clean up old alerts (keep last 24 hours)
        cutoff = now - timedelta(hours=24)
        expired_alerts = [aid for aid, alert in self.active_alerts.items()
                         if alert['start_time'] < cutoff]
        for aid in expired_alerts:
            del self.active_alerts[aid]

    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of current state."""
        return {
            'blocked_ips_count': len(self.blocked_ips),
            'users_requiring_2fa_count': len(self.users_requiring_2fa),
            'active_alerts_count': len(self.active_alerts),
            'monitoring_targets_count': len(self.monitoring_targets),
            'last_processed_timestamp': self.last_processed_timestamp
        }