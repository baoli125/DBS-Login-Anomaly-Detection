"""
Response Strategies

Implements different response strategies for each attack type.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any

from agent.core.state import ResponseState


class ResponseStrategies:
    """Handles different response strategies for attack types."""

    def __init__(self, state: ResponseState):
        self.state = state

    def apply_response(self, classification: Dict[str, Any]) -> None:
        """Apply appropriate response based on attack classification."""
        event = classification['event']
        attack_type = classification['attack_type']
        username = event.get('username', 'unknown')
        src_ip = event.get('src_ip', 'unknown')

        print(f" ATTACK DETECTED: {attack_type}")
        print(f"   User: {username}, IP: {src_ip}")
        print(f"   Confidence: {classification['attack_type_confidence']:.3f}")
        print()

        if attack_type == 'rapid_bruteforce':
            self._respond_rapid_bruteforce(src_ip, username)
        elif attack_type == 'credential_stuffing':
            self._respond_credential_stuffing(username, src_ip)
        elif attack_type == 'distributed_attack':
            self._respond_distributed_attack(username, src_ip)
        elif attack_type == 'targeted_slow_low':
            self._respond_targeted_slow(username, src_ip)
        else:
            print(f"  Unknown attack type: {attack_type} - no action taken")

    def _respond_rapid_bruteforce(self, src_ip: str, username: str) -> None:
        """Response: Temporary IP block."""
        block_duration = timedelta(minutes=5)
        self.state.add_blocked_ip(src_ip, block_duration)
        unblock_time = datetime.now() + block_duration

        print("  RESPONSE: Rapid Brute-Force")
        print(f"   Action: Block IP {src_ip} for 5 minutes")
        print(f"   Unblock at: {unblock_time}")
        print()

        # Log alert
        alert_id = f"rapid_{src_ip}_{int(time.time())}"
        alert_info = {
            'type': 'ip_block',
            'target': src_ip,
            'reason': 'rapid_bruteforce',
            'start_time': datetime.now(),
            'end_time': unblock_time,
        }
        self.state.add_alert(alert_id, alert_info)

    def _respond_credential_stuffing(self, username: str, src_ip: str) -> None:
        """Response: Require 2FA for user."""
        self.state.add_2fa_requirement(username)

        print("  RESPONSE: Credential Stuffing")
        print(f"   Action: Require 2FA for user {username}")
        print(f"   Triggered by IP: {src_ip}")
        print()

        # Log alert
        alert_id = f"2fa_{username}_{int(time.time())}"
        alert_info = {
            'type': 'require_2fa',
            'target': username,
            'reason': 'credential_stuffing',
            'start_time': datetime.now(),
        }
        self.state.add_alert(alert_id, alert_info)

    def _respond_distributed_attack(self, username: str, src_ip: str) -> None:
        """Response: Admin alert and monitoring."""
        monitor_duration = timedelta(hours=1)
        self.state.add_monitoring_target(f"user_{username}", monitor_duration)

        print("  RESPONSE: Distributed Attack")
        print(f"   Action: Admin alert + monitor user {username} for 1 hour")
        print(f"   Triggered by IP: {src_ip}")
        print("    ALERT: Distributed attack detected - manual review recommended")
        print()

        # Log alert
        alert_id = f"distributed_{username}_{int(time.time())}"
        alert_info = {
            'type': 'admin_alert',
            'target': username,
            'reason': 'distributed_attack',
            'start_time': datetime.now(),
            'severity': 'high',
        }
        self.state.add_alert(alert_id, alert_info)

    def _respond_targeted_slow(self, username: str, src_ip: str) -> None:
        """Response: Increased monitoring only."""
        monitor_duration = timedelta(hours=2)
        self.state.add_monitoring_target(f"user_{username}", monitor_duration)

        print("  RESPONSE: Targeted Slow Attack")
        print(f"   Action: Monitor user {username} for 2 hours (no blocking)")
        print(f"   Triggered by IP: {src_ip}")
        print()

        # Log alert
        alert_id = f"slow_{username}_{int(time.time())}"
        alert_info = {
            'type': 'monitoring',
            'target': username,
            'reason': 'targeted_slow_low',
            'start_time': datetime.now(),
            'end_time': datetime.now() + monitor_duration,
        }
        self.state.add_alert(alert_id, alert_info)