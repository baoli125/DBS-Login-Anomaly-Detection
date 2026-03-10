#!/usr/bin/env python3
"""
AI Response Agent for Brute-Force Detection & Classification.

This agent:
1. Monitors login events periodically (every 5 minutes)
2. Uses ML models to detect and classify attacks
3. Applies appropriate response strategies based on attack type

Response Strategies:
- rapid_bruteforce: Temporary IP block (5 minutes)
- credential_stuffing: Require 2FA for affected users
- distributed_attack: Admin alert + monitoring
- targeted_slow_low: Increased monitoring only
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.core.inference import predict_attack_and_type
from ml.features.feature_builder import build_features_from_events
from scripts.run_rulebase import load_ndjson


class ResponseAgent:
    """AI Agent for automated response to detected attacks."""

    def __init__(self, models_dir: str = "models", check_interval: int = 300):
        """
        Initialize the response agent.

        Args:
            models_dir: Directory containing ML models
            check_interval: Check interval in seconds (default: 5 minutes)
        """
        self.models_dir = models_dir
        self.check_interval = check_interval

        # Response state
        self.blocked_ips: Dict[str, datetime] = {}  # IP -> unblock_time
        self.users_requiring_2fa: Set[str] = set()
        self.active_alerts: Dict[str, Dict[str, Any]] = {}  # alert_id -> alert_info
        self.monitoring_targets: Dict[str, datetime] = {}  # target -> end_time

        # Event processing state
        self.last_processed_timestamp: datetime = datetime.min
        self.processed_event_hashes: Set[str] = set()  # Avoid reprocessing

        print(" AI Response Agent initialized")
        print(f"   Models: {models_dir}")
        print(f"   Check interval: {check_interval}s")
        print()

    def _load_new_events(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load events newer than last processed timestamp."""
        if not os.path.exists(dataset_path):
            return []

        events = load_ndjson(dataset_path)

        # Filter new events
        new_events = []
        for event in events:
            # Parse timestamp
            ts_str = event.get('timestamp')
            if ts_str:
                try:
                    if ts_str.endswith('Z'):
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    else:
                        ts = datetime.fromisoformat(ts_str)
                except:
                    continue

                # Skip if already processed or too old
                event_hash = f"{event.get('timestamp')}_{event.get('username')}_{event.get('src_ip')}"
                if ts > self.last_processed_timestamp and event_hash not in self.processed_event_hashes:
                    new_events.append(event)
                    self.processed_event_hashes.add(event_hash)

                    # Update last processed timestamp
                    if ts > self.last_processed_timestamp:
                        self.last_processed_timestamp = ts

        return new_events

    def _classify_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify events using ML models."""
        if not events:
            return []

        # Build features
        df_features = build_features_from_events(events)
        if df_features.empty:
            return []

        classifications = []
        for idx, row in df_features.iterrows():
            feature_dict = row.to_dict()
            # Remove non-feature columns
            for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
                feature_dict.pop(col, None)

            # Predict
            prediction = predict_attack_and_type(feature_dict, models_dir=self.models_dir)

            # Add event info
            event = events[idx]
            classification = {
                'event': event,
                'is_attack': prediction['label'],
                'attack_score': prediction['score'],
                'attack_type': prediction['attack_type'],
                'attack_type_confidence': max(prediction['attack_type_probabilities'].values()),
                'features': feature_dict,
            }
            classifications.append(classification)

        return classifications

    def _apply_response_strategy(self, classification: Dict[str, Any]) -> None:
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
        unblock_time = datetime.now() + block_duration

        self.blocked_ips[src_ip] = unblock_time

        print("  RESPONSE: Rapid Brute-Force")
        print(f"   Action: Block IP {src_ip} for 5 minutes")
        print(f"   Unblock at: {unblock_time}")
        print()

        # Log alert
        alert_id = f"rapid_{src_ip}_{int(time.time())}"
        self.active_alerts[alert_id] = {
            'type': 'ip_block',
            'target': src_ip,
            'reason': 'rapid_bruteforce',
            'start_time': datetime.now(),
            'end_time': unblock_time,
        }

    def _respond_credential_stuffing(self, username: str, src_ip: str) -> None:
        """Response: Require 2FA for user."""
        self.users_requiring_2fa.add(username)

        print("  RESPONSE: Credential Stuffing")
        print(f"   Action: Require 2FA for user {username}")
        print(f"   Triggered by IP: {src_ip}")
        print()

        # Log alert
        alert_id = f"2fa_{username}_{int(time.time())}"
        self.active_alerts[alert_id] = {
            'type': 'require_2fa',
            'target': username,
            'reason': 'credential_stuffing',
            'start_time': datetime.now(),
        }

    def _respond_distributed_attack(self, username: str, src_ip: str) -> None:
        """Response: Admin alert and monitoring."""
        monitor_duration = timedelta(hours=1)
        end_time = datetime.now() + monitor_duration

        self.monitoring_targets[f"user_{username}"] = end_time

        print("  RESPONSE: Distributed Attack")
        print(f"   Action: Admin alert + monitor user {username} for 1 hour")
        print(f"   Triggered by IP: {src_ip}")
        print("    ALERT: Distributed attack detected - manual review recommended")
        print()

        # Log alert
        alert_id = f"distributed_{username}_{int(time.time())}"
        self.active_alerts[alert_id] = {
            'type': 'admin_alert',
            'target': username,
            'reason': 'distributed_attack',
            'start_time': datetime.now(),
            'severity': 'high',
        }

    def _respond_targeted_slow(self, username: str, src_ip: str) -> None:
        """Response: Increased monitoring only."""
        monitor_duration = timedelta(hours=2)
        end_time = datetime.now() + monitor_duration

        self.monitoring_targets[f"user_{username}"] = end_time

        print("  RESPONSE: Targeted Slow Attack")
        print(f"   Action: Monitor user {username} for 2 hours (no blocking)")
        print(f"   Triggered by IP: {src_ip}")
        print()

        # Log alert
        alert_id = f"slow_{username}_{int(time.time())}"
        self.active_alerts[alert_id] = {
            'type': 'monitoring',
            'target': username,
            'reason': 'targeted_slow_low',
            'start_time': datetime.now(),
            'end_time': end_time,
        }

    def _cleanup_expired_responses(self) -> None:
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

    def _print_status(self) -> None:
        """Print current agent status."""
        print(" Agent Status:")
        print(f"   Blocked IPs: {len(self.blocked_ips)}")
        print(f"   Users requiring 2FA: {len(self.users_requiring_2fa)}")
        print(f"   Active alerts: {len(self.active_alerts)}")
        print(f"   Monitoring targets: {len(self.monitoring_targets)}")
        print(f"   Last processed: {self.last_processed_timestamp}")
        print()

    def run_once(self, dataset_path: str) -> None:
        """Run one cycle of monitoring and response."""
        print(f" Agent cycle started at {datetime.now()}")
        print("-" * 50)

        # Load new events
        new_events = self._load_new_events(dataset_path)
        print(f" New events: {len(new_events)}")

        if not new_events:
            print("   No new events to process")
        else:
            # Classify events
            classifications = self._classify_events(new_events)
            attack_events = [c for c in classifications if c['is_attack']]

            print(f" Attack events detected: {len(attack_events)}")

            # Apply responses
            for classification in attack_events:
                self._apply_response_strategy(classification)

        # Cleanup expired responses
        self._cleanup_expired_responses()

        # Print status
        self._print_status()

        print(f" Agent cycle completed at {datetime.now()}")
        print()

    def run_continuous(self, dataset_path: str) -> None:
        """Run agent continuously."""
        print(" Starting continuous monitoring...")
        print(f"   Check interval: {self.check_interval} seconds")
        print(f"   Dataset: {dataset_path}")
        print()

        try:
            while True:
                self.run_once(dataset_path)
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            print("\n Agent stopped by user")
        except Exception as e:
            print(f"\n Agent error: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(
        description="AI Response Agent for Brute-Force Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dataset",
        default="data/test_events.ndjson",
        help="Path to NDJSON dataset to monitor (default: %(default)s)",
    )
    parser.add_argument(
        "--models-dir",
        default="models",
        help="Directory containing ML models (default: %(default)s)",
    )
    parser.add_argument(
        "--check-interval",
        type=int,
        default=300,
        help="Check interval in seconds (default: %(default)s = 5 minutes)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one cycle and exit (default: continuous)",
    )

    args = parser.parse_args()

    agent = ResponseAgent(
        models_dir=args.models_dir,
        check_interval=args.check_interval,
    )

    if args.once:
        agent.run_once(args.dataset)
    else:
        agent.run_continuous(args.dataset)


if __name__ == "__main__":
    main()