"""
Agent Core Module

Contains the main ResponseAgent class and core functionality.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set

from agent.core.state import ResponseState
from agent.core.strategies import ResponseStrategies
from agent.processing.event_loader import EventLoader
from agent.processing.classifier import EventClassifier


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

        # Initialize components
        self.state = ResponseState()
        self.strategies = ResponseStrategies(self.state)
        self.event_loader = EventLoader()
        self.classifier = EventClassifier(models_dir)

        print(" AI Response Agent initialized")
        print(f"   Models: {models_dir}")
        print(f"   Check interval: {check_interval}s")
        print()

    def run_once(self, dataset_path: str) -> None:
        """Run one cycle of monitoring and response."""
        print(f" Agent cycle started at {datetime.now()}")
        print("-" * 50)

        # Load new events
        new_events = self.event_loader.load_new_events(
            dataset_path,
            self.state.last_processed_timestamp,
            self.state.processed_event_hashes
        )
        print(f" New events: {len(new_events)}")

        if not new_events:
            print("   No new events to process")
        else:
            # Classify events
            classifications = self.classifier.classify_events(new_events)
            attack_events = [c for c in classifications if c['is_attack']]

            print(f" Attack events detected: {len(attack_events)}")

            # Apply responses
            for classification in attack_events:
                self.strategies.apply_response(classification)

        # Cleanup expired responses
        self.state.cleanup_expired_responses()

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

    def _print_status(self) -> None:
        """Print current agent status."""
        print(" Agent Status:")
        print(f"   Blocked IPs: {len(self.state.blocked_ips)}")
        print(f"   Users requiring 2FA: {len(self.state.users_requiring_2fa)}")
        print(f"   Active alerts: {len(self.state.active_alerts)}")
        print(f"   Monitoring targets: {len(self.state.monitoring_targets)}")
        print(f"   Last processed: {self.state.last_processed_timestamp}")
        print()