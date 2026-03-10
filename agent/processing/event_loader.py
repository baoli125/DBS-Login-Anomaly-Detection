"""
Event Processing Module

Handles loading and preprocessing of events for the agent.
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Set

from scripts.run_rulebase import load_ndjson


class EventLoader:
    """Handles loading and filtering of events."""

    def load_new_events(self, dataset_path: str, last_processed_timestamp: datetime,
                       processed_hashes: Set[str]) -> List[Dict[str, Any]]:
        """Load events newer than last processed timestamp."""
        if not os.path.exists(dataset_path):
            return []

        events = load_ndjson(dataset_path)

        # Filter new events
        new_events = []
        latest_timestamp = last_processed_timestamp

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

                # Create event hash to avoid reprocessing
                event_hash = f"{event.get('timestamp')}_{event.get('username')}_{event.get('src_ip')}"

                # Skip if already processed or too old
                if ts > last_processed_timestamp and event_hash not in processed_hashes:
                    new_events.append(event)
                    processed_hashes.add(event_hash)

                    # Update latest timestamp
                    if ts > latest_timestamp:
                        latest_timestamp = ts

        # Update the caller's last processed timestamp
        # Note: This is a bit of a hack - ideally we'd return this separately
        if hasattr(self, '_last_timestamp_ref'):
            self._last_timestamp_ref[0] = latest_timestamp

        return new_events

    def load_events_in_range(self, dataset_path: str, start_time: datetime,
                           end_time: datetime) -> List[Dict[str, Any]]:
        """Load events within a specific time range."""
        if not os.path.exists(dataset_path):
            return []

        events = load_ndjson(dataset_path)
        filtered_events = []

        for event in events:
            ts_str = event.get('timestamp')
            if ts_str:
                try:
                    if ts_str.endswith('Z'):
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    else:
                        ts = datetime.fromisoformat(ts_str)

                    if start_time <= ts <= end_time:
                        filtered_events.append(event)
                except:
                    continue

        return filtered_events