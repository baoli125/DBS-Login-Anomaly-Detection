"""
Mô-đun Xử lý Sự kiện

Xử lý việc tải và tiền xử lý các sự kiện cho agent.
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Set

from scripts.run_rulebase import load_ndjson


class EventLoader:
    """Xử lý việc tải và lọc các sự kiện."""

    def load_new_events(self, dataset_path: str, last_processed_timestamp: datetime,
                       processed_hashes: Set[str]) -> List[Dict[str, Any]]:
        """Tải các sự kiện mới hơn timestamp đã xử lý cuối cùng."""
        if not os.path.exists(dataset_path):
            return []

        events = load_ndjson(dataset_path)

        # Lọc các sự kiện mới
        new_events = []
        latest_timestamp = last_processed_timestamp

        for event in events:
            # Phân tích timestamp
            ts_str = event.get('timestamp')
            if ts_str:
                try:
                    if ts_str.endswith('Z'):
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    else:
                        ts = datetime.fromisoformat(ts_str)
                except:
                    continue

                # Tạo sự kiện hash để tránh xử lý lại
                event_hash = f"{event.get('timestamp')}_{event.get('username')}_{event.get('src_ip')}"

                # Bỏ qua nếu đã xử lý hoặc quá cũ
                if ts > last_processed_timestamp and event_hash not in processed_hashes:
                    new_events.append(event)
                    processed_hashes.add(event_hash)

                    # Cập nhật latest timestamp
                    if ts > latest_timestamp:
                        latest_timestamp = ts

        # Update the caller's last processed timestamp
        # Note: This is a bit of a hack - ideally we'd trả về this separately
        if hasattr(self, '_last_timestamp_ref'):
            self._last_timestamp_ref[0] = latest_timestamp

        return new_events

    def load_events_in_range(self, dataset_path: str, start_time: datetime,
                           end_time: datetime) -> List[Dict[str, Any]]:
        """Tải các sự kiện trong khoảng thời gian nhất định."""
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