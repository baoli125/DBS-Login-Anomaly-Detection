"""
Single Sự kiện Demo Mô-đun

Xử lý demonstration of single sự kiện classification.
"""

import json
from typing import Dict, Any

from classification.core.classifier import EventClassifier
from classification.core.formatter import ResultFormatter


class SingleEventDemo:
    """Demo phân loại một sự kiện."""

    def __init__(self, models_dir: str = "models"):
        self.classifier = EventClassifier(models_dir)
        self.formatter = ResultFormatter()

    def run_demo(self, event: Dict[str, Any]) -> str:
        """Run single sự kiện classification demo."""
        result = self.classifier.classify_single_event(event)
        return self.formatter.format_single_event_result(result)

    def parse_event_from_json(self, json_str: str) -> Dict[str, Any]:
        """Phân tích sự kiện từ chuỗi JSON."""
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON event: {e}")

    def create_sample_event(self, **kwargs) -> Dict[str, Any]:
        """Tạo một sự kiện mẫu với giá trị mặc định."""
        default_event = {
            "timestamp": "2026-03-09T10:00:00Z",
            "username": "user1",
            "src_ip": "192.168.1.1",
            "success": False
        }
        default_event.update(kwargs)
        return default_event