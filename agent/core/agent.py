
"""
Mô-đun Core của Agent

Mô-đun này triển khai class ResponseAgent chính để tự động phản hồi tấn công.
Code được tổ chức và comment rõ ràng để dễ hiểu và trình diễn demo.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set

from agent.core.state import ResponseState
from agent.core.strategies import ResponseStrategies
from agent.processing.event_loader import EventLoader
from agent.processing.classifier import EventClassifier


class ResponseAgent:
    """
    Agent AI để tự động phản hồi các tấn công được phát hiện.
    - Tải các sự kiện mới, phân loại chúng, và áp dụng chiến lược phản hồi.
    - Duy trì trạng thái (IP bị khóa, 2FA, cảnh báo, etc.).
    - Được thiết kế để rõ ràng và dễ giải thích trong demo.
    """

    def __init__(self, models_dir: str = "models", check_interval: int = 300):
        """
        Khởi tạo phản hồi agent và tất cả các thành phần core.

        Args:
            models_dir: Thư mục chứa các mô hình ML
            check_interval: Khoảng thời gian kiểm tra tính bằng giây (mặc định: 5 phút)
        """
        self.models_dir = models_dir
        self.check_interval = check_interval

        # Khởi tạo các thành phần
        self.state = ResponseState()
        self.strategies = ResponseStrategies(self.state)
        self.event_loader = EventLoader()
        self.classifier = EventClassifier(models_dir)

        print(" AI Response Agent initialized")
        print(f"   Models: {models_dir}")
        print(f"   Check interval: {check_interval}s")
        print()

    def run_once(self, dataset_path: str) -> None:
        """
        Chạy một chu kỳ giám sát và phản hồi.
        Tải các sự kiện mới, phân loại, áp dụng phản hồi, và in trạng thái.
        """
        print(f" Agent cycle started at {datetime.now()}")
        print("-" * 50)

        # Tải các sự kiện mới
        new_events = self.event_loader.load_new_events(
            dataset_path,
            self.state.last_processed_timestamp,
            self.state.processed_event_hashes
        )
        print(f" New events: {len(new_events)}")

        if not new_events:
            print("   No new events to process")
        else:
            # Phân loại events
            classifications = self.classifier.classify_events(new_events)
            attack_events = [c for c in classifications if c['is_attack']]

            print(f" Attack events detected: {len(attack_events)}")

            # Áp dụng phản hồi
            for classification in attack_events:
                self.strategies.apply_response(classification)

        # Dọn dẹp các phản hồi đã hết hạn
        self.state.cleanup_expired_responses()

        # In trạng thái
        self._print_status()

        print(f" Agent cycle completed at {datetime.now()}")
        print()

    def run_continuous(self, dataset_path: str) -> None:
        """
        Chạy agent liên tục (vòng lặp vô hạn với sleep).
        Hữu ích cho việc giám sát trực tiếp trong demo.
        """
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
        """
        In trạng thái agent hiện tại (IP bị khóa, 2FA, cảnh báo, etc.).
        Được thiết kế để rõ ràng trong demo.
        """
        print(" Agent Status:")
        print(f"   Blocked IPs: {len(self.state.blocked_ips)}")
        print(f"   Users requiring 2FA: {len(self.state.users_requiring_2fa)}")
        print(f"   Active alerts: {len(self.state.active_alerts)}")
        print(f"   Monitoring targets: {len(self.state.monitoring_targets)}")
        print(f"   Last processed: {self.state.last_processed_timestamp}")
        print()