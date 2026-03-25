"""
Mô-đun Phân loại Sự kiện

Xử lý phân loại dựa trên ML cho các sự kiện.
"""

from typing import Dict, List, Any

from ml.core.inference import predict_attack_and_type
from ml.features.feature_builder import build_features_from_events


class EventClassifier:
    """Xử lý phân loại ML cho các sự kiện."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir

    def classify_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Phân loại danh sách các sự kiện bằng mô hình ML."""
        if not events:
            return []

        # Xây dựng đặc trưng
        df_features = build_features_from_events(events)
        if df_features.empty:
            return []

        classifications = []
        for idx, row in df_features.iterrows():
            feature_dict = row.to_dict()
            # Loại bỏ các cột không phải đặc trưng
            for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
                feature_dict.pop(col, None)

            # Dự đoán
            prediction = predict_attack_and_type(feature_dict, models_dir=self.models_dir)

            # Thêm thông tin sự kiện
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

    def classify_single_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Phân loại một sự kiện duy nhất."""
        classifications = self.classify_events([event])
        return classifications[0] if classifications else {}

    def get_attack_summary(self, classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Lấy thống kê tổng hợp của các phân loại."""
        total_events = len(classifications)
        attack_events = [c for c in classifications if c['is_attack']]

        attack_types = {}
        for classification in attack_events:
            attack_type = classification['attack_type']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        return {
            'total_events': total_events,
            'attack_events': len(attack_events),
            'attack_types': attack_types,
            'attack_rate': len(attack_events) / total_events if total_events > 0 else 0
        }