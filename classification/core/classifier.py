"""
Mô-đun Core Phân loại

Chứa logic phân loại chính và các tiện ích.
"""

import json
from typing import Dict, List, Any

from ml.core.inference import predict_attack_and_type
from ml.features.feature_builder import build_features_from_events


class EventClassifier:
    """Xử lý phân loại ML cho các sự kiện."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir

    def classify_single_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Phân loại một sự kiện duy nhất."""
        # Xây dựng đặc trưng cho sự kiện này
        events = [event]
        df_features = build_features_from_events(events)

        if df_features.empty:
            return {
                'error': 'No features could be built from this event',
                'event': event
            }

        # Lấy dict đặc trưng
        feature_dict = df_features.iloc[0].to_dict()
        # Loại bỏ các cột không phải đặc trưng
        for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
            feature_dict.pop(col, None)

        # Dự đoán
        prediction = predict_attack_and_type(feature_dict, models_dir=self.models_dir)

        return {
            'event': event,
            'features': feature_dict,
            'prediction': prediction,
            'binary_result': 'ATTACK' if prediction['label'] else 'BENIGN',
            'attack_type': prediction['attack_type'],
            'confidence': max(prediction['attack_type_probabilities'].values()),
            'probabilities': prediction['attack_type_probabilities']
        }

    def classify_dataset(self, events: List[Dict[str, Any]], limit: int = None) -> List[Dict[str, Any]]:
        """Phân loại một tập dữ liệu các sự kiện."""
        if limit:
            events = events[:limit]

        # Xây dựng đặc trưng
        df_features = build_features_from_events(events)
        if df_features.empty:
            return []

        classifications = []
        attack_counts = {}

        for idx, row in df_features.iterrows():
            feature_dict = row.to_dict()
            # Remove non-đặc trưng columns
            for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
                feature_dict.pop(col, None)

            prediction = predict_attack_and_type(feature_dict, models_dir=self.models_dir)

            # Đếm dự đoán
            pred_type = prediction['attack_type']
            attack_counts[pred_type] = attack_counts.get(pred_type, 0) + 1

            # Thêm thông tin sự kiện
            event = events[idx]
            ground_truth = event.get('attack_type', 'benign') if event.get('is_attack') else 'benign'

            classification = {
                'event': event,
                'ground_truth': ground_truth,
                'prediction': prediction,
                'binary_result': 'ATTACK' if prediction['label'] else 'BENIGN',
                'attack_type': pred_type,
                'confidence': max(prediction['attack_type_probabilities'].values()),
                'features': feature_dict
            }
            classifications.append(classification)

        # Add summary
        total = len(classifications)
        summary = {
            'total_events': total,
            'attack_counts': attack_counts,
            'attack_rate': sum(attack_counts.values()) / total if total > 0 else 0
        }

        return classifications, summary