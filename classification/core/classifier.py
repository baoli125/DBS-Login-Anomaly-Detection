"""
Classification Core Module

Contains the main classification logic and utilities.
"""

import json
from typing import Dict, List, Any

from ml.core.inference import predict_attack_and_type
from ml.features.feature_builder import build_features_from_events


class EventClassifier:
    """Handles ML classification of events."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir

    def classify_single_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single event."""
        # Build features for this event
        events = [event]
        df_features = build_features_from_events(events)

        if df_features.empty:
            return {
                'error': 'No features could be built from this event',
                'event': event
            }

        # Get feature dict
        feature_dict = df_features.iloc[0].to_dict()
        # Remove non-feature columns
        for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
            feature_dict.pop(col, None)

        # Predict
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
        """Classify a dataset of events."""
        if limit:
            events = events[:limit]

        # Build features
        df_features = build_features_from_events(events)
        if df_features.empty:
            return []

        classifications = []
        attack_counts = {}

        for idx, row in df_features.iterrows():
            feature_dict = row.to_dict()
            # Remove non-feature columns
            for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
                feature_dict.pop(col, None)

            prediction = predict_attack_and_type(feature_dict, models_dir=self.models_dir)

            # Count predictions
            pred_type = prediction['attack_type']
            attack_counts[pred_type] = attack_counts.get(pred_type, 0) + 1

            # Add event info
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