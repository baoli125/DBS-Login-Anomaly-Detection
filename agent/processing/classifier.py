"""
Event Classification Module

Handles ML-based classification of events.
"""

from typing import Dict, List, Any

from ml.core.inference import predict_attack_and_type
from ml.features.feature_builder import build_features_from_events


class EventClassifier:
    """Handles ML classification of events."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir

    def classify_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify a list of events using ML models."""
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

    def classify_single_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single event."""
        classifications = self.classify_events([event])
        return classifications[0] if classifications else {}

    def get_attack_summary(self, classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary statistics of classifications."""
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