"""
Dataset Demo Module

Handles demonstration of dataset classification.
"""

from typing import Dict, List, Any

from scripts.run_rulebase import load_ndjson
from classification.core.classifier import EventClassifier
from classification.core.formatter import ResultFormatter


class DatasetDemo:
    """Demo for classifying datasets."""

    def __init__(self, models_dir: str = "models"):
        self.classifier = EventClassifier(models_dir)
        self.formatter = ResultFormatter()

    def run_demo(self, dataset_path: str, limit: int = 10, show_details: bool = True) -> str:
        """Run dataset classification demo."""
        # Load events
        events = load_ndjson(dataset_path)
        if not events:
            return f" No events loaded from {dataset_path}"

        # Limit for demo
        events = events[:limit]

        # Classify
        classifications, summary = self.classifier.classify_dataset(events, limit)

        if not classifications:
            return " No classifications could be performed"

        # Format results
        return self.formatter.format_dataset_results(classifications, summary, show_details)

    def load_and_validate_dataset(self, dataset_path: str) -> List[Dict[str, Any]]:
        """Load and validate dataset."""
        events = load_ndjson(dataset_path)
        if not events:
            raise FileNotFoundError(f"No events found in {dataset_path}")

        # Basic validation
        required_fields = ['timestamp', 'username', 'src_ip']
        for event in events[:5]:  # Check first 5 events
            missing = [field for field in required_fields if field not in event]
            if missing:
                raise ValueError(f"Event missing required fields: {missing}")

        return events

    def get_dataset_stats(self, dataset_path: str) -> Dict[str, Any]:
        """Get basic statistics about the dataset."""
        events = load_ndjson(dataset_path)

        total_events = len(events)
        attack_events = sum(1 for e in events if e.get('is_attack', False))

        attack_types = {}
        for event in events:
            if event.get('is_attack'):
                attack_type = event.get('attack_type', 'unknown')
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        return {
            'total_events': total_events,
            'attack_events': attack_events,
            'benign_events': total_events - attack_events,
            'attack_types': attack_types,
            'attack_rate': attack_events / total_events if total_events > 0 else 0
        }