"""
Output Formatting Module

Handles formatting and display of classification results.
"""

import json
from typing import Dict, List, Any


class ResultFormatter:
    """Formats classification results for display."""

    def format_single_event_result(self, result: Dict[str, Any]) -> str:
        """Format result for single event classification."""
        if 'error' in result:
            return f" Error: {result['error']}\nEvent: {json.dumps(result['event'], indent=2, default=str)}"

        lines = []
        lines.append(" Single Event Classification Demo")
        lines.append("=" * 50)
        lines.append(f"Event: {json.dumps(result['event'], indent=2, default=str)}")
        lines.append("")

        lines.append(" Extracted Features:")
        for k, v in sorted(result['features'].items()):
            lines.append(f"  {k}: {v}")
        lines.append("")

        lines.append(" ML Prediction:")
        pred = result['prediction']
        lines.append(f"  Binary Detection: {result['binary_result']} (score: {pred['score']:.3f})")
        lines.append(f"  Attack Type: {result['attack_type']} (confidence: {result['confidence']:.3f})")
        lines.append("")

        lines.append(" Attack Type Probabilities:")
        for label, prob in result['probabilities'].items():
            marker = " ←" if label == result['attack_type'] else ""
            lines.append(f"  {label}: {prob:.3f}{marker}")
        lines.append("")

        return "\n".join(lines)

    def format_dataset_results(self, classifications: List[Dict[str, Any]],
                             summary: Dict[str, Any], show_details: bool = True) -> str:
        """Format results for dataset classification."""
        lines = []
        lines.append(" Dataset Classification Demo")
        lines.append("=" * 50)
        lines.append(f"Total Events: {summary['total_events']}")
        lines.append("")

        if show_details and classifications:
            lines.append(" Sample Classifications:")
            lines.append("")

            # Show first 5 results
            for i, result in enumerate(classifications[:5]):
                event = result['event']
                pred = result['prediction']
                lines.append(f"Event {i+1}:")
                lines.append(f"  Ground Truth: {result['ground_truth']}")
                lines.append(f"  ML Prediction: {result['attack_type']} (conf: {result['confidence']:.3f})")
                lines.append(f"  Binary: {result['binary_result']}")
                lines.append("")

        lines.append(" Summary:")
        for attack_type, count in sorted(summary['attack_counts'].items()):
            pct = count / summary['total_events'] * 100
            lines.append(f"  {attack_type}: {count}/{summary['total_events']} ({pct:.1f}%)")
        lines.append("")

        return "\n".join(lines)

    def format_attack_summary(self, summary: Dict[str, Any]) -> str:
        """Format attack summary statistics."""
        lines = []
        lines.append(" Attack Detection Summary:")
        lines.append(f"  Total Events: {summary['total_events']}")
        lines.append(f"  Attack Events: {summary['attack_events']}")
        lines.append(f"  Attack Rate: {summary['attack_rate']:.1%}")
        lines.append("")
        lines.append("  Attack Types:")

        for attack_type, count in summary['attack_types'].items():
            pct = count / summary['attack_events'] * 100 if summary['attack_events'] > 0 else 0
            lines.append(f"    {attack_type}: {count} ({pct:.1f}%)")

        return "\n".join(lines)