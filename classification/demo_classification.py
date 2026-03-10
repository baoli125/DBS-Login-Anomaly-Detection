#!/usr/bin/env python3
"""
Demo ML-based brute-force attack classification.

This script demonstrates the multi-class ML model that classifies login events
into attack types: benign, rapid_bruteforce, credential_stuffing, distributed_attack, targeted_slow_low.

Usage:
  python demo_classification.py --dataset data/test_events.ndjson --limit 10
  python demo_classification.py --event '{"timestamp":"2026-03-09T10:00:00Z","username":"user1","src_ip":"192.168.1.1","success":false}'
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.core.inference import predict_attack_and_type
from ml.features.feature_builder import build_features_from_events
from scripts.run_rulebase import load_ndjson


def demo_single_event(event: Dict[str, Any]) -> None:
    """Demo classification on a single event."""
    print(" Single Event Classification Demo")
    print("=" * 50)
    print(f"Event: {json.dumps(event, indent=2)}")
    print()

    # Build features for this event
    events = [event]
    df_features = build_features_from_events(events)

    if df_features.empty:
        print(" No features could be built from this event.")
        return

    # Get feature dict
    feature_dict = df_features.iloc[0].to_dict()
    # Remove non-feature columns
    for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
        feature_dict.pop(col, None)

    print(" Extracted Features:")
    for k, v in sorted(feature_dict.items()):
        print(f"  {k}: {v}")
    print()

    # Predict
    prediction = predict_attack_and_type(feature_dict)

    print(" ML Prediction:")
    print(f"  Binary Detection: {'ATTACK' if prediction['label'] else 'BENIGN'} "
          f"(score: {prediction['score']:.3f})")
    print(f"  Attack Type: {prediction['attack_type']} "
          f"(confidence: {max(prediction['attack_type_probabilities'].values()):.3f})")
    print()

    # Show all probabilities
    print(" Attack Type Probabilities:")
    for label, prob in prediction['attack_type_probabilities'].items():
        marker = " ←" if label == prediction['attack_type'] else ""
        print(f"  {label}: {prob:.3f}{marker}")
    print()


def demo_dataset_classification(dataset_path: str, limit: int = 10) -> None:
    """Demo classification on a dataset."""
    print(" Dataset Classification Demo")
    print("=" * 50)
    print(f"Dataset: {dataset_path}")
    print(f"Limit: {limit} events")
    print()

    # Load events
    events = load_ndjson(dataset_path)
    if not events:
        print(" No events loaded.")
        return

    # Limit for demo
    events = events[:limit]

    # Build features
    df_features = build_features_from_events(events)
    if df_features.empty:
        print(" No features could be built.")
        return

    print(" Classifying events...")
    print()

    # Classify each event
    attack_counts = {}
    for idx, row in df_features.iterrows():
        feature_dict = row.to_dict()
        # Remove non-feature columns
        for col in ['timestamp', 'entity_type', 'entity_value', 'is_attack_label', 'attack_type_label']:
            feature_dict.pop(col, None)

        prediction = predict_attack_and_type(feature_dict)

        # Count predictions
        pred_type = prediction['attack_type']
        attack_counts[pred_type] = attack_counts.get(pred_type, 0) + 1

        # Show sample predictions
        if idx < 5:  # Show first 5
            event = events[idx]
            ground_truth = event.get('attack_type', 'benign') if event.get('is_attack') else 'benign'
            print(f"Event {idx+1}:")
            print(f"  Ground Truth: {ground_truth}")
            print(f"  ML Prediction: {pred_type} (conf: {max(prediction['attack_type_probabilities'].values()):.3f})")
            print(f"  Binary: {'ATTACK' if prediction['label'] else 'BENIGN'}")
            print()

    print(" Summary:")
    total = len(df_features)
    for attack_type, count in sorted(attack_counts.items()):
        pct = count / total * 100
        print(f"  {attack_type}: {count}/{total} ({pct:.1f}%)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Demo ML-based brute-force attack classification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--dataset",
        help="Path to NDJSON dataset for batch classification demo",
    )
    group.add_argument(
        "--event",
        help="JSON string of a single event to classify",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Limit number of events to process in dataset mode (default: %(default)s)",
    )

    args = parser.parse_args()

    if args.event:
        try:
            event = json.loads(args.event)
            demo_single_event(event)
        except json.JSONDecodeError as e:
            print(f" Invalid JSON event: {e}")
            sys.exit(1)
    elif args.dataset:
        demo_dataset_classification(args.dataset, args.limit)


if __name__ == "__main__":
    main()