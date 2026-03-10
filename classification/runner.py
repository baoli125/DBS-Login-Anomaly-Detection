"""
Classification Runner

CLI interface for classification demos.
"""

import argparse
import sys
from pathlib import Path

from classification.demo.single_event import SingleEventDemo
from classification.demo.dataset_demo import DatasetDemo


def main():
    """Main entry point for classification runner."""
    parser = argparse.ArgumentParser(
        description="EaglePro Classification Demo Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single event classification
  python -m classification.runner single --event '{"timestamp": "2024-01-01T00:00:00Z", "username": "admin", "src_ip": "192.168.1.100", "success": false}'

  # Dataset classification demo
  python -m classification.runner dataset --dataset data/test_events.ndjson --limit 20

  # Dataset stats
  python -m classification.runner stats --dataset data/test_events.ndjson
        """
    )

    parser.add_argument(
        'command',
        choices=['single', 'dataset', 'stats'],
        help='Demo command to run'
    )

    parser.add_argument(
        '--event',
        type=str,
        help='JSON string for single event classification'
    )

    parser.add_argument(
        '--dataset',
        type=str,
        help='Path to NDJSON dataset file'
    )

    parser.add_argument(
        '--limit',
        type=int,
        default=10,
        help='Limit number of events to process (default: 10)'
    )

    parser.add_argument(
        '--models-dir',
        type=str,
        default='models',
        help='Directory containing trained models (default: models)'
    )

    parser.add_argument(
        '--no-details',
        action='store_true',
        help='Hide detailed results in output'
    )

    args = parser.parse_args()

    try:
        if args.command == 'single':
            if not args.event:
                print(" --event is required for single event classification")
                sys.exit(1)

            demo = SingleEventDemo(args.models_dir)
            result = demo.run_demo(demo.parse_event_from_json(args.event))
            print(result)

        elif args.command == 'dataset':
            if not args.dataset:
                print(" --dataset is required for dataset classification")
                sys.exit(1)

            if not Path(args.dataset).exists():
                print(f" Dataset file not found: {args.dataset}")
                sys.exit(1)

            demo = DatasetDemo(args.models_dir)
            result = demo.run_demo(args.dataset, args.limit)
            print(result)

        elif args.command == 'stats':
            if not args.dataset:
                print(" --dataset is required for dataset stats")
                sys.exit(1)

            if not Path(args.dataset).exists():
                print(f" Dataset file not found: {args.dataset}")
                sys.exit(1)

            demo = DatasetDemo(args.models_dir)
            stats = demo.get_dataset_stats(args.dataset)

            print(" Dataset Statistics")
            print("=" * 50)
            print(f"Total Events: {stats['total_events']}")
            print(f"Attack Events: {stats['attack_events']}")
            print(f"Benign Events: {stats['benign_events']}")
            print(".2%")
            print("\nAttack Types:")
            for attack_type, count in stats['attack_types'].items():
                print(f"  {attack_type}: {count}")

    except Exception as e:
        print(f" Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()