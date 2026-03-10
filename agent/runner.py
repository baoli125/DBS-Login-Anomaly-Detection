#!/usr/bin/env python3
"""
AI Response Agent Runner

CLI interface for the AI Response Agent.
"""

import argparse
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from agent import ResponseAgent


def main():
    parser = argparse.ArgumentParser(
        description="AI Response Agent for Brute-Force Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dataset",
        default="data/test_events.ndjson",
        help="Path to NDJSON dataset to monitor (default: %(default)s)",
    )
    parser.add_argument(
        "--models-dir",
        default="models",
        help="Directory containing ML models (default: %(default)s)",
    )
    parser.add_argument(
        "--check-interval",
        type=int,
        default=300,
        help="Check interval in seconds (default: %(default)s = 5 minutes)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one cycle and exit (default: continuous)",
    )

    args = parser.parse_args()

    agent = ResponseAgent(
        models_dir=args.models_dir,
        check_interval=args.check_interval,
    )

    if args.once:
        agent.run_once(args.dataset)
    else:
        agent.run_continuous(args.dataset)


if __name__ == "__main__":
    main()