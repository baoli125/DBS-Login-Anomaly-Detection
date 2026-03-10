#!/usr/bin/env python3
"""
EaglePro ML pipeline: build features, train models, evaluate vs rule-based.

Cách dùng:
  # Build feature từ NDJSON -> Parquet (mặc định: data/train_events.ndjson, data/test_events.ndjson)
  python scripts/run_ml.py build
  python scripts/run_ml.py build --train-ndjson data/train_events.ndjson --features-dir data/features

  # Train model từ Parquet (mặc định: data/features/train_features.parquet -> models/)
  python scripts/run_ml.py train
  python scripts/run_ml.py train --input-parquet data/features/train_features.parquet --output-dir models

  # So sánh ML vs rule trên cùng dataset (mặc định: data/test_events.ndjson)
  python scripts/run_ml.py evaluate
  python scripts/run_ml.py evaluate --dataset data/test_events.ndjson --models-dir models

  # Chạy cả pipeline: build -> train -> evaluate (dùng path mặc định)
  python scripts/run_ml.py all
"""

import argparse
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _ensure_project_root():
    os.chdir(PROJECT_ROOT)


def cmd_build(args):
    """Build feature Parquet từ file NDJSON."""
    from ml.features.feature_builder import build_dataset_from_ndjson

    _ensure_project_root()
    features_dir = args.features_dir or "data/features"
    os.makedirs(features_dir, exist_ok=True)

    train_ndjson = args.train_ndjson or "data/train_events.ndjson"
    test_ndjson = getattr(args, "test_ndjson", None) or "data/test_events.ndjson"

    paths_to_build = []
    if train_ndjson and os.path.exists(train_ndjson):
        paths_to_build.append((train_ndjson, os.path.join(features_dir, "train_features.parquet")))
    else:
        print(f"  Train NDJSON not found: {train_ndjson}")

    if test_ndjson and os.path.exists(test_ndjson):
        paths_to_build.append((test_ndjson, os.path.join(features_dir, "test_features.parquet")))

    if not paths_to_build:
        print(" No NDJSON file found. Generate data first: python scripts/run_generator.py")
        return 1

    print("=" * 60)
    print(" ML PIPELINE - BUILD FEATURES")
    print("=" * 60)
    for ndjson_path, parquet_path in paths_to_build:
        print(f"\n {ndjson_path} -> {parquet_path}")
        df = build_dataset_from_ndjson(ndjson_path, output_parquet_path=parquet_path)
        print(f"    {len(df)} rows written")
    print("\n Build features done.")
    return 0


def cmd_train(args):
    """Train binary + multi-class model từ Parquet."""
    from ml.core.train_models import train_models

    _ensure_project_root()
    input_parquet = args.input_parquet or "data/features/train_features.parquet"
    output_dir = args.output_dir or "models"

    if not os.path.exists(input_parquet):
        print(f" Parquet not found: {input_parquet}")
        print("   Run first: python scripts/run_ml.py build")
        return 1

    print("=" * 60)
    print(" ML PIPELINE - TRAIN MODELS")
    print("=" * 60)
    print(f"Input : {input_parquet}")
    print(f"Output: {output_dir}")
    print()
    train_models(
        input_parquet=input_parquet,
        output_dir=output_dir,
        random_state=args.random_state,
    )
    print("\n Train done.")
    return 0


def cmd_evaluate(args):
    """So sánh ML vs rule-based trên cùng dataset NDJSON."""
    from ml.evaluation.evaluate_ml_vs_rule import main as evaluate_main

    _ensure_project_root()
    dataset = args.dataset or "data/test_events.ndjson"
    if not os.path.exists(dataset):
        print(f" Dataset not found: {dataset}")
        print("   Generate test data or run: python scripts/run_generator.py")
        return 1

    # Build argv for evaluate_ml_vs_rule
    eval_argv = [
        dataset,
        "--models-dir", args.models_dir or "models",
        "--threshold-key", args.threshold_key or "t_balanced",
        "--output-dir", args.output_dir or "reports",
    ]
    if getattr(args, "no_cooldown", True):
        eval_argv.append("--no-cooldown")
    if getattr(args, "verbose", False):
        eval_argv.append("--verbose")
    if getattr(args, "custom_threshold", None) is not None:
        eval_argv.extend(["--custom-threshold", str(args.custom_threshold)])

    print("=" * 60)
    print(" ML PIPELINE - EVALUATE (ML vs RULE)")
    print("=" * 60)
    evaluate_main(eval_argv)
    return 0


def cmd_all(args):
    """Chạy cả pipeline: build -> train -> evaluate (path mặc định)."""
    _ensure_project_root()
    features_dir = args.features_dir or "data/features"
    train_ndjson = args.train_ndjson or "data/train_events.ndjson"
    test_ndjson = getattr(args, "test_ndjson", None) or "data/test_events.ndjson"
    models_dir = args.output_dir or "models"
    train_parquet = os.path.join(features_dir, "train_features.parquet")

    print("=" * 60)
    print(" ML PIPELINE - ALL (build -> train -> evaluate)")
    print("=" * 60)

    # 1. Build
    build_args = type('Args', (), {})()
    build_args.features_dir = features_dir
    build_args.train_ndjson = train_ndjson
    build_args.test_ndjson = test_ndjson
    if cmd_build(build_args) != 0:
        return 1

    # 2. Train
    train_args = type('Args', (), {})()
    train_args.input_parquet = train_parquet
    train_args.output_dir = models_dir
    train_args.random_state = getattr(args, "random_state", 42)
    if cmd_train(train_args) != 0:
        return 1

    # 3. Evaluate (nếu có test NDJSON)
    if test_ndjson and os.path.exists(test_ndjson):
        eval_args = type('Args', (), {})()
        eval_args.dataset = test_ndjson
        eval_args.models_dir = models_dir
        eval_args.threshold_key = getattr(args, "threshold_key", "t_balanced")
        eval_args.output_dir = "reports"
        eval_args.no_cooldown = getattr(args, "no_cooldown", True)
        eval_args.verbose = getattr(args, "verbose", False)
        eval_args.custom_threshold = getattr(args, "custom_threshold", None)
        if cmd_evaluate(eval_args) != 0:
            return 1
    else:
        print(f"\n  Test NDJSON not found ({test_ndjson}), skip evaluate.")

    print("\n ML pipeline (all) done.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="EaglePro ML pipeline: build features, train, evaluate vs rule.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- build ---
    p_build = subparsers.add_parser("build", help="Build feature Parquet from NDJSON")
    p_build.add_argument("--train-ndjson", default="data/train_events.ndjson", help="Train NDJSON path")
    p_build.add_argument("--test-ndjson", default="data/test_events.ndjson", help="Test NDJSON path (optional)")
    p_build.add_argument("--features-dir", default="data/features", help="Output directory for Parquet files")
    p_build.set_defaults(func=cmd_build)

    # --- train ---
    p_train = subparsers.add_parser("train", help="Train binary + multi-class models from Parquet")
    p_train.add_argument("--input-parquet", default="data/features/train_features.parquet", help="Input Parquet path")
    p_train.add_argument("--output-dir", default="models", help="Output directory for models")
    p_train.add_argument("--random-state", type=int, default=42, help="Random seed")
    p_train.set_defaults(func=cmd_train)

    # --- evaluate ---
    p_eval = subparsers.add_parser("evaluate", help="Compare ML vs rule-based on same NDJSON dataset")
    p_eval.add_argument("--dataset", default="data/test_events.ndjson", help="NDJSON dataset path")
    p_eval.add_argument("--models-dir", default="models", help="Models directory")
    p_eval.add_argument("--threshold-key", default="t_high_precision", choices=["t_high_recall", "t_balanced", "t_high_precision"])
    p_eval.add_argument("--custom-threshold", type=float, default=None, help="Override threshold (0-1)")
    p_eval.add_argument("--output-dir", default="reports", help="Report output directory")
    p_eval.add_argument("--no-cooldown", action="store_true", default=True, help="Disable rule cooldown")
    p_eval.add_argument("--verbose", action="store_true", help="Verbose output")
    p_eval.set_defaults(func=cmd_evaluate)

    # --- all ---
    p_all = subparsers.add_parser("all", help="Run full pipeline: build -> train -> evaluate (default paths)")
    p_all.add_argument("--train-ndjson", default="data/train_events.ndjson", help="Train NDJSON path")
    p_all.add_argument("--test-ndjson", default="data/test_events.ndjson", help="Test NDJSON path")
    p_all.add_argument("--features-dir", default="data/features", help="Features output directory")
    p_all.add_argument("--output-dir", default="models", help="Models output directory")
    p_all.add_argument("--random-state", type=int, default=42, help="Random seed")
    p_all.add_argument("--threshold-key", default="t_high_precision")
    p_all.add_argument("--no-cooldown", action="store_false", dest="cooldown")
    p_all.add_argument("--verbose", action="store_true")
    p_all.add_argument("--custom-threshold", type=float, default=None)
    p_all.set_defaults(func=cmd_all)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
