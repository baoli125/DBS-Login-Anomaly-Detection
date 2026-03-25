#!/usr/bin/env python3

"""
EaglePro ML pipeline - DEMO VERSION

Script này runs the full ML pipeline for login anomaly phát hiện:
    1. Xây dựng đặc trưng from NDJSON sự kiện data (output from run_generator.py)
    2. Train ML models (binary + multi-class) from đặc trưng
    3. Evaluate ML vs dựa trên quy tắc phát hiện on the same tập dữ liệu
    4. Optionally run the full pipeline in one command

Được thiết kế cho demo và trình bày: mỗi bước rõ ràng, đầu ra dễ hiểu và kết quả được lưu để so sánh.

Usage examples:
    # Xây dựng đặc trưng from NDJSON
    python scripts/run_ml.py xây dựng
    python scripts/run_ml.py xây dựng --all-ndjson data/all_events.ndjson --đặc trưng-dir data/đặc trưng

    # Train model from Parquet
    python scripts/run_ml.py train
    python scripts/run_ml.py train --input-parquet data/đặc trưng/all_features.parquet --output-dir models

    # Compare ML vs dựa trên quy tắc on the same tập dữ liệu
    python scripts/run_ml.py evaluate
    python scripts/run_ml.py evaluate --tập dữ liệu data/all_events.ndjson --models-dir models

    # Chạy toàn bộ pipeline: xây dựng -> train -> evaluate
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
    """
    Step 1: Xây dựng đặc trưng Parquet from NDJSON sự kiện data.
    Input: NDJSON files (from run_generator.py)
    Output: Parquet files for ML training/testing
    """
    from ml.features.feature_builder import build_dataset_from_ndjson

    _ensure_project_root()
    features_dir = args.features_dir or "data/features"
    os.makedirs(features_dir, exist_ok=True)

    all_ndjson = args.all_ndjson or "data/all_events.ndjson"

    if not os.path.exists(all_ndjson):
        print(f" All NDJSON not found: {all_ndjson}")
        print("   Generate data first: python scripts/run_generator.py")
        return 1

    print("Building features...")
    parquet_path = os.path.join(features_dir, "all_features.parquet")
    df = build_dataset_from_ndjson(all_ndjson, output_parquet_path=parquet_path)
    print(f"Features built: {len(df)} rows")

    # Chia sự kiện thành train và test NDJSON
    import json
    events = []
    with open(all_ndjson, 'r') as f:
        for line in f:
            events.append(json.loads(line.strip()))
    
    from sklearn.model_selection import train_test_split
    train_events, test_events = train_test_split(events, test_size=0.2, random_state=42)
    
    train_ndjson = os.path.join(os.path.dirname(all_ndjson), "train_events.ndjson")
    test_ndjson = os.path.join(os.path.dirname(all_ndjson), "test_events.ndjson")
    
    with open(train_ndjson, 'w') as f:
        for event in train_events:
            json.dump(event, f)
            f.write('\n')
    
    with open(test_ndjson, 'w') as f:
        for event in test_events:
            json.dump(event, f)
            f.write('\n')
    
    print(f"Split into train ({len(train_events)} events) and test ({len(test_events)} events)")
    
    return 0


def cmd_train(args):
    """
    Step 2: Train binary + multi-class ML models from Parquet đặc trưng.
    Input: Parquet file (from xây dựng step)
    Output: Trained models and metadata (saved to models/)
    """
    from ml.core.train_models import train_models

    _ensure_project_root()
    input_parquet = args.input_parquet or "data/features/train_features.parquet"
    
    # Xây dựng train đặc trưng if not exists
    if not os.path.exists(input_parquet):
        from ml.features.feature_builder import build_dataset_from_ndjson
        train_ndjson = "data/train_events.ndjson"
        if os.path.exists(train_ndjson):
            build_dataset_from_ndjson(train_ndjson, output_parquet_path=input_parquet)
            print(f"Built train features: {input_parquet}")
        else:
            print(f" Train NDJSON not found: {train_ndjson}")
            return 1
    output_dir = args.output_dir or "models"

    if not os.path.exists(input_parquet):
        print(f" Parquet not found: {input_parquet}")
        print("   Run first: python scripts/run_ml.py build")
        return 1

    print("Training models...")
    train_models(
        input_parquet=input_parquet,
        output_dir=output_dir,
        random_state=args.random_state,
    )
    print("Training complete.")
    return 0


def cmd_evaluate(args):
    """
    Step 3: Evaluate ML vs dựa trên quy tắc phát hiện on the same tập dữ liệu.
    Input: NDJSON kiểm tra set, trained models
    Output: Metrics and comparison reports (saved to reports/)
    """
    from ml.evaluation.evaluate_ml_vs_rule import main as evaluate_main

    _ensure_project_root()
    dataset = args.dataset or "data/test_events.ndjson"
    if not os.path.exists(dataset):
        print(f" Dataset not found: {dataset}")
        print("   Generate test data or run: python scripts/run_generator.py")
        return 1

    # Xây dựng argv for evaluate_ml_vs_rule
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

    print("Evaluating ML vs Rule...")
    evaluate_main(eval_argv)
    return 0


def cmd_all(args):
    """
    Run the full ML pipeline: xây dựng -> train -> evaluate (default paths).
    For demo: shows the complete workflow in one command.
    """
    _ensure_project_root()
    features_dir = args.features_dir or "data/features"
    all_ndjson = args.all_ndjson or "data/all_events.ndjson"
    models_dir = args.output_dir or "models"
    all_parquet = os.path.join(features_dir, "train_features.parquet")

    print("Running full ML pipeline...")

    # 1. Xây dựng
    build_args = type('Args', (), {})()
    build_args.features_dir = features_dir
    build_args.all_ndjson = all_ndjson
    if cmd_build(build_args) != 0:
        return 1

    # 2. Train
    train_args = type('Args', (), {})()
    train_args.input_parquet = all_parquet
    train_args.output_dir = models_dir
    train_args.random_state = getattr(args, "random_state", 42)
    if cmd_train(train_args) != 0:
        return 1

    # 3. Đánh giá (nếu có toàn bộ NDJSON)
    if all_ndjson and os.path.exists(all_ndjson):
        eval_args = type('Args', (), {})()
        eval_args.dataset = "data/test_events.ndjson"
        eval_args.models_dir = models_dir
        # if args.threshold_key was provided from CLI, use it; otherwise default to t_balanced
        eval_args.threshold_key = getattr(args, "threshold_key", "t_balanced") or "t_balanced"
        eval_args.output_dir = "reports"
        eval_args.no_cooldown = getattr(args, "no_cooldown", True)
        eval_args.verbose = getattr(args, "verbose", False)
        eval_args.custom_threshold = getattr(args, "custom_threshold", None)
        if cmd_evaluate(eval_args) != 0:
            return 1
    else:
        print(f"\n  All NDJSON not found ({all_ndjson}), skip evaluate.")

    print("ML pipeline complete.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="EaglePro ML pipeline: build features, train, evaluate vs rule.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- xây dựng ---
    p_build = subparsers.add_parser("build", help="Build feature Parquet from NDJSON")
    p_build.add_argument("--all-ndjson", default="data/all_events.ndjson", help="All NDJSON path")
    p_build.add_argument("--features-dir", default="data/features", help="Output directory for Parquet files")
    p_build.set_defaults(func=cmd_build)

    # --- train ---
    p_train = subparsers.add_parser("train", help="Train binary + multi-class models from Parquet")
    p_train.add_argument("--input-parquet", default="data/features/all_features.parquet", help="Input Parquet path")
    p_train.add_argument("--output-dir", default="models", help="Output directory for models")
    p_train.add_argument("--random-state", type=int, default=42, help="Random seed")
    p_train.set_defaults(func=cmd_train)

    # --- evaluate ---
    p_eval = subparsers.add_parser("evaluate", help="Compare ML vs rule-based on same NDJSON dataset")
    p_eval.add_argument("--dataset", default="data/all_events.ndjson", help="NDJSON dataset path")
    p_eval.add_argument("--models-dir", default="models", help="Models directory")
    p_eval.add_argument("--threshold-key", default="t_balanced", choices=["t_high_recall", "t_balanced", "t_high_precision"], help="Threshold key for ML binary decision")
    p_eval.add_argument("--custom-threshold", "--threshold", type=float, default=0.35, help="Override threshold (0-1). Default is 0.4 for consistent evaluation. Alias: --threshold")
    p_eval.add_argument("--output-dir", default="reports", help="Report output directory")
    p_eval.add_argument("--no-cooldown", action="store_true", default=True, help="Disable rule cooldown")
    p_eval.add_argument("--verbose", action="store_true", help="Verbose output")
    p_eval.set_defaults(func=cmd_evaluate)

    # --- all ---
    p_all = subparsers.add_parser("all", help="Run full pipeline: build -> train -> evaluate (default paths)")
    p_all.add_argument("--all-ndjson", default="data/all_events.ndjson", help="All NDJSON path")
    p_all.add_argument("--features-dir", default="data/features", help="Features output directory")
    p_all.add_argument("--output-dir", default="models", help="Models output directory")
    p_all.add_argument("--random-state", type=int, default=42, help="Random seed")
    p_all.add_argument("--threshold-key", default="t_balanced", choices=["t_high_recall", "t_balanced", "t_high_precision"], help="Threshold key for ML binary decision")
    p_all.add_argument("--no-cooldown", action="store_false", dest="cooldown")
    p_all.add_argument("--verbose", action="store_true")
    p_all.add_argument("--custom-threshold", type=float, default=0.19, help="Custom threshold for evaluation (default 0.19).")
    p_all.set_defaults(func=cmd_all)

    # Cho phép shorthand invocation like:
    #   python scripts/run_ml.py data/all_events.ndjson
    # which behaves like:
    #   python scripts/run_ml.py evaluate --tập dữ liệu data/all_events.ndjson
    raw_args = sys.argv[1:]
    known_commands = {"build", "train", "evaluate", "all", "-h", "--help"}
    if raw_args and raw_args[0] not in known_commands:
        raw_args = ["evaluate", "--dataset", raw_args[0]] + raw_args[1:]

    args = parser.parse_args(raw_args)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
