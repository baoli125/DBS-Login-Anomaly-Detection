#!/usr/bin/env python3
from __future__ import annotations


"""
So sánh phát hiện dựa trên ML với phát hiện dựa trên quy tắc trên cùng một tập dữ liệu NDJSON (Phiên bản DEMO)

Script này:
    1. Tải sự kiện từ NDJSON (đầu ra của run_generator.py)
    2. Chạy đánh giá quy tắc để lấy số liệu chuẩn
    3. Chạy đánh giá ML trên cùng tập sự kiện
    4. In bảng so sánh song song (precision, recall, F1, phát hiện theo attack_type)
    5. Lưu báo cáo JSON cho demo và phân tích sau (trong reports/)

Được thiết kế cho demo và trình bày: đầu ra rõ ràng, số liệu dễ so sánh, và kết quả được lưu để xem lại.
"""

import argparse
import json
import os
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from ml.core.metrics import compute_binary_metrics

# Đảm bảo thư mục gốc dự án trong sys.path để có thể import `scripts.*` và `ml.*`
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ..features.feature_builder import build_features_from_events  # type: ignore  # noqa: E402
from ..features.features import get_feature_names  # type: ignore  # noqa: E402
from ..core.inference import LoadedModels, load_models  # type: ignore  # noqa: E402
from scripts.run_rulebase import (  # type: ignore  # noqa: E402
    evaluate_events,
    load_ndjson,
)


@dataclass
class BinaryMetrics:
    precision: float
    recall: float
    f1: float
    support_pos: int
    support_neg: int


## All binary metric computation now in ml.core.metrics


def _ml_detect_attack_types(
    df_features: pd.DataFrame,
    scores: np.ndarray,
    y_pred: np.ndarray,
) -> Dict[str, Dict[str, float]]:
    """
    Compute tấn công-type level phát hiện statistics for ML predictions.

    Returns:
        {
          attack_type: {
             'total': int,
             'detected': int,
             'rate': float,
          },
          ...
        }
    """
    stats: Dict[str, Dict[str, float]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "rate": 0.0}
    )

    attack_types = df_features["attack_type_label"].astype(str).fillna("benign").to_numpy()
    is_attack = df_features["is_attack_label"].astype(int).to_numpy()

    for idx in range(len(df_features)):
        if not is_attack[idx]:
            continue
        attack_type = attack_types[idx]
        stats[attack_type]["total"] += 1
        if y_pred[idx] == 1:
            stats[attack_type]["detected"] += 1

    for attack_type, s in stats.items():
        total = s["total"]
        detected = s["detected"]
        s["rate"] = float(detected / total) if total > 0 else 0.0

    return dict(stats)


def _run_ml_evaluation(
    events: List[Dict[str, Any]],
    models: LoadedModels,
    threshold_key: str,
    custom_threshold: float | None = None,
) -> Tuple[BinaryMetrics, Dict[str, Dict[str, float]]]:
    """
    Run ML evaluation on the provided events using pre-trained models.
    """
    df_features = build_features_from_events(events)
    if df_features.empty:
        raise ValueError("Feature dataset is empty; cannot run ML evaluation.")

    feature_names = models.feature_names or get_feature_names()

    missing_features = [f for f in feature_names if f not in df_features.columns]
    if missing_features:
        raise ValueError(f"Missing expected feature columns in features DataFrame: {missing_features}")

    X = df_features[feature_names].to_numpy(dtype=float)
    y_true = df_features["is_attack_label"].astype(int).to_numpy()

    # Scale and compute scores
    X_scaled = models.scaler.transform(X)
    scores = models.binary_model.predict_proba(X_scaled)[:, 1]

    # Decide threshold
    if custom_threshold is not None:
        threshold_used = float(custom_threshold)
        threshold_name = "custom"
    else:
        thresholds = models.thresholds
        if threshold_key not in thresholds:
            threshold_used = 0.5
            threshold_name = "0.5_fallback"
        else:
            threshold_used = float(thresholds[threshold_key])
            threshold_name = threshold_key

    y_pred = (scores >= threshold_used).astype(int)

    binary_metrics = compute_binary_metrics(y_true, scores, threshold=threshold_used)
    binary_metrics["threshold_used"] = threshold_used
    binary_metrics["threshold_name"] = threshold_name
    attack_type_stats = _ml_detect_attack_types(df_features, scores, y_pred)
    return binary_metrics, attack_type_stats


def _print_side_by_side(
    rule_results: Dict[str, Any],
    ml_metrics: BinaryMetrics,
    ml_attack_types: Dict[str, Dict[str, float]],
) -> None:
    """
    Pretty-print comparison between dựa trên quy tắc and ML phát hiện.
    """
    print("\n" + "=" * 80)
    print(" RULE-BASED vs ML DETECTION (BINARY)")
    print("=" * 80)

    # Overall metrics
    print("\n[Overall metrics]")
    print("-" * 40)
    rule_prec = float(rule_results.get("precision", 0.0))
    rule_rec = float(rule_results.get("recall", 0.0))
    rule_f1 = float(rule_results.get("f1_score", 0.0))

    print(f"Rule-based Precision : {rule_prec:.3f}")
    print(f"Rule-based Recall    : {rule_rec:.3f}")
    print(f"Rule-based F1        : {rule_f1:.3f}")

    print()
    print(f"ML Precision         : {ml_metrics['precision']:.3f}")
    print(f"ML Recall            : {ml_metrics['recall']:.3f}")
    print(f"ML F1                : {ml_metrics['f1']:.3f}")

    # Threshold info if available
    threshold_name = ml_metrics.get("threshold_name", "n/a")
    threshold_used = ml_metrics.get("threshold_used", None)
    if threshold_used is not None:
        print(f"ML Threshold         : {threshold_used:.3f} ({threshold_name})")

    # Tấn công-type comparison
    print("\n[Detection rate by attack_type]")
    print("-" * 40)
    print(
        f"{'Attack Type':25s} | {'Rule Detected/Total':20s} | "
        f"{'Rule Rate':10s} | {'ML Detected/Total':18s} | {'ML Rate':10s}"
    )
    print("-" * 80)

    rule_attack_types = rule_results.get("attack_type_detection", {}) or {}

    all_types = sorted(
        set(rule_attack_types.keys()) | set(ml_attack_types.keys())
    )

    for attack_type in all_types:
        r_stats = rule_attack_types.get(attack_type, {})
        m_stats = ml_attack_types.get(attack_type, {})

        r_total = int(r_stats.get("total", 0))
        r_detected = int(r_stats.get("detected", 0))
        r_rate = float(r_stats.get("rate", 0.0))

        m_total = int(m_stats.get("total", 0))
        m_detected = int(m_stats.get("detected", 0))
        m_rate = float(m_stats.get("rate", 0.0))

        print(
            f"{attack_type:25s} | "
            f"{r_detected:4d}/{r_total:<14d} | {r_rate:8.3f} | "
            f"{m_detected:4d}/{m_total:<12d} | {m_rate:8.3f}"
        )


def _save_report(
    dataset_path: str,
    rule_results: Dict[str, Any],
    ml_metrics: BinaryMetrics,
    ml_attack_types: Dict[str, Dict[str, float]],
    output_dir: str,
) -> str:
    """
    Save a JSON report with rule vs ML comparison for further analysis.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"ml_vs_rule_{ts}.json")

    report = {
        "dataset": os.path.abspath(dataset_path),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "rule_results": rule_results,
        "ml_metrics": ml_metrics,
        "ml_attack_type_detection": ml_attack_types,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return output_path


def _parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare ML-based detection vs rule-based system on the same NDJSON dataset.",
    )
    parser.add_argument(
        "dataset",
        help="Path to NDJSON dataset file (same format used for rule-based evaluation).",
    )
    parser.add_argument(
        "--models-dir",
        default="models",
        help="Directory containing ML model artifacts (default: %(default)s).",
    )
    parser.add_argument(
        "--threshold-key",
        default="t_high_precision",
        choices=["t_high_recall", "t_balanced", "t_high_precision"],
        help="Which pre-computed binary threshold to use for ML (default: %(default)s).",
    )
    parser.add_argument(
        "--custom-threshold",
        type=float,
        default=None,
        help="Override threshold with a custom value (0–1). If set, ignores --threshold-key.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save comparison report JSON (default: %(default)s).",
    )
    parser.add_argument(
        "--no-cooldown",
        action="store_true",
        help="Pass-through option to rule-based evaluator: disable cooldown periods.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional rule-based evaluation logs.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = _parse_args(argv)

    if not os.path.exists(args.dataset):
        raise FileNotFoundError(f"Dataset not found: {args.dataset}")

    print("=" * 80)
    print(" EAGLEPRO: ML vs RULE-BASED DETECTION EVALUATION")
    print("=" * 80)
    print(f"Dataset        : {args.dataset}")
    print(f"Models dir     : {args.models_dir}")
    print(f"Threshold key  : {args.threshold_key}")
    print(f"Custom thr     : {args.custom_threshold}")
    print(f"No cooldown    : {args.no_cooldown}")
    print(f"Verbose rules  : {args.verbose}")
    print(f"Output dir     : {args.output_dir}")
    print()

    # 1) Tải events (shared input for dựa trên quy tắc and ML)
    print(" Loading events (NDJSON)...")
    events = load_ndjson(args.dataset)
    if not events:
        raise RuntimeError("No events loaded from dataset; aborting.")

    # 2) Run dựa trên quy tắc evaluation
    print("\n Running rule-based evaluation (baseline)...")
    alerts_rule, rule_results = evaluate_events(
        events,
        no_cooldown=args.no_cooldown,
        verbose=args.verbose,
    )

    # 3) Tải ML models
    print("\n Loading ML models...")
    models = load_models(models_dir=args.models_dir, use_cache=True)

    # 4) Run ML evaluation on same events
    print("\n Running ML evaluation on same dataset...")
    ml_metrics, ml_attack_types = _run_ml_evaluation(
        events=events,
        models=models,
        threshold_key=args.threshold_key,
        custom_threshold=args.custom_threshold,
    )

    # 5) Print side-by-side comparison
    _print_side_by_side(rule_results, ml_metrics, ml_attack_types)

    # 6) Save JSON report
    print("\n Writing JSON comparison report...")
    report_path = _save_report(
        dataset_path=args.dataset,
        rule_results=rule_results,
        ml_metrics=ml_metrics,
        ml_attack_types=ml_attack_types,
        output_dir=args.output_dir,
    )
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()

