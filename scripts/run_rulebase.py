#!/usr/bin/env python3
"""
Fixed Rule-Based Evaluation with new aggregator and evaluator
COMPATIBLE with the rewritten rule-based system
"""

import sys
import os
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from detection_system.rule_based.aggregator import SimpleAggregator
from detection_system.rule_based.rule_loader import RuleLoader
from detection_system.rule_based.rule_evaluator import RuleEvaluator, Decision

def parse_timestamp(timestamp):
    """Parse timestamp from various formats (compatible with new aggregator)"""
    if isinstance(timestamp, datetime):
        return timestamp
    elif isinstance(timestamp, str):
        try:
            if timestamp.endswith('Z'):
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                return datetime.fromisoformat(timestamp)
        except:
            try:
                # Try other formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        return datetime.strptime(timestamp, fmt)
                    except:
                        continue
                return datetime.now()
            except:
                return datetime.now()
    else:
        return datetime.now()

def load_ndjson(filepath, max_events=None):
    """Load events from NDJSON file"""
    events = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if max_events and i >= max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as e:
                print(f" Error parsing line {i+1}: {e}")
                continue
    return events

def evaluate_events(events, no_cooldown=False, verbose=False):
    """
    Evaluate events using the new rule-based system
    
    Returns:
        alerts: List of alerts triggered
        metrics: Evaluation metrics
    """
    print(" Initializing rule-based detection system...")
    
    # Initialize components
    aggregator = SimpleAggregator()
    rule_loader = RuleLoader()
    evaluator = RuleEvaluator(rule_loader)
    
    # Disable cooldown if requested
    if no_cooldown:
        for rule in rule_loader.rules.values():
            rule.cooldown_seconds = 0
    
    # Statistics
    total_events = len(events)
    attack_events = [e for e in events if e.get('is_attack', False)]
    normal_events = [e for e in events if not e.get('is_attack', False)]
    
    print(f" Dataset: {total_events} total events")
    print(f"  - Attack events: {len(attack_events)} ({len(attack_events)/total_events*100:.1f}%)")
    print(f"  - Normal events: {len(normal_events)} ({len(normal_events)/total_events*100:.1f}%)")
    
    # Load rules
    enabled_rules = rule_loader.get_enabled_rules()
    print(f" Enabled rules: {len(enabled_rules)}")
    for rule in enabled_rules:
        print(f"  - {rule.name} ({rule.id})")
    
    # Process events
    alerts = []
    attack_detections = set()  # Event indices where attacks were detected
    false_positives = []       # Alerts on normal events
    
    # Track by entity for deduplication
    last_alert_by_entity = {}
    
    print("\n Processing events...")
    
    for event_idx, event in enumerate(events):
        if verbose and event_idx % 500 == 0 and event_idx > 0:
            print(f"  Processed {event_idx}/{total_events} events...")
        
        # Parse timestamp
        timestamp = parse_timestamp(event.get('timestamp', datetime.now()))
        event['timestamp'] = timestamp
        
        # Evaluate in real-time (using the new method)
        decision = evaluator.evaluate_realtime(aggregator, event)
        
        if decision and decision.matched:
            # Check for duplicate alerts (same entity, same rule within 30 seconds)
            entity_key = None
            if event.get('src_ip') and decision.rule_id.startswith('R-rapid'):
                entity_key = f"ip:{event['src_ip']}:{decision.rule_id}"
            elif event.get('username') and decision.rule_id.startswith('R-distributed'):
                entity_key = f"user:{event['username']}:{decision.rule_id}"
            
            # Apply deduplication
            if entity_key and entity_key in last_alert_by_entity:
                last_time = last_alert_by_entity[entity_key]
                time_diff = (timestamp - last_time).total_seconds()
                if time_diff < 30:  # 30-second deduplication window
                    continue
            
            # Record alert
            is_attack = event.get('is_attack', False)
            alert = {
                'event_index': event_idx,
                'timestamp': timestamp.isoformat(),
                'entity': event.get('src_ip') or event.get('username'),
                'entity_type': 'ip' if event.get('src_ip') and decision.rule_id.startswith('R-rapid') else 'user',
                'rule_id': decision.rule_id,
                'rule_name': decision.evidence.get('rule_name', 'Unknown'),
                'action': decision.action_suggestion,
                'severity': decision.evidence.get('severity', 'medium'),
                'is_attack': is_attack,
                'attack_type': event.get('attack_type', None),
                'metrics': decision.evidence.get('metrics', {}),
                'evidence': {
                    'sample_count': decision.evidence.get('raw_sample_count', 0),
                    'failed_attempts': decision.evidence.get('failed_attempts_30s', 0)
                }
            }
            
            alerts.append(alert)
            
            # Update tracking
            if entity_key:
                last_alert_by_entity[entity_key] = timestamp
            
            # Update statistics
            if is_attack:
                attack_detections.add(event_idx)
            else:
                false_positives.append({
                    'event_index': event_idx,
                    'rule_id': decision.rule_id,
                    'timestamp': timestamp.isoformat()
                })
    
    # Calculate metrics
    print("\n Calculating metrics...")
    
    total_attack_events = len(attack_events)
    detected_attack_events = len(attack_detections)
    missed_attack_events = total_attack_events - detected_attack_events
    false_positive_count = len(false_positives)
    
    # Precision, Recall, F1
    precision = 0
    if len(alerts) > 0:
        precision = detected_attack_events / (detected_attack_events + false_positive_count)
    
    recall = 0
    if total_attack_events > 0:
        recall = detected_attack_events / total_attack_events
    
    f1 = 0
    if precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    
    # Rule performance breakdown
    rule_performance = defaultdict(lambda: {
        'total_alerts': 0,
        'attack_alerts': 0,
        'false_positives': 0,
        'detected_events': set()
    })
    
    for alert in alerts:
        rule_id = alert['rule_id']
        rule_performance[rule_id]['total_alerts'] += 1
        
        if alert['is_attack']:
            rule_performance[rule_id]['attack_alerts'] += 1
            rule_performance[rule_id]['detected_events'].add(alert['event_index'])
        else:
            rule_performance[rule_id]['false_positives'] += 1
    
    # Convert sets to counts
    for rule_id, stats in rule_performance.items():
        stats['detected_events_count'] = len(stats['detected_events'])
        stats['precision'] = stats['attack_alerts'] / stats['total_alerts'] if stats['total_alerts'] > 0 else 0
        del stats['detected_events']
    
    # Attack type detection rates
    attack_type_detection = defaultdict(lambda: {'total': 0, 'detected': 0})
    
    for event_idx, event in enumerate(events):
        if event.get('is_attack'):
            attack_type = event.get('attack_type', 'unknown')
            attack_type_detection[attack_type]['total'] += 1
            if event_idx in attack_detections:
                attack_type_detection[attack_type]['detected'] += 1
    
    # Calculate detection rates
    for attack_type in attack_type_detection:
        total = attack_type_detection[attack_type]['total']
        detected = attack_type_detection[attack_type]['detected']
        attack_type_detection[attack_type]['rate'] = detected / total if total > 0 else 0
    
    # Compile results
    results = {
        'total_events': total_events,
        'attack_events': total_attack_events,
        'normal_events': len(normal_events),
        'total_alerts': len(alerts),
        'true_positives': detected_attack_events,  # Unique attack events detected
        'false_positives': false_positive_count,
        'false_negatives': missed_attack_events,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'rule_performance': dict(rule_performance),
        'attack_type_detection': dict(attack_type_detection),
        'processing_time': datetime.now().isoformat()
    }
    
    return alerts, results

def print_results(results, detailed=False):
    """Print evaluation results in a readable format"""
    print("\n" + "="*70)
    print(" RULE-BASED DETECTION EVALUATION RESULTS")
    print("="*70)
    
    print(f"\n OVERALL METRICS")
    print("-"*40)
    print(f"Total Events           : {results['total_events']:,}")
    print(f"Attack Events          : {results['attack_events']:,} ({results['attack_events']/results['total_events']*100:.1f}%)")
    print(f"Normal Events          : {results['normal_events']:,} ({results['normal_events']/results['total_events']*100:.1f}%)")
    print(f"Total Alerts           : {results['total_alerts']:,}")
    print(f"True Positives (TP)    : {results['true_positives']:,} (detected attack events)")
    print(f"False Positives (FP)   : {results['false_positives']:,} (alerts on normal events)")
    print(f"False Negatives (FN)   : {results['false_negatives']:,} (missed attacks)")
    print(f"Precision              : {results['precision']:.3f} ({results['precision']*100:.1f}%)")
    print(f"Recall                 : {results['recall']:.3f} ({results['recall']*100:.1f}%)")
    print(f"F1 Score               : {results['f1_score']:.3f}")
    
    # Detection rate
    if results['attack_events'] > 0:
        detection_rate = results['true_positives'] / results['attack_events']
        print(f"Detection Rate         : {detection_rate:.3f} ({detection_rate*100:.1f}%)")
    
    # False positive rate
    if results['normal_events'] > 0:
        fpr = results['false_positives'] / results['normal_events']
        print(f"False Positive Rate    : {fpr:.5f} ({fpr*100:.3f}%)")
    
    print(f"\n DETECTION BY ATTACK TYPE")
    print("-"*40)
    
    for attack_type, stats in sorted(results['attack_type_detection'].items()):
        if stats['total'] > 0:
            rate = stats['detected'] / stats['total']
            print(f"{attack_type:25s}: {stats['detected']:3d}/{stats['total']:3d} = {rate:.3f} ({rate*100:.1f}%)")
    
    print(f"\n RULE PERFORMANCE BREAKDOWN")
    print("-"*40)
    
    for rule_id, stats in sorted(results['rule_performance'].items()):
        precision = stats['precision']
        print(f"{rule_id:25s}:")
        print(f"  Alerts: {stats['total_alerts']:3d} (TP: {stats['attack_alerts']:3d}, FP: {stats['false_positives']:3d})")
        print(f"  Detected Events: {stats['detected_events_count']:3d}")
        print(f"  Precision: {precision:.3f} ({precision*100:.1f}%)")
    
    # Summary
    print(f"\n SUMMARY")
    print("-"*40)
    
    if results['precision'] >= 0.95 and results['recall'] >= 0.90:
        print(" EXCELLENT: High precision and recall!")
    elif results['precision'] >= 0.90 and results['recall'] >= 0.80:
        print(" GOOD: Good balance of precision and recall")
    elif results['precision'] >= 0.80 and results['recall'] >= 0.70:
        print("  FAIR: Acceptable performance")
    else:
        print(" NEEDS IMPROVEMENT: Precision or recall too low")
    
    if results['false_positives'] > 100:
        print("  Warning: High number of false positives")
    
    if results['false_negatives'] > results['attack_events'] * 0.3:
        print("  Warning: Missing too many attacks")

def save_report(alerts, results, output_dir="reports"):
    """Save evaluation report to files"""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save detailed results
    report = {
        'evaluation_time': results['processing_time'],
        'summary': {
            'total_events': results['total_events'],
            'attack_events': results['attack_events'],
            'precision': results['precision'],
            'recall': results['recall'],
            'f1_score': results['f1_score']
        },
        'detailed_results': results,
        'alerts_sample': alerts[:100]  # First 100 alerts
    }
    
    report_file = os.path.join(output_dir, f"rule_evaluation_{timestamp}.json")
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)
    
    # Save alerts to CSV-like format
    alerts_file = os.path.join(output_dir, f"alerts_{timestamp}.ndjson")
    with open(alerts_file, 'w', encoding='utf-8') as f:
        for alert in alerts:
            f.write(json.dumps(alert) + '\n')
    
    print(f"\n Reports saved:")
    print(f"  - {report_file}")
    print(f"  - {alerts_file}")
    
    return report_file, alerts_file

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate rule-based detection system with new implementation"
    )
    parser.add_argument(
        "dataset",
        help="Path to NDJSON dataset file"
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Maximum number of events to process"
    )
    parser.add_argument(
        "--no-cooldown",
        action='store_true',
        help="Disable rule cooldown periods"
    )
    parser.add_argument(
        "--verbose",
        action='store_true',
        help="Show detailed progress"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save reports"
    )
    parser.add_argument(
        "--rules-dir",
        default=None,
        help="Custom rules directory (default: detection_system/rule_based/rules)"
    )
    
    args = parser.parse_args()
    
    # Validate dataset file
    if not os.path.exists(args.dataset):
        print(f" Dataset not found: {args.dataset}")
        sys.exit(1)
    
    print("="*70)
    print(" EAGLEPRO RULE-BASED DETECTION EVALUATION")
    print("="*70)
    print(f"Dataset: {args.dataset}")
    print(f"Max events: {args.max_events or 'All'}")
    print(f"No cooldown: {args.no_cooldown}")
    print(f"Verbose: {args.verbose}")
    print(f"Output dir: {args.output_dir}")
    print()
    
    # Load events
    print(f" Loading events from {args.dataset}...")
    events = load_ndjson(args.dataset, max_events=args.max_events)
    
    if not events:
        print(" No events loaded. Exiting.")
        sys.exit(1)
    
    # Set custom rules directory if specified
    rule_loader_args = {}
    if args.rules_dir:
        rule_loader_args['rules_dir'] = args.rules_dir
        print(f" Using custom rules directory: {args.rules_dir}")
    
    # Evaluate
    try:
        alerts, results = evaluate_events(
            events,
            no_cooldown=args.no_cooldown,
            verbose=args.verbose
        )
        
        # Print results
        print_results(results, detailed=args.verbose)
        
        # Save reports
        save_report(alerts, results, args.output_dir)
        
        # Quick recommendations
        print("\n RECOMMENDATIONS:")
        print("-"*40)
        
        if results['false_positives'] > 0:
            print(f"1. Consider adjusting thresholds for rules with high FP:")
            for rule_id, stats in results['rule_performance'].items():
                if stats['false_positives'] > 0:
                    print(f"   - {rule_id}: {stats['false_positives']} FPs")
        
        if results['false_negatives'] > 0:
            print(f"2. {results['false_negatives']} attacks were missed. Consider:")
            print(f"   - Adding new rules for missed attack types")
            print(f"   - Lowering thresholds for existing rules")
        
        if results['precision'] < 0.90:
            print(f"3. Precision ({results['precision']:.1%}) is low. Too many false positives.")
        
        if results['recall'] < 0.80:
            print(f"4. Recall ({results['recall']:.1%}) is low. Missing too many attacks.")
        
        print("\n Evaluation complete!")
        
    except Exception as e:
        print(f" Evaluation failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()