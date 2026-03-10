from __future__ import annotations

"""
Offline feature builder for brute-force detection & attack classification.

This module converts EaglePro NDJSON event logs into a feature matrix (Parquet)
that matches the feature schema defined in `ml.features.ALL_FEATURES`.

Design constraints:
- Each input event produces exactly one feature row (event-level snapshot).
- Sliding-window metrics only use **past** events (no future leakage).
- Features are computed for IP, user, and IP-user scopes as described in
  the ML design plan, plus time-based context features.
- Labels:
  - `is_attack_label`: 1 if event['is_attack'] is truthy, else 0.
  - `attack_type_label`: event['attack_type'] or 'benign'.
"""

import json
import math
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from .features import EntityScope, get_feature_names


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(ts: Any) -> datetime:
    """Parse timestamps from strings or datetime objects, similar to rule-based code."""
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str):
        try:
            if ts.endswith("Z"):
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return datetime.fromisoformat(ts)
        except Exception:
            # Best-effort fallback
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(ts, fmt)
                except Exception:
                    continue
    # Last resort: now()
    return datetime.now()


def _get_hour_fraction(dt: datetime) -> float:
    """Return hour-of-day as fractional value in [0, 24)."""
    h = dt.hour
    m = dt.minute
    s = dt.second
    return h + m / 60.0 + s / 3600.0


def _is_business_hours(dt: datetime) -> int:
    """
    Business hours flag.

    Policy:
    - Monday–Friday (weekday 0–4)
    - 08:00 <= local time < 18:00
    """
    if dt.weekday() >= 5:
        return 0
    return int(8 <= dt.hour < 18)


# ---------------------------------------------------------------------------
# Sliding window state containers
# ---------------------------------------------------------------------------

@dataclass
class IpState:
    """
    State for IP-based features.

    All deques store ONLY events strictly before the "current" event being
    evaluated; current event is appended **after** computing features so that
    no future information is leaked.
    """

    # For ip_attempts_1s / 5s / 30s and ip_failed_rate_30s
    win30_events: Deque[Tuple[datetime, bool, str]]  # (ts, success, username)
    # For ip_unique_users_5m
    win5m_users: Deque[Tuple[datetime, str]]  # (ts, username)
    # For ip_avg_interarrival_30s
    win30_timestamps: Deque[datetime]

    def __init__(self) -> None:
        self.win30_events = deque()
        self.win5m_users = deque()
        self.win30_timestamps = deque()


@dataclass
class UserState:
    """State for user-based features."""

    # For user_failed_5m
    win5m_failed: Deque[datetime]
    # For user_unique_ips_5m / 1h
    win1h_ips: Deque[Tuple[datetime, str]]  # (ts, ip)
    # For user_success_streak
    success_streak: int

    def __init__(self) -> None:
        self.win5m_failed = deque()
        self.win1h_ips = deque()
        self.success_streak = 0


@dataclass
class PairState:
    """State for IP-user pair features."""

    win5m_events: Deque[Tuple[datetime, bool]]  # (ts, success)

    def __init__(self) -> None:
        self.win5m_events = deque()


# ---------------------------------------------------------------------------
# Core feature builder
# ---------------------------------------------------------------------------

def build_features_from_events(events: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    """
    Build a feature DataFrame from an iterable of event dicts.

    Each event is expected to follow the schema produced by `SimpleDataGenerator`,
    containing at least:
    - 'timestamp' (ISO string)
    - 'username'
    - 'src_ip'
    - 'success' (bool)
    - 'is_attack' (bool)
    - 'attack_type' (str or None)

    Returns:
        pandas.DataFrame with columns:
        - 'timestamp' (datetime64[ns])
        - 'entity_type' (str, currently always 'ip' for primary entity key)
        - 'entity_value' (str, src_ip)
        - Features in the same order as `get_feature_names()`
        - 'is_attack_label' (int 0/1)
        - 'attack_type_label' (str)
    """
    # Normalize to list so we can sort stably by time
    event_list: List[Dict[str, Any]] = list(events)
    if not event_list:
        # Empty dataset – return an empty frame with the correct columns
        base_cols = ["timestamp", "entity_type", "entity_value"]
        label_cols = ["is_attack_label", "attack_type_label"]
        feature_cols = get_feature_names()
        return pd.DataFrame(columns=base_cols + feature_cols + label_cols)

    # Sort events by timestamp
    for e in event_list:
        e["_parsed_ts"] = _parse_timestamp(e.get("timestamp"))
    event_list.sort(key=lambda e: e["_parsed_ts"])

    # Per-entity state
    ip_states: Dict[str, IpState] = defaultdict(IpState)
    user_states: Dict[str, UserState] = defaultdict(UserState)
    pair_states: Dict[str, PairState] = defaultdict(PairState)

    rows: List[Dict[str, Any]] = []

    feature_names = get_feature_names()
    feature_set = set(feature_names)

    for idx, event in enumerate(event_list):
        ts: datetime = event["_parsed_ts"]
        ip = event.get("src_ip") or "unknown_ip"
        user = event.get("username") or "unknown_user"
        success = bool(event.get("success"))

        ip_state = ip_states[ip]
        user_state = user_states[user]
        pair_key = f"{ip}:{user}"
        pair_state = pair_states[pair_key]

        # ------------------------------------------------------------------
        # Maintain / cleanup windows BEFORE computing features
        # (so that they only contain strictly past events)
        # ------------------------------------------------------------------

        # IP 30s window (events)
        cutoff_30s = ts - timedelta(seconds=30)
        while ip_state.win30_events and ip_state.win30_events[0][0] < cutoff_30s:
            ip_state.win30_events.popleft()
        while ip_state.win30_timestamps and ip_state.win30_timestamps[0] < cutoff_30s:
            ip_state.win30_timestamps.popleft()

        # IP 5m window (unique users)
        cutoff_5m = ts - timedelta(minutes=5)
        while ip_state.win5m_users and ip_state.win5m_users[0][0] < cutoff_5m:
            ip_state.win5m_users.popleft()

        # User 5m failed window
        while user_state.win5m_failed and user_state.win5m_failed[0] < cutoff_5m:
            user_state.win5m_failed.popleft()

        # User 1h IPs window
        cutoff_1h = ts - timedelta(hours=1)
        while user_state.win1h_ips and user_state.win1h_ips[0][0] < cutoff_1h:
            user_state.win1h_ips.popleft()

        # Pair 5m window
        while pair_state.win5m_events and pair_state.win5m_events[0][0] < cutoff_5m:
            pair_state.win5m_events.popleft()

        # ------------------------------------------------------------------
        # Compute features from cleaned state (no current event yet)
        # ------------------------------------------------------------------
        features: Dict[str, float] = {}

        # --- IP-based features --------------------------------------------
        if "ip_attempts_1s" in feature_set or "ip_attempts_5s" in feature_set or "ip_attempts_30s" in feature_set:
            # Counters over the 30s deque, restricted by age
            attempts_1s = 0
            attempts_5s = 0
            attempts_30s = 0
            failed_30s = 0

            for ev_ts, ev_success, ev_user in ip_state.win30_events:
                age = (ts - ev_ts).total_seconds()
                if age <= 1.0:
                    attempts_1s += 1
                if age <= 5.0:
                    attempts_5s += 1
                if age <= 30.0:
                    attempts_30s += 1
                    if not ev_success:
                        failed_30s += 1

            if "ip_attempts_1s" in feature_set:
                features["ip_attempts_1s"] = float(attempts_1s)
            if "ip_attempts_5s" in feature_set:
                features["ip_attempts_5s"] = float(attempts_5s)
            if "ip_attempts_30s" in feature_set:
                features["ip_attempts_30s"] = float(attempts_30s)
            if "ip_failed_rate_30s" in feature_set:
                if attempts_30s > 0:
                    features["ip_failed_rate_30s"] = failed_30s / float(attempts_30s)
                else:
                    features["ip_failed_rate_30s"] = 0.0

        if "ip_unique_users_5m" in feature_set:
            unique_users_5m = {u for _, u in ip_state.win5m_users}
            features["ip_unique_users_5m"] = float(len(unique_users_5m))

        if "ip_avg_interarrival_30s" in feature_set:
            ts_list = list(ip_state.win30_timestamps)
            if len(ts_list) >= 2:
                deltas = [
                    (ts_list[i] - ts_list[i - 1]).total_seconds()
                    for i in range(1, len(ts_list))
                ]
                avg_delta = float(sum(deltas) / len(deltas)) if deltas else 0.0
                features["ip_avg_interarrival_30s"] = avg_delta
            else:
                features["ip_avg_interarrival_30s"] = 0.0

        # --- User-based features ------------------------------------------
        if "user_failed_5m" in feature_set:
            features["user_failed_5m"] = float(len(user_state.win5m_failed))

        if "user_unique_ips_5m" in feature_set or "user_unique_ips_1h" in feature_set:
            # Construct sets from 1h deque, then filter by age
            ips_5m = set()
            ips_1h = set()
            for ev_ts, ev_ip in user_state.win1h_ips:
                age = (ts - ev_ts).total_seconds()
                if age <= 5 * 60:
                    ips_5m.add(ev_ip)
                if age <= 60 * 60:
                    ips_1h.add(ev_ip)

            if "user_unique_ips_5m" in feature_set:
                features["user_unique_ips_5m"] = float(len(ips_5m))
            if "user_unique_ips_1h" in feature_set:
                features["user_unique_ips_1h"] = float(len(ips_1h))

        if "user_success_streak" in feature_set:
            # Streak is maintained as "streak before current event"
            features["user_success_streak"] = float(user_state.success_streak)

        # --- Pair-based features ------------------------------------------
        if "pair_attempts_5m" in feature_set or "pair_success_rate_5m" in feature_set:
            total_pair = len(pair_state.win5m_events)
            success_pair = sum(1 for _, s in pair_state.win5m_events if s)

            if "pair_attempts_5m" in feature_set:
                features["pair_attempts_5m"] = float(total_pair)
            if "pair_success_rate_5m" in feature_set:
                if total_pair > 0:
                    features["pair_success_rate_5m"] = success_pair / float(total_pair)
                else:
                    features["pair_success_rate_5m"] = 0.0

        # --- Time-based features ------------------------------------------
        hour_frac = _get_hour_fraction(ts)
        angle = 2.0 * math.pi * hour_frac / 24.0

        if "hour_sin" in feature_set:
            features["hour_sin"] = math.sin(angle)
        if "hour_cos" in feature_set:
            features["hour_cos"] = math.cos(angle)
        if "is_business_hours" in feature_set:
            features["is_business_hours"] = float(_is_business_hours(ts))

        # Fill any missing features with 0.0 (model pipeline can standardize later)
        for fname in feature_names:
            if fname not in features:
                features[fname] = 0.0

        # ------------------------------------------------------------------
        # Labels
        # ------------------------------------------------------------------
        is_attack = bool(event.get("is_attack", False))
        attack_type = event.get("attack_type") or "benign"

        row: Dict[str, Any] = {
            "timestamp": ts,
            # For now we attach the logical "entity" to IP; this is primarily
            # for debugging / grouping and does not affect model inputs.
            "entity_type": EntityScope.IP.value,
            "entity_value": ip,
            "is_attack_label": int(is_attack),
            "attack_type_label": attack_type,
        }
        row.update(features)
        rows.append(row)

        # ------------------------------------------------------------------
        # Update state with current event (for future events)
        # ------------------------------------------------------------------
        ip_state.win30_events.append((ts, success, user))
        ip_state.win5m_users.append((ts, user))
        ip_state.win30_timestamps.append(ts)

        if not success:
            user_state.win5m_failed.append(ts)
        user_state.win1h_ips.append((ts, ip))

        # Update success streak AFTER using the previous value
        if success:
            user_state.success_streak += 1
        else:
            user_state.success_streak = 0

        pair_state.win5m_events.append((ts, success))

    # Build DataFrame in stable column order
    base_cols = ["timestamp", "entity_type", "entity_value"]
    label_cols = ["is_attack_label", "attack_type_label"]

    df = pd.DataFrame(rows)
    # Ensure column order and existence
    for col in base_cols + feature_names + label_cols:
        if col not in df.columns:
            df[col] = np.nan
    df = df[base_cols + feature_names + label_cols]

    return df


def build_dataset_from_ndjson(
    path: str,
    output_parquet_path: Optional[str] = None,
) -> pd.DataFrame:
    """
    Convenience wrapper: load NDJSON from `path`, build features, and
    optionally write them to a Parquet file.

    Args:
        path: Path to `.ndjson` file.
        output_parquet_path: If provided, the resulting DataFrame is written
            to this location with `DataFrame.to_parquet(index=False)`.

    Returns:
        pandas.DataFrame with the same structure as `build_features_from_events`.
    """
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip bad lines but continue
                continue

    df = build_features_from_events(events)

    if output_parquet_path:
        os.makedirs(os.path.dirname(output_parquet_path), exist_ok=True)
        df.to_parquet(output_parquet_path, index=False)

    return df


__all__ = [
    "build_features_from_events",
    "build_dataset_from_ndjson",
]

