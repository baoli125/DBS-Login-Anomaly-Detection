from __future__ import annotations

"""
Offline đặc trưng builder for brute-force phát hiện & tấn công classification.

Mô-đun này converts EaglePro NDJSON sự kiện logs into a đặc trưng matrix (Parquet)
that matches the đặc trưng schema defined in `ml.đặc trưng.ALL_FEATURES`.

Design constraints:
- Each input sự kiện produces exactly one đặc trưng row (sự kiện-level snapshot).
- Sliding-window metrics only use **past** events (no future leakage).
- Đặc trưng are computed for IP, user, and IP-user scopes as described in
  the ML design plan, plus time-based context đặc trưng.
- Labels:
  - `is_attack_label`: 1 if sự kiện['is_attack'] is truthy, else 0.
  - `attack_type_label`: sự kiện['attack_type'] or 'benign'.
"""

import json
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from ml.core.metrics import (
    compute_avg_interarrival_seconds,
    cyclic_hour_features,
    is_business_hours,
    rate,
)

from .features import EntityScope, get_feature_names


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(ts: Any) -> datetime:
    """Phân tích timestamps from strings or datetime objects, similar to dựa trên quy tắc code."""
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


# ---------------------------------------------------------------------------
# Sliding window trạng thái containers
# ---------------------------------------------------------------------------

@dataclass
class IpState:
    """
    Trạng thái for IP-based đặc trưng.

    All deques store ONLY events strictly before the "current" sự kiện being
    evaluated; current sự kiện is appended **after** computing đặc trưng so that
    no future information is leaked.
    """

    # For ip_attempts_1s / 5s / 30s and ip_failed_rate_30s
    win30_events: Deque[Tuple[datetime, bool, str]]  # (ts, success, username)
    # For ip_unique_users_5m
    win5m_users: Deque[Tuple[datetime, str]]  # (ts, username)
    # For ip_avg_interarrival_30s
    win30_timestamps: Deque[datetime]
    # For ip_unique_geos_5m
    win5m_geos: Deque[Tuple[datetime, str]]  # (ts, geo)
    # For ip_unique_devices_5m
    win5m_devices: Deque[Tuple[datetime, str]]  # (ts, device_fingerprint)
    # For ip_avg_request_duration_30s
    win30_durations: Deque[Tuple[datetime, float]]  # (ts, request_duration_ms)
    # For ip_failed_attempts_5m
    win5m_failed: Deque[datetime]
    # For ip_velocity_1m
    win1m_timestamps: Deque[datetime]
    # For ip_failed_streak
    failed_streak: int
    # For ip_unique_users_1m
    win1m_users: Deque[Tuple[datetime, str]]  # (ts, username)
    # For ip_min_interarrival_30s and ip_std_interarrival_30s
    win30_interarrivals: Deque[float]  # interarrival times in seconds

    def __init__(self) -> None:
        self.win30_events = deque()
        self.win5m_users = deque()
        self.win30_timestamps = deque()
        self.win5m_geos = deque()
        self.win5m_devices = deque()
        self.win30_durations = deque()
        self.win5m_failed = deque()
        self.win1m_timestamps = deque()
        self.failed_streak = 0
        self.win1m_users = deque()
        self.win30_interarrivals = deque()
        self.win10s_events = deque()


@dataclass
class UserState:
    """Trạng thái for user-based đặc trưng."""

    # For user_failed_5m
    win5m_failed: Deque[datetime]
    # For user_unique_ips_5m / 1h
    win1h_ips: Deque[Tuple[datetime, str]]  # (ts, ip)
    # For user_success_streak
    success_streak: int
    # For user_unique_geos_5m
    win5m_geos: Deque[Tuple[datetime, str]]  # (ts, geo)
    # For user_unique_devices_5m
    win5m_devices: Deque[Tuple[datetime, str]]  # (ts, device_fingerprint)
    # For user_failed_rate_5m and user_attempts_velocity_5m
    win5m_events: Deque[Tuple[datetime, bool]]  # (ts, success)
    # For user_failed_streak
    failed_streak: int
    # For user_unique_ips_1m
    win1m_ips: Deque[Tuple[datetime, str]]  # (ts, ip)
    # For user_min_interarrival_5m
    win5m_interarrivals: Deque[float]  # interarrival times in seconds

    def __init__(self) -> None:
        self.win5m_failed = deque()
        self.win1h_ips = deque()
        self.success_streak = 0
        self.win5m_geos = deque()
        self.win5m_devices = deque()
        self.win5m_events = deque()
        self.failed_streak = 0
        self.win1m_ips = deque()
        self.win5m_interarrivals = deque()


@dataclass
class PairState:
    """Trạng thái for IP-user pair đặc trưng."""

    win5m_events: Deque[Tuple[datetime, bool]]  # (ts, success)

    def __init__(self) -> None:
        self.win5m_events = deque()


# ---------------------------------------------------------------------------
# Core đặc trưng builder
# ---------------------------------------------------------------------------

def build_features_from_events(events: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    """
    Xây dựng a đặc trưng DataFrame from an iterable of sự kiện dicts.

    Each sự kiện is expected to follow the schema produced by `SimpleDataGenerator`,
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
        - Đặc trưng in the same order as `get_feature_names()`
        - 'is_attack_label' (int 0/1)
        - 'attack_type_label' (str)
    """
    # Normalize to list so we can sort stably by time
    event_list: List[Dict[str, Any]] = list(events)
    if not event_list:
        # Empty tập dữ liệu – trả về an empty frame with the correct columns
        base_cols = ["timestamp", "entity_type", "entity_value"]
        label_cols = ["is_attack_label", "attack_type_label"]
        feature_cols = get_feature_names()
        return pd.DataFrame(columns=base_cols + feature_cols + label_cols)

    # Sort events by timestamp
    for e in event_list:
        e["_parsed_ts"] = _parse_timestamp(e.get("timestamp"))
    event_list.sort(key=lambda e: e["_parsed_ts"])

    # Per-entity trạng thái
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
        geo = event.get("geo") or "unknown_geo"
        device = event.get("device_fingerprint") or "unknown_device"
        duration = float(event.get("request_duration_ms", 0.0))

        ip_state = ip_states[ip]
        user_state = user_states[user]
        pair_key = f"{ip}:{user}"
        pair_state = pair_states[pair_key]

        # ------------------------------------------------------------------
        # Maintain / dọn dẹp windows BEFORE computing đặc trưng
        # (so that they only contain strictly past events)
        # ------------------------------------------------------------------

        # IP 30s window (events, timestamps, durations)
        cutoff_30s = ts - timedelta(seconds=30)
        cutoff_10s = ts - timedelta(seconds=10)
        while ip_state.win30_events and ip_state.win30_events[0][0] < cutoff_30s:
            ip_state.win30_events.popleft()
        while ip_state.win30_timestamps and ip_state.win30_timestamps[0] < cutoff_30s:
            ip_state.win30_timestamps.popleft()
        while ip_state.win30_durations and ip_state.win30_durations[0][0] < cutoff_30s:
            ip_state.win30_durations.popleft()
        while ip_state.win10s_events and ip_state.win10s_events[0][0] < cutoff_10s:
            ip_state.win10s_events.popleft()

        # Rebuild interarrivals after dọn dẹp
        ip_state.win30_interarrivals.clear()
        timestamps = list(ip_state.win30_timestamps)
        for i in range(1, len(timestamps)):
            interarrival = (timestamps[i] - timestamps[i-1]).total_seconds()
            ip_state.win30_interarrivals.append(interarrival)

        # IP 5m window (unique users, geos, devices, failed)
        cutoff_5m = ts - timedelta(minutes=5)
        while ip_state.win5m_users and ip_state.win5m_users[0][0] < cutoff_5m:
            ip_state.win5m_users.popleft()
        while ip_state.win5m_geos and ip_state.win5m_geos[0][0] < cutoff_5m:
            ip_state.win5m_geos.popleft()
        while ip_state.win5m_devices and ip_state.win5m_devices[0][0] < cutoff_5m:
            ip_state.win5m_devices.popleft()
        while ip_state.win5m_failed and ip_state.win5m_failed[0] < cutoff_5m:
            ip_state.win5m_failed.popleft()

        # IP 1m window (velocity, unique users)
        cutoff_1m = ts - timedelta(minutes=1)
        while ip_state.win1m_timestamps and ip_state.win1m_timestamps[0] < cutoff_1m:
            ip_state.win1m_timestamps.popleft()
        while ip_state.win1m_users and ip_state.win1m_users[0][0] < cutoff_1m:
            ip_state.win1m_users.popleft()

        # User 5m window (failed, geos, devices, events)
        while user_state.win5m_failed and user_state.win5m_failed[0] < cutoff_5m:
            user_state.win5m_failed.popleft()
        while user_state.win5m_geos and user_state.win5m_geos[0][0] < cutoff_5m:
            user_state.win5m_geos.popleft()
        while user_state.win5m_devices and user_state.win5m_devices[0][0] < cutoff_5m:
            user_state.win5m_devices.popleft()
        while user_state.win5m_events and user_state.win5m_events[0][0] < cutoff_5m:
            user_state.win5m_events.popleft()

        # Rebuild interarrivals after dọn dẹp
        user_state.win5m_interarrivals.clear()
        events_ts = [t for t, _ in user_state.win5m_events]
        for i in range(1, len(events_ts)):
            interarrival = (events_ts[i] - events_ts[i-1]).total_seconds()
            user_state.win5m_interarrivals.append(interarrival)

        # User 1h IPs window
        cutoff_1h = ts - timedelta(hours=1)
        while user_state.win1h_ips and user_state.win1h_ips[0][0] < cutoff_1h:
            user_state.win1h_ips.popleft()
        while user_state.win1m_ips and user_state.win1m_ips[0][0] < cutoff_1m:
            user_state.win1m_ips.popleft()

        # Pair 5m window
        while pair_state.win5m_events and pair_state.win5m_events[0][0] < cutoff_5m:
            pair_state.win5m_events.popleft()

        # ------------------------------------------------------------------
        # Compute đặc trưng from cleaned trạng thái (no current sự kiện yet)
        # ------------------------------------------------------------------
        features: Dict[str, float] = {}

        # --- IP-based đặc trưng --------------------------------------------
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
                features["ip_failed_rate_30s"] = rate(failed_30s, attempts_30s)

        if "ip_unique_users_5m" in feature_set:
            unique_users_5m = {u for _, u in ip_state.win5m_users}
            features["ip_unique_users_5m"] = float(len(unique_users_5m))

        if "ip_avg_interarrival_30s" in feature_set:
            ts_list = list(ip_state.win30_timestamps)
            features["ip_avg_interarrival_30s"] = compute_avg_interarrival_seconds(ts_list)

        if "ip_unique_geos_5m" in feature_set:
            unique_geos_5m = {g for _, g in ip_state.win5m_geos}
            features["ip_unique_geos_5m"] = float(len(unique_geos_5m))

        if "ip_unique_devices_5m" in feature_set:
            unique_devices_5m = {d for _, d in ip_state.win5m_devices}
            features["ip_unique_devices_5m"] = float(len(unique_devices_5m))

        if "ip_avg_request_duration_30s" in feature_set:
            durations = [d for _, d in ip_state.win30_durations]
            features["ip_avg_request_duration_30s"] = float(np.mean(durations)) if durations else 0.0

        if "ip_failed_attempts_5m" in feature_set:
            features["ip_failed_attempts_5m"] = float(len(ip_state.win5m_failed))

        if "ip_velocity_1m" in feature_set:
            n_attempts = len(ip_state.win1m_timestamps)
            time_span = 60.0  # 1 minute in seconds
            features["ip_velocity_1m"] = float(n_attempts / time_span) if time_span > 0 else 0.0

        if "ip_failed_streak" in feature_set:
            features["ip_failed_streak"] = float(ip_state.failed_streak)

        if "ip_unique_users_1m" in feature_set:
            unique_users_1m = {u for _, u in ip_state.win1m_users}
            features["ip_unique_users_1m"] = float(len(unique_users_1m))

        if "ip_min_interarrival_30s" in feature_set or "ip_std_interarrival_30s" in feature_set:
            interarrivals = list(ip_state.win30_interarrivals)
            if len(interarrivals) >= 2:
                min_inter = min(interarrivals)
                std_inter = np.std(interarrivals)
            else:
                min_inter = 0.0
                std_inter = 0.0
            if "ip_min_interarrival_30s" in feature_set:
                features["ip_min_interarrival_30s"] = min_inter
            if "ip_std_interarrival_30s" in feature_set:
                features["ip_std_interarrival_30s"] = std_inter

        if "ip_attempts_10s" in feature_set:
            attempts_10s = sum(1 for ev_ts, _, _ in ip_state.win30_events if (ts - ev_ts).total_seconds() <= 10.0)
            features["ip_attempts_10s"] = float(attempts_10s)

        if "ip_failed_velocity_30s" in feature_set:
            failed_30s = sum(1 for _, ev_success, _ in ip_state.win30_events if not ev_success)
            time_span = 30.0
            features["ip_failed_velocity_30s"] = float(failed_30s / time_span) if time_span > 0 else 0.0

        # --- User-based đặc trưng ------------------------------------------
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
            # Streak is maintained as "streak before current sự kiện"
            features["user_success_streak"] = float(user_state.success_streak)

        if "user_unique_geos_5m" in feature_set:
            unique_geos_5m = {g for _, g in user_state.win5m_geos}
            features["user_unique_geos_5m"] = float(len(unique_geos_5m))

        if "user_unique_devices_5m" in feature_set:
            unique_devices_5m = {d for _, d in user_state.win5m_devices}
            features["user_unique_devices_5m"] = float(len(unique_devices_5m))

        if "user_failed_rate_5m" in feature_set:
            total_user = len(user_state.win5m_events)
            failed_user = sum(1 for _, s in user_state.win5m_events if not s)
            features["user_failed_rate_5m"] = rate(failed_user, total_user)

        if "user_attempts_velocity_5m" in feature_set:
            n_attempts = len(user_state.win5m_events)
            time_span = 300.0  # 5 minutes in seconds
            features["user_attempts_velocity_5m"] = float(n_attempts / time_span) if time_span > 0 else 0.0

        if "user_failed_streak" in feature_set:
            features["user_failed_streak"] = float(user_state.failed_streak)

        if "user_unique_ips_1m" in feature_set:
            unique_ips_1m = {ip for _, ip in user_state.win1m_ips}
            features["user_unique_ips_1m"] = float(len(unique_ips_1m))

        if "user_min_interarrival_5m" in feature_set:
            interarrivals = list(user_state.win5m_interarrivals)
            if len(interarrivals) >= 2:
                min_inter = min(interarrivals)
            else:
                min_inter = 0.0
            features["user_min_interarrival_5m"] = min_inter

        # --- Pair-based đặc trưng ------------------------------------------
        if "pair_attempts_5m" in feature_set or "pair_success_rate_5m" in feature_set:
            total_pair = len(pair_state.win5m_events)
            success_pair = sum(1 for _, s in pair_state.win5m_events if s)

            if "pair_attempts_5m" in feature_set:
                features["pair_attempts_5m"] = float(total_pair)
            if "pair_success_rate_5m" in feature_set:
                features["pair_success_rate_5m"] = rate(success_pair, total_pair)

        # --- Time-based đặc trưng ------------------------------------------
        # Use cyclic encoding for hour of day to avoid a discontinuity at midnight.
        if "hour_sin" in feature_set or "hour_cos" in feature_set:
            hour_sin, hour_cos = cyclic_hour_features(ts)
            if "hour_sin" in feature_set:
                features["hour_sin"] = hour_sin
            if "hour_cos" in feature_set:
                features["hour_cos"] = hour_cos

        if "is_business_hours" in feature_set:
            features["is_business_hours"] = float(is_business_hours(ts))

        # Fill any missing đặc trưng with 0.0 (model pipeline can standardize later)
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
        # Update trạng thái with current sự kiện (for future events)
        # ------------------------------------------------------------------
        # Compute interarrivals before appending
        if ip_state.win30_timestamps:
            last_ts = ip_state.win30_timestamps[-1]
            interarrival = (ts - last_ts).total_seconds()
            ip_state.win30_interarrivals.append(interarrival)

        if user_state.win5m_events:
            last_ts = user_state.win5m_events[-1][0]
            interarrival = (ts - last_ts).total_seconds()
            user_state.win5m_interarrivals.append(interarrival)

        ip_state.win30_events.append((ts, success, user))
        ip_state.win5m_users.append((ts, user))
        ip_state.win30_timestamps.append(ts)
        ip_state.win5m_geos.append((ts, geo))
        ip_state.win5m_devices.append((ts, device))
        ip_state.win30_durations.append((ts, duration))
        ip_state.win1m_timestamps.append(ts)
        ip_state.win1m_users.append((ts, user))
        ip_state.win10s_events.append((ts, success))
        if not success:
            ip_state.win5m_failed.append(ts)

        if not success:
            user_state.win5m_failed.append(ts)
        user_state.win1h_ips.append((ts, ip))
        user_state.win1m_ips.append((ts, ip))
        user_state.win5m_geos.append((ts, geo))
        user_state.win5m_devices.append((ts, device))
        user_state.win5m_events.append((ts, success))

        # Update streaks
        if success:
            user_state.success_streak += 1
            user_state.failed_streak = 0
            ip_state.failed_streak = 0
        else:
            user_state.success_streak = 0
            user_state.failed_streak += 1
            ip_state.failed_streak += 1

        pair_state.win5m_events.append((ts, success))

    # Xây dựng DataFrame in stable column order
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
    Convenience wrapper: tải NDJSON from `path`, xây dựng đặc trưng, and
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

