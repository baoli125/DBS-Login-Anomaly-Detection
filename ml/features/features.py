from __future__ import annotations

"""
Định nghĩa trung tâm của các đặc trưng ML dùng cho phát hiện brute-force và phân loại tấn công.

Mô-đun này CỐ ĐỊNH danh sách các đặc trưng (tên, phạm vi, cửa sổ, kiểu) sao cho:
- Offline đặc trưng builders, training scripts, and online inference can all share one schema.
- Both binary phát hiện (`is_attack`) and multi-class classification (`attack_type`) use
  the same đặc trưng vector.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Literal, Optional, Sequence


class EntityScope(str, Enum):
    """Logical scope for which a đặc trưng is computed."""

    IP = "ip"
    USER = "user"
    PAIR = "pair"  # (IP, username)
    GLOBAL = "global"  # purely time-based / contextual features


NumericDType = Literal["float32", "float64", "int32", "int64"]


@dataclass(frozen=True)
class FeatureSpec:
    """
    Specification of a single đặc trưng in the ML tập dữ liệu.

    Attributes:
        name: Stable column name in đặc trưng DataFrame / model input.
        scope: Which entity the đặc trưng is attached to (ip/user/pair/global).
        window: Sliding time window length as a string (e.g. '1s', '5s', '30s', '5m', '1h'),
                or None for window-less / purely contextual đặc trưng.
        dtype: Numeric dtype hint for downstream processing.
        description: Human-readable explanation of how the đặc trưng is computed.
    """

    name: str
    scope: EntityScope
    window: Optional[str]
    dtype: NumericDType
    description: str


# === IP-based đặc trưng ======================================================

IP_FEATURES: Sequence[FeatureSpec] = [
    FeatureSpec(
        name="ip_attempts_1s",
        scope=EntityScope.IP,
        window="1s",
        dtype="int32",
        description="Number of login attempts from this src_ip in the last 1 second "
        "(excluding the current event).",
    ),
    FeatureSpec(
        name="ip_attempts_5s",
        scope=EntityScope.IP,
        window="5s",
        dtype="int32",
        description="Number of login attempts from this src_ip in the last 5 seconds "
        "(excluding the current event).",
    ),
    FeatureSpec(
        name="ip_attempts_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="int32",
        description="Number of login attempts from this src_ip in the last 30 seconds "
        "(excluding the current event).",
    ),
    FeatureSpec(
        name="ip_failed_rate_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="float32",
        description="Failure rate for this src_ip over the last 30 seconds: "
        "failed_attempts / total_attempts (0.0 if no attempts).",
    ),
    FeatureSpec(
        name="ip_unique_users_5m",
        scope=EntityScope.IP,
        window="5m",
        dtype="int32",
        description="Number of distinct usernames targeted by this src_ip in the last 5 minutes.",
    ),
    FeatureSpec(
        name="ip_avg_interarrival_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="float32",
        description="Average time in seconds between consecutive login attempts from this src_ip "
        "over the last 30 seconds (computed from timestamps of previous attempts only; "
        "0.0 if fewer than 2 attempts).",
    ),
    FeatureSpec(
        name="ip_unique_geos_5m",
        scope=EntityScope.IP,
        window="5m",
        dtype="int32",
        description="Number of distinct geo locations for this src_ip in the last 5 minutes.",
    ),
    FeatureSpec(
        name="ip_unique_devices_5m",
        scope=EntityScope.IP,
        window="5m",
        dtype="int32",
        description="Number of distinct device fingerprints for this src_ip in the last 5 minutes.",
    ),
    FeatureSpec(
        name="ip_avg_request_duration_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="float32",
        description="Average request duration in ms for this src_ip over the last 30 seconds.",
    ),
    FeatureSpec(
        name="ip_failed_attempts_5m",
        scope=EntityScope.IP,
        window="5m",
        dtype="int32",
        description="Number of failed login attempts from this src_ip in the last 5 minutes.",
    ),
    FeatureSpec(
        name="ip_velocity_1m",
        scope=EntityScope.IP,
        window="1m",
        dtype="float32",
        description="Average attempts per second from this src_ip in the last 1 minute.",
    ),
    FeatureSpec(
        name="ip_failed_streak",
        scope=EntityScope.IP,
        window=None,
        dtype="int32",
        description="Number of consecutive failed attempts from this src_ip immediately before the current event.",
    ),
    FeatureSpec(
        name="ip_unique_users_1m",
        scope=EntityScope.IP,
        window="1m",
        dtype="int32",
        description="Number of distinct usernames targeted by this src_ip in the last 1 minute.",
    ),
    FeatureSpec(
        name="ip_min_interarrival_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="float32",
        description="Minimum time in seconds between consecutive login attempts from this src_ip "
        "over the last 30 seconds (0.0 if fewer than 2 attempts).",
    ),
    FeatureSpec(
        name="ip_std_interarrival_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="float32",
        description="Standard deviation of interarrival times for this src_ip over the last 30 seconds "
        "(0.0 if fewer than 2 attempts).",
    ),
    FeatureSpec(
        name="ip_unique_users_velocity_1m",
        scope=EntityScope.IP,
        window="1m",
        dtype="float32",
        description="Number of unique users per minute from this src_ip in the last 1 minute.",
    ),
    FeatureSpec(
        name="ip_consecutive_failures_10s",
        scope=EntityScope.IP,
        window="10s",
        dtype="int32",
        description="Number of consecutive failed attempts from this src_ip in the last 10 seconds.",
    ),
    FeatureSpec(
        name="ip_attempts_10s",
        scope=EntityScope.IP,
        window="10s",
        dtype="int32",
        description="Number of login attempts from this src_ip in the last 10 seconds "
        "(excluding the current event).",
    ),
    FeatureSpec(
        name="ip_failed_velocity_30s",
        scope=EntityScope.IP,
        window="30s",
        dtype="float32",
        description="Average failed attempts per second from this src_ip in the last 30 seconds.",
    ),
]


# === User-based đặc trưng ====================================================

USER_FEATURES: Sequence[FeatureSpec] = [
    FeatureSpec(
        name="user_failed_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="int32",
        description="Number of failed login attempts for this username in the last 5 minutes.",
    ),
    FeatureSpec(
        name="user_unique_ips_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="int32",
        description="Number of distinct src_ip values that have attempted to log in as this "
        "username in the last 5 minutes.",
    ),
    FeatureSpec(
        name="user_unique_ips_1h",
        scope=EntityScope.USER,
        window="1h",
        dtype="int32",
        description="Number of distinct src_ip values that have attempted to log in as this "
        "username in the last 1 hour (captures slow distributed or slow-low patterns).",
    ),
    FeatureSpec(
        name="user_success_streak",
        scope=EntityScope.USER,
        window=None,
        dtype="int32",
        description="Count of consecutive successful login attempts for this username "
        "immediately before the current event (reset to 0 on failure).",
    ),
    FeatureSpec(
        name="user_unique_geos_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="int32",
        description="Number of distinct geo locations for this username in the last 5 minutes.",
    ),
    FeatureSpec(
        name="user_unique_devices_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="int32",
        description="Number of distinct device fingerprints for this username in the last 5 minutes.",
    ),
    FeatureSpec(
        name="user_failed_rate_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="float32",
        description="Failure rate for this username over the last 5 minutes: failed_attempts / total_attempts.",
    ),
    FeatureSpec(
        name="user_attempts_velocity_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="float32",
        description="Average attempts per minute for this username in the last 5 minutes.",
    ),
    FeatureSpec(
        name="user_failed_streak",
        scope=EntityScope.USER,
        window=None,
        dtype="int32",
        description="Number of consecutive failed attempts for this username immediately before the current event.",
    ),
    FeatureSpec(
        name="user_unique_ips_1m",
        scope=EntityScope.USER,
        window="1m",
        dtype="int32",
        description="Number of distinct src_ip values that have attempted to log in as this "
        "username in the last 1 minute.",
    ),
    FeatureSpec(
        name="user_min_interarrival_5m",
        scope=EntityScope.USER,
        window="5m",
        dtype="float32",
        description="Minimum time in seconds between consecutive login attempts for this username "
        "over the last 5 minutes (0.0 if fewer than 2 attempts).",
    ),
    FeatureSpec(
        name="user_ip_velocity_1m",
        scope=EntityScope.USER,
        window="1m",
        dtype="float32",
        description="Number of unique IPs per minute attempting to log in as this username in the last 1 minute.",
    ),
    FeatureSpec(
        name="user_consecutive_failures_10s",
        scope=EntityScope.USER,
        window="10s",
        dtype="int32",
        description="Number of consecutive failed attempts for this username in the last 10 seconds.",
    ),
]


# === IP-User pair đặc trưng ==================================================

PAIR_FEATURES: Sequence[FeatureSpec] = [
    FeatureSpec(
        name="pair_attempts_5m",
        scope=EntityScope.PAIR,
        window="5m",
        dtype="int32",
        description="Number of login attempts in the last 5 minutes for this (src_ip, username) pair.",
    ),
    FeatureSpec(
        name="pair_success_rate_5m",
        scope=EntityScope.PAIR,
        window="5m",
        dtype="float32",
        description="Success rate for this (src_ip, username) pair over the last 5 minutes: "
        "successful_attempts / total_attempts (0.0 if no attempts).",
    ),
]


# === Time-based / global đặc trưng ==========================================

TIME_FEATURES: Sequence[FeatureSpec] = [
    FeatureSpec(
        name="hour_sin",
        scope=EntityScope.GLOBAL,
        window=None,
        dtype="float32",
        description="Sine transform of the hour-of-day (0–23) from event timestamp: "
        "sin(2π * hour / 24).",
    ),
    FeatureSpec(
        name="hour_cos",
        scope=EntityScope.GLOBAL,
        window=None,
        dtype="float32",
        description="Cosine transform of the hour-of-day (0–23) from event timestamp: "
        "cos(2π * hour / 24).",
    ),
    FeatureSpec(
        name="is_business_hours",
        scope=EntityScope.GLOBAL,
        window=None,
        dtype="int32",
        description="1 if event local time is within business hours (e.g. 08:00–18:00, Monday–Friday), "
        "else 0. The exact policy is defined in the feature builder.",
    ),
]


# NOTE: Rule-derived flags (e.g. rule_rapid_flag, rule_cred_flag, rule_dist_flag)
# are intentionally NOT part of the core, fixed đặc trưng list yet. They can be
# added later as additional FeatureSpec entries without breaking this initial design.


ALL_FEATURES: Sequence[FeatureSpec] = (
    tuple(IP_FEATURES)
    + tuple(USER_FEATURES)
    + tuple(PAIR_FEATURES)
    + tuple(TIME_FEATURES)
)


def get_feature_names() -> list[str]:
    """
    Convenience helper to get the ordered list of đặc trưng column names for model input.
    """

    return [f.name for f in ALL_FEATURES]


__all__ = [
    "EntityScope",
    "FeatureSpec",
    "IP_FEATURES",
    "USER_FEATURES",
    "PAIR_FEATURES",
    "TIME_FEATURES",
    "ALL_FEATURES",
    "get_feature_names",
]

