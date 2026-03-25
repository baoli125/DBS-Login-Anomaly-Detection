"""
Bộ Tải Cấu Hình Agent - Tương tự cách tải cấu hình ML

Mô-đun này tải các ngưỡng (threshold) của decision engine từ agent_metadata.json.
Cho phép quản lý tập trung các chính sách khóa mà không cần sửa code.
"""

import json
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class DecisionEngineConfig:
    """Decision engine thresholds loaded from metadata."""
    
    # Trọng số risk score
    rule_weight: float
    ml_weight: float
    
    # Ngưỡng hành động
    ml_block_threshold: float
    risk_score_block: float
    risk_score_throttle: float
    risk_score_challenge: float
    
    # Điều kiện tối thiểu để xem xét cả rule và ML
    min_rule_score_for_combined: float
    min_ml_score_for_combined: float
    
    # Ngưỡng cho từng loại tấn công
    per_attack_type_thresholds: Dict[str, Dict[str, Any]]
    
    # Chính sách khóa
    block_duration_seconds: int


_CONFIG_CACHE: Dict[str, DecisionEngineConfig] = {}


def load_agent_config(config_dir: str = "agent/config") -> DecisionEngineConfig:
    """
    Tải các ngưỡng decision engine từ agent_metadata.json.
    Sử dụng bộ đệm (cache) để tăng hiệu suất.
    
    Args:
        config_dir: Thư mục chứa agent_metadata.json
        
    Returns:
        Instance DecisionEngineConfig với tất cả các ngưỡng
    """
    resolved_dir = os.path.abspath(config_dir)
    
    # Kiểm tra bộ đệm
    if resolved_dir in _CONFIG_CACHE:
        return _CONFIG_CACHE[resolved_dir]
    
    metadata_path = os.path.join(resolved_dir, "agent_metadata.json")
    
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(f"Metadata agent không tìm thấy: {metadata_path}")
    
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata: Dict[str, Any] = json.load(f)
    
    # Trích xuất các ngưỡng decision engine
    decision_engine = metadata.get("decision_engine", {})
    risk_score_weights = decision_engine.get("risk_score_weights", {})
    action_thresholds = decision_engine.get("action_thresholds", {})
    ml_score_minimum_factors = decision_engine.get("ml_score_minimum_factors", {})
    blocking_policy = metadata.get("blocking_policy", {})
    per_attack_type = metadata.get("per_attack_type_thresholds", {})
    
    config = DecisionEngineConfig(
        rule_weight=float(risk_score_weights.get("rule_weight", 0.5)),
        ml_weight=float(risk_score_weights.get("ml_weight", 0.5)),
        
        ml_block_threshold=float(action_thresholds.get("ml_block_threshold", 0.8)),
        risk_score_block=float(action_thresholds.get("risk_score_block", 0.75)),
        risk_score_throttle=float(action_thresholds.get("risk_score_throttle", 0.6)),
        risk_score_challenge=float(action_thresholds.get("risk_score_challenge", 0.4)),
        
        min_rule_score_for_combined=float(ml_score_minimum_factors.get("min_rule_score_for_combined", 0.3)),
        min_ml_score_for_combined=float(ml_score_minimum_factors.get("min_ml_score_for_combined", 0.3)),
        
        per_attack_type_thresholds=per_attack_type,
        block_duration_seconds=int(blocking_policy.get("block_duration_seconds", 3600)),
    )
    
    # Lưu vào bộ đệm
    _CONFIG_CACHE[resolved_dir] = config
    
    return config


def get_attack_type_threshold(attack_type: str, config: Optional[DecisionEngineConfig] = None) -> float:
    """
    Lấy ngưỡng ML score cho loại tấn công cụ thể.
    
    Args:
        attack_type: Tên loại tấn công (vd: 'credential_stuffing', 'rapid_bruteforce')
        cấu hình: Instance DecisionEngineConfig. Nếu None, tải cấu hình mặc định.
        
    Returns:
        Ngưỡng ML score cho loại tấn công đó, hoặc 0.5 (mặc định)
    """
    if config is None:
        config = load_agent_config()
    
    attack_config = config.per_attack_type_thresholds.get(attack_type, {})
    return float(attack_config.get("ml_score_threshold", 0.5))


__all__ = [
    "DecisionEngineConfig",
    "load_agent_config",
    "get_attack_type_threshold",
]
