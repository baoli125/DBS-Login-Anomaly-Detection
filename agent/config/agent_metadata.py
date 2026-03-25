"""
Truy cập nhanh và các hàm tiện ích cho cấu hình agent - quản lý ngưỡng tập trung.
Cho phép dễ dàng kiểm tra và tải lại các ngưỡng mà không cần sửa code.
"""

import json
import os
from pathlib import Path


def get_metadata_path():
    """Lấy đường dẫn tuyệt đối đến agent_metadata.json."""
    config_dir = Path(__file__).parent
    return config_dir / "agent_metadata.json"


def get_config():
    """Tải và trả về metadata agent hiện tại dưới dạng dict."""
    path = get_metadata_path()
    if not path.exists():
        raise FileNotFoundError(f"Agent metadata not found: {path}")
    
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def reload_config():
    """Tải lại metadata agent (hữu ích khi file được sửa thủ công).
    Điều này chỉ là đọc lại file - Bộ đệm Python được xử lý bởi core loader"""
    return get_config()


def show_config():
    """In đẹp cấu hình agent hiện tại."""
    config = get_config()
    
    print("\n" + "="*60)
    print(" CẤU HÌNH DECISION ENGINE CỦA AGENT")
    print("="*60)
    
    de = config.get("decision_engine", {})
    
    print("\n[Trọng Số Risk Score]")
    weights = de.get("risk_score_weights", {})
    print(f"  rule_weight:  {weights.get('rule_weight', 0.5)}")
    print(f"  ml_weight:    {weights.get('ml_weight', 0.5)}")
    
    print("\n[Ngưỡng Hành Động]")
    thresholds = de.get("action_thresholds", {})
    print(f"  ml_block_threshold:       {thresholds.get('ml_block_threshold', 0.8)}")
    print(f"  risk_score_block:         {thresholds.get('risk_score_block', 0.75)}")
    print(f"  risk_score_throttle:      {thresholds.get('risk_score_throttle', 0.6)}")
    print(f"  risk_score_challenge:     {thresholds.get('risk_score_challenge', 0.4)}")
    
    print("\n[Điều Kiện Tối Thiểu Cho Quyết Định Kết Hợp]")
    factors = de.get("ml_score_minimum_factors", {})
    print(f"  min_rule_score_for_combined:  {factors.get('min_rule_score_for_combined', 0.3)}")
    print(f"  min_ml_score_for_combined:    {factors.get('min_ml_score_for_combined', 0.3)}")
    
    print("\n[Ngưỡng Cho Từng Loại Tấn Công]")
    attack_types = config.get("per_attack_type_thresholds", {})
    for attack_type, settings in attack_types.items():
        threshold = settings.get("ml_score_threshold", 0.5)
        priority = "PRECISION" if settings.get("precision_priority") else "RECALL"
        print(f"  {attack_type:25s}: threshold={threshold:.2f} (ưu tiên={priority})")
    
    print("\n[Chính Sách Khóa IP]")
    policy = config.get("blocking_policy", {})
    duration_sec = policy.get("block_duration_seconds", 3600)
    duration_min = duration_sec / 60
    print(f"  block_duration: {duration_sec} giây ({duration_min:.0f} phút)")
    
    print("\n" + "="*60 + "\n")


def update_threshold(threshold_path_str: str, new_value: float):
    """
    Cập nhật một ngưỡng cụ thể trong agent_metadata.json.
    
    Args:
        threshold_path_str: Đường dẫn như "decision_engine/action_thresholds/risk_score_block"
        new_value: Giá trị mới cho ngưỡng
    """
    config = get_config()
    path_parts = threshold_path_str.split("/")
    
    # Điều hướng đến dict cha
    current = config
    for part in path_parts[:-1]:
        if part not in current:
            raise KeyError(f"Đường dẫn không tìm thấy: {threshold_path_str}")
        current = current[part]
    
    # Cập nhật khóa cuối cùng
    final_key = path_parts[-1]
    if final_key not in current:
        raise KeyError(f"Ngưỡng không tìm thấy: {threshold_path_str}")
    
    current[final_key] = new_value
    
    # Ghi lại vào file
    path = get_metadata_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"✓ Cập nhật {threshold_path_str} = {new_value}")


if __name__ == "__main__":
    # Khi chạy script, hiển thị cấu hình hiện tại
    show_config()
