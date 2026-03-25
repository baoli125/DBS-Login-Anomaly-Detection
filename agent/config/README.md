# Agent Cấu hình Guide

## Tổng Quan

Thay vì hardcode các số thresholds trong code, hệ thống sử dụng **`agent_metadata.json`** để lưu trữ tất cả các thông số quyết định hành động (block, throttle, challenge, cho phép).

**Lợi ích:**
- Chỉnh sửa thresholds mà không cần sửa code
- Dễ dàng thử nghiệm các ngưỡng khác nhau
- Giống như ML model metadata (centralized cấu hình)

---

## 📁 Vị trí & Cấu Trúc

```
agent/
├── cấu hình/
│   ├── __init__.py
│   ├── agent_metadata.json          ← Thresholds & policies
│   └── agent_metadata.py            ← Utility functions
├── core/
│   ├── config_loader.py             ← Tải cấu hình
│   └── ...
└── ...
```

---

## 🔧 Các Thresholds Chính

### 1. Risk Score Weights (Trọng số mix Rule + ML)

```json
"risk_score_weights": {
  "rule_weight": 0.5,
  "ml_weight": 0.5
}
```

**Công thức:** `risk_score = rule_score * rule_weight + ml_score * ml_weight`

- `rule_weight = 0.5`: Quyết định cuối =50% từ dựa trên quy tắc
- `ml_weight = 0.5`: Quyết định cuối =50% từ ML

---

### 2. Action Thresholds (Ngưỡng quyết định hành động)

```json
"action_thresholds": {
  "ml_block_threshold": 0.8,
  "risk_score_block": 0.75,
  "risk_score_throttle": 0.6,
  "risk_score_challenge": 0.4
}
```

**Decision Flow:**
1. Nếu `ml_score >= 0.8` → **BLOCK** (ML rất chắc chắn)
2. Nếu `risk_score > 0.75` → **BLOCK** (tích hợp rule + ML)
3. Nếu `risk_score > 0.6` → **THROTTLE** + 2FA (yêu cầu xác minh)
4. Nếu `risk_score > 0.4` → **CHALLENGE** + 2FA (hỏi thêm)
5. Còn lại → **ALLOW** (bình thường)

---

### 3. Minimum Factors (Điều kiện "cân nhắc cả hai")

```json
"ml_score_minimum_factors": {
  "min_rule_score_for_combined": 0.3,
  "min_ml_score_for_combined": 0.3
}
```

**Ý nghĩa:** 
- Chỉ mix rule + ML nếu **cả hai > 0.3**
- Nếu một cái = 0, dùng cay khác mà không weighted mix

---

### 4. Per-Tấn công-Type Thresholds

```json
"per_attack_type_thresholds": {
  "credential_stuffing": {
    "ml_score_threshold": 0.5,
    "precision_priority": true
  },
  "distributed_attack": {
    "ml_score_threshold": 0.25,
    "precision_priority": false
  },
  "rapid_bruteforce": {
    "ml_score_threshold": 0.2,
    "precision_priority": false
  }
}
```

**Cách hoạt động:**
- Nếu attack_type = "credential_stuffing" và `ml_score >= 0.5` → Block ngay
- Nếu attack_type = "distributed_attack" và `ml_score >= 0.25` → Block ngay
- Nếu attack_type = "rapid_bruteforce" và `ml_score >= 0.2` → Block ngay

---

## 🚀 Cách Sử Dụng

### (1) Xem cấu hình hiện tại

```bash
cd /mnt/hgfs/share_Ubuntu/DBS-Login-Anomaly-Phát hiện-main
python -m agent.cấu hình.agent_metadata
```

Output:
```
============================================================
 AGENT DECISION ENGINE CONFIGURATION
============================================================

[Risk Score Weights]
  rule_weight:  0.5
  ml_weight:    0.5

[Action Thresholds]
  ml_block_threshold:       0.8
  risk_score_block:         0.75
  risk_score_throttle:      0.6
  risk_score_challenge:     0.4

...
```

### (2) Sửa trực tiếp file JSON

Edit `agent/cấu hình/agent_metadata.json` - ví dụ:

```json
"action_thresholds": {
  "ml_block_threshold": 0.7,        // Hạ từ 0.8 xuống 0.7
  "risk_score_block": 0.7,          // Hạ từ 0.75 xuống 0.7
  ...
}
```

Lần tới khi chạy hệ thống, cấu hình mới sẽ được tải tự động.

### (3) Cập nhật programmatically

```python
from agent.cấu hình.agent_metadata import update_threshold, show_config

# Cập nhật từng threshold
update_threshold("decision_engine/action_thresholds/risk_score_block", 0.7)
update_threshold("per_attack_type_thresholds/distributed_attack/ml_score_threshold", 0.2)

# Xem lại cấu hình
show_config()
```

---

## 📊 Ví Dụ Điều Chỉnh

### Scenario 1: Giảm False Positive (ít block hơn)

**Vấn đề:** Quá nhiều user bình thường bị block

**Cách fix:**
```json
{
  "rule_weight": 0.6,              // Tăng weight rule (ít bị FP)
  "ml_weight": 0.4,
  
  "ml_block_threshold": 0.85,      // Nâng cao (cần rất chắc chắn)
  "risk_score_block": 0.8,         // Nâng cao
  
  "credential_stuffing": {
    "ml_score_threshold": 0.6      // Nâng cao (ít FP)
  }
}
```

### Scenario 2: Tăng Phát hiện (block nhiều hơn)

**Vấn đề:** Bỏ sót nhiều tấn công

**Cách fix:**
```json
{
  "rule_weight": 0.4,              // Giảm weight rule
  "ml_weight": 0.6,                // Tăng weight ML
  
  "ml_block_threshold": 0.7,       // Hạ (cần ít chắc chắn hơn)
  "risk_score_block": 0.65,        // Hạ
  
  "distributed_attack": {
    "ml_score_threshold": 0.2      // Hạ (tăng recall)
  }
}
```

---

## 💾 Chú Ý

1. **Caching:** Cấu hình được cache khi chạy lần đầu. Để reload, tắt/khởi động lại ứng dụng hoặc gọi `reload_config()`.

2. **Validation:** Hiện tại không có validation, hãy đảm bảo:
   - `rule_weight + ml_weight ≈ 1.0`
   - Tất cả threshold là số từ 0-1
   - `ml_block_threshold >= risk_score_block >= risk_score_throttle >= risk_score_challenge`

3. **Rollback:** Nếu cấu hình bị lỗi, có thể khôi phục bản backup hoặc dùng git.

---

## 🔗 Liên Kết

- **Core loader:** `agent/core/config_loader.py`
- **Integration:** `web_app/integration.py` (sử dụng cấu hình trong decision engine)
- **ML thresholds:** `models/model_metadata.json` (tương tự cơ chế)
