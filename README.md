# EaglePro: Complete Brute-Force Phát hiện System

## Overview

EaglePro implements a complete 4-layer brute-force phát hiện system:

1. **Dựa trên quy tắc Phát hiện** - Fixed rules for immediate phản hồi
2. **ML-based Phát hiện** - Binary classification (tấn công vs benign)
3. **Tấn công Classification** - Multi-class ML (tấn công type identification)
4. **AI Phản hồi Agent** - Automated phản hồi strategies

## Architecture

```
Login Events → Rule Engine → ML Binary → ML Multi-class → Phản hồi Agent
     ↓            ↓            ↓            ↓              ↓
   Raw logs    Immediate     Tấn công?     Tấn công type    Actions
              blocking      phát hiện   classification  (block/alert/2FA)
```

## Components

### 1. Dựa trên quy tắc Phát hiện (`detection_system/rule_based/`)

**Rules:**
- `rapid_bruteforce.json`: IP-level rapid attempts (>10 fails/30s, >0.5 attempts/sec)
- `credential_stuffing.json`: Multi-user attacks from single IP (>5 users, >5 fails/5m)
- `distributed_attack.json`: Multi-IP attacks on single user (>8 IPs, >50 fails/5m)

**Đặc trưng:**
- Sliding window metrics (30s, 5m, 1h)
- Cooldown periods (set to 0 for training)
- Staged responses (alert → throttle → block)

### 2. ML Binary Phát hiện (`ml/`)

**Model:** Logistic Regression
**Đặc trưng:** 15 sliding-window metrics (IP, user, pair scopes)
**Performance:** Precision 1.000, Recall 0.991, F1 0.995

### 3. ML Tấn công Classification (`ml/`)

**Model:** Multi-class Logistic Regression
**Classes:** benign, rapid_bruteforce, credential_stuffing, distributed_attack, targeted_slow_low
**Performance:** 100% accuracy on kiểm tra set

### 4. AI Phản hồi Agent (`agent/`)

**Chiến lược:**
- `rapid_bruteforce`: Block IP for 5 minutes
- `credential_stuffing`: Yêu cầu 2FA for affected users
- `distributed_attack`: Admin alert + 1-hour giám sát
- `targeted_slow_low`: 2-hour giám sát only

**Đặc trưng:**
- Periodic giám sát (default 5 minutes)
- Trạng thái management (blocked IPs, 2FA requirements, alerts)
- Automatic dọn dẹp of expired responses

## Usage

### Training Pipeline
```bash
# Xây dựng đặc trưng from NDJSON
python scripts/run_ml.py xây dựng

# Train ML models
python scripts/run_ml.py train

# Evaluate vs dựa trên quy tắc
python scripts/run_ml.py evaluate
```

### Classification Demo
```bash
# Phân loại tập dữ liệu
python scripts/run_classification.py tập dữ liệu --tập dữ liệu data/test_events.ndjson --limit 10

# Phân loại single sự kiện
python scripts/run_classification.py single --sự kiện '{"timestamp":"2026-03-09T10:00:00Z","username":"user1","src_ip":"192.168.1.1","success":false}'

# Tập dữ liệu statistics
python scripts/run_classification.py stats --tập dữ liệu data/test_events.ndjson
```

### AI Phản hồi Agent
```bash
# Run once on kiểm tra data
python scripts/run_agent.py --tập dữ liệu data/test_events.ndjson --once

# Continuous giám sát (every 5 minutes)
python scripts/run_agent.py --tập dữ liệu data/test_events.ndjson
```

## Quick start + flowchart

### Quick-start 1-liner

```bash
python scripts/setup_database.py && python scripts/run_web.py
```

### Overview flowchart

```mermaid
flowchart LR
    A[Login request] --> B[Rule evaluation]
    B --> C{Rule matched?}
    C -->|Yes| D[Rule confidence]
    C -->|No| E[ML inference]
    D --> F[Risk aggregation]
    E --> F
    F --> G{Risk/ML thresholds}
    G -->|ml >= 0.8| H[BLOCK]
    G -->|risk > 0.85| H
    G -->|0.6 < risk <= 0.85| I[THROTTLE / 2FA]
    G -->|0.4 < risk <= 0.6| J[CHALLENGE]
    G -->|otherwise| K[ALLOW]
    E --> L[LOG: ML ALERT]
    H --> M[LOG: BLOCKED]
```

## Performance Results

### Dựa trên quy tắc vs ML Comparison
| Metric | Dựa trên quy tắc | ML Binary | ML Multi-class |
|--------|------------|-----------|----------------|
| Precision | 0.997 | 1.000 | N/A |
| Recall | 0.985 | 0.991 | 100% |
| F1 | 0.991 | 0.995 | N/A |

### Tấn công Type Phát hiện Rates
- `rapid_bruteforce`: 94.7%
- `credential_stuffing`: 99.5%
- `distributed_attack`: 94.4%

## Key Innovations

1. **Hybrid Phát hiện**: Rules for speed, ML for sophistication
2. **Tấn công-aware Responses**: Different strategies per tấn công type
3. **Stateful Agent**: Maintains phản hồi trạng thái across giám sát cycles
4. **Zero Cooldown Training**: Rules tuned without cooldown for better labeling

## Files Structure

```
eaglepro/
├── agent/                           # AI Phản hồi Agent
│   ├── core/                        # Core agent functionality
│   ├── processing/                  # Sự kiện processing
│   └── README.md
├── classification/                  # ML Classification demos
│   ├── core/                        # Classification logic
│   ├── demo/                        # Demo modules
│   └── README.md
├── data_generator/                  # Synthetic data generation
│   ├── core/                        # Core generation logic
│   ├── patterns/                    # Tấn công patterns
│   ├── scenarios/                   # Scenario configurations
│   └── README.md
├── detection_system/rule_based/     # Rule engine
├── ml/                              # ML models & training
│   ├── core/                        # Training and inference
│   ├── đặc trưng/                    # Đặc trưng engineering
│   ├── evaluation/                  # Evaluation utilities
│   └── README.md
├── scripts/                         # Training & evaluation scripts
├── data/                            # Generated datasets
├── models/                          # Trained ML artifacts
├── reports/                         # Evaluation reports
└── README.md                        # This file
```

## Future Enhancements

- Real-time streaming integration
- Advanced ML models (Random Forest, Neural Networks)
- User behavior modeling
- Integration with SIEM systems
- Adaptive threshold tuning
4. **ML**: Xây dựng đặc trưng, train, so sánh ML vs rule bằng [scripts/run_ml.py](scripts/run_ml.py) (xem [ml/README.md](ml/README.md)).
5. **Web**: Chạy [web_app/app.py](web_app/app.py); phát hiện dựa trên quy tắc chạy real-time khi login (xem [web_app/README.md](web_app/README.md)).

---

## Dev housekeeping

- Đã xóa file tạm: `tmp_import_test.py`.
- Đã xóa folder không dùng: `web_app_old`.
- Đã xóa báo cáo cũ: `WEB_APP_COMPLETE_FIX.md`, `WEB_APP_FIX_REPORT.md`.
- Các tệp cốt lõi vẫn còn:
  - `scripts/` (setup, run, trigger)
  - `database/` (schema, sample_data.sql)
  - `models/` (artifact ML: binary_model, multiclass_model, scaler, metadata)
  - `web_app/` (app logic và route)

Lưu ý: khi clone repo mới, chỉ cần chạy `python scripts/setup_database.py` để tạo schema + sample data, rồi `python scripts/run_web.py` để start web.

---

## Tài liệu chi tiết từng phần

- **[agent/README.md](agent/README.md)** — AI Phản hồi Agent architecture, usage, and integration.
- **[classification/README.md](classification/README.md)** — ML Classification mô-đun, demos, and API.
- **[data_generator/README.md](data_generator/README.md)** — Synthetic data generation, patterns, and scenarios.
- **[ml/README.md](ml/README.md)** — ML pipeline: đặc trưng, training, inference, and evaluation.
- **[detection_system/README.md](detection_system/README.md)** — Dựa trên quy tắc (aggregator, rule_loader, rule_evaluator), rules JSON, ML gateway.
- **[web_app/README.md](web_app/README.md)** — App, routes, detection_integration, models, cấu hình, templates.
- **[scripts/README.md](scripts/README.md)** — run_generator, run_rulebase, run_ml, setup_database.
- **[database/README.md](database/README.md)** — Schema, bảng, mối quan hệ.
