# Detection System

Gói phát hiện tấn công brute-force: **rule-based** (aggregator + rules + evaluator) chạy real-time, và **ML gateway** chuẩn bị cho Decision Engine.

---

## Cấu trúc

```
detection_system/
├── __init__.py          # Export: SimpleAggregator, RuleLoader, RuleEvaluator, DebugRuleEvaluator
├── ml_gateway.py        # API gọi ML: load model, evaluate_event(feature_vector)
├── README.md            # (file này)
└── rule_based/          # Hệ thống rule
    ├── __init__.py
    ├── aggregator.py    # SimpleAggregator: sliding window 30s/5m/1h theo IP và User
    ├── rule_loader.py   # RuleLoader: đọc rules từ JSON
    ├── rule_evaluator.py    # RuleEvaluator: evaluate_realtime(aggregator, event) -> Decision
    ├── rule_evaluator_debug.py  # DebugRuleEvaluator (debug)
    ├── rule_debugger.py
    ├── comprehensive_test.py   # Test rule/aggregator
    └── rules/           # Rule JSON (rapid_bruteforce, credential_stuffing, distributed_attack)
        ├── rapid_bruteforce.json
        ├── credential_stuffing.json
        └── distributed_attack.json
```

---

## 1. Rule-based detection

### 1.1. SimpleAggregator (`rule_based/aggregator.py`)

- **Vai trò**: Cập nhật state theo từng event login (IP + User), tính metrics trong các cửa sổ thời gian **trước** thời điểm event hiện tại (tránh leak tương lai).
- **Cửa sổ**: 30s, 5m, 1h cho mỗi entity (IP hoặc username).
- **Metrics** (ví dụ): `failed_attempts_30s`, `attempts_per_sec_30s`, `unique_users`, `unique_ips`, v.v.
- **API chính**:
  - `process_event(event)` — đẩy event vào aggregator.
  - `get_metrics_at_event_time(scope, entity_key, event)` — trả về dict metrics tại thời điểm event (dùng cho evaluator).
  - `get_evidence_samples(scope, entity_key, limit)` — lấy mẫu event gần đây cho evidence.

### 1.2. RuleLoader (`rule_based/rule_loader.py`)

- Đọc file JSON trong `rule_based/rules/` (ví dụ `rapid_bruteforce.json`, `credential_stuffing.json`, `distributed_attack.json`).
- Mỗi rule có: `id`, `name`, `enabled`, `scope` (ip/user), `condition` (clauses: metric, op, value), `action` (staged: alert / throttle / temp_block), `cooldown_seconds`, `evidence_fields`.
- **API**: `get_enabled_rules()`, `get_rule(rule_id)`.

### 1.3. RuleEvaluator (`rule_based/rule_evaluator.py`)

- **API chính**: `evaluate_realtime(aggregator, event) -> Decision | None`.
  - Lấy metrics cho IP và User từ aggregator tại thời điểm event.
  - So sánh với từng rule (condition); nếu match thì trả về `Decision(matched=True, rule_id, action_suggestion, evidence)`.
- **Decision**: `matched`, `rule_id`, `action_suggestion`, `evidence` (metrics, severity, …).
- Hỗ trợ staged action (alert → throttle → temp_block theo ngưỡng).

### 1.4. Rules JSON

- **rapid_bruteforce**: scope IP, window 30s, điều kiện `failed_attempts_30s >= 20` và `attempts_per_sec_30s >= 0.7`.
- **credential_stuffing**: scope IP, window 5m, nhiều user khác nhau từ cùng IP.
- **distributed_attack**: scope User, window 5m/1h, nhiều IP khác nhau tấn công cùng user.

Chi tiết từng field xem trong từng file `.json`.

---

## 2. ML Gateway (`ml_gateway.py`)

- **Mục đích**: Interface thống nhất để Decision Engine (hoặc web app sau này) gọi ML: load model một lần, sau đó predict theo feature vector.
- **Đã làm**:
  - `initialize_ml_models(models_dir="models") -> bool`: load binary + multiclass model + scaler + metadata, cache trong memory.
  - `is_ml_enabled() -> bool`: kiểm tra đã load model chưa.
  - `evaluate_event(event, feature_vector=None) -> MLEvaluationResult`: nếu có `feature_vector` (dict hoặc list theo `ml.features.get_feature_names()`) thì gọi `ml.inference.predict_attack_and_type`, trả về score, label, attack_type, thresholds, probabilities, debug.
- **Chưa làm**: Tính feature real-time từ event (cần ML-aggregator hoặc tái sử dụng SimpleAggregator + logic feature giống `ml.feature_builder`). Hiện chỉ nhận feature đã tính sẵn.

---

## 3. Luồng tích hợp (web app)

- Web app khởi tạo một lần: `SimpleAggregator`, `RuleLoader`, `RuleEvaluator` (xem `web_app/detection_integration.py`).
- Mỗi request login: tạo event dict → `evaluator.evaluate_realtime(aggregator, event)` → nếu `Decision.matched` thì block/alert/throttle theo `action_suggestion`.

---

## 4. Đánh giá rule trên file NDJSON

- Dùng script `scripts/run_rulebase.py`: load NDJSON, duyệt từng event, gọi `evaluate_realtime`, thu thập alerts và tính precision/recall/F1, detection theo attack_type. Chi tiết xem [scripts/README.md](scripts/README.md).
