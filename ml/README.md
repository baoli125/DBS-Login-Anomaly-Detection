# ML — Brute-force detection & attack classification

Pipeline ML: định nghĩa feature, build feature từ NDJSON, train binary + multi-class model, inference, và so sánh với rule-based.

---

## Cấu trúc

```
ml/
├── core/
│   ├── train_models.py       # train_models(): train binary + multiclass LR, scaler, metadata, thresholds
│   ├── inference.py          # load_models(), predict_attack_from_features(), predict_attack_type_from_features(), predict_attack_and_type()
│   └── __init__.py
├── features/
│   ├── features.py           # Định nghĩa feature: IP, User, Pair, Time (ALL_FEATURES, get_feature_names())
│   ├── feature_builder.py    # build_features_from_events(), build_dataset_from_ndjson() — NDJSON -> Parquet
│   └── __init__.py
├── evaluation/
│   ├── evaluate_ml_vs_rule.py # So sánh ML vs rule trên cùng NDJSON, report theo attack_type
│   └── __init__.py
├── __init__.py               # Export: EntityScope, FeatureSpec, ALL_FEATURES, get_feature_names, ...
└── README.md                 # (file này)
```

---

## 1. Feature (`features.py`)

- **EntityScope**: IP, USER, PAIR, GLOBAL.
- **FeatureSpec**: name, scope, window, dtype, description.
- **Nhóm feature**:
  - **IP**: `ip_attempts_1s`, `ip_attempts_5s`, `ip_attempts_30s`, `ip_failed_rate_30s`, `ip_unique_users_5m`, `ip_avg_interarrival_30s`.
  - **User**: `user_failed_5m`, `user_unique_ips_5m`, `user_unique_ips_1h`, `user_success_streak`.
  - **Pair**: `pair_attempts_5m`, `pair_success_rate_5m`.
  - **Time**: `hour_sin`, `hour_cos`, `is_business_hours`.
- **get_feature_names()**: trả về list tên feature đúng thứ tự dùng cho model và inference.

---

## 2. Feature builder (`feature_builder.py`)

- **build_features_from_events(events)**  
  Nhận iterable event dict (có `timestamp`, `username`, `src_ip`, `success`, `is_attack`, `attack_type`). Sort theo thời gian, duyệt từng event, dùng sliding window **chỉ dữ liệu quá khứ** để tính từng feature. Mỗi event → 1 dòng DataFrame với cột: `timestamp`, `entity_type`, `entity_value`, các feature, `is_attack_label` (0/1), `attack_type_label` (string, mặc định "benign").

- **build_dataset_from_ndjson(path, output_parquet_path=None)**  
  Đọc NDJSON từ file, gọi `build_features_from_events`, trả về DataFrame; nếu truyền `output_parquet_path` thì ghi Parquet.

- State nội bộ: IpState, UserState, PairState (deque theo cửa sổ 30s/5m/1h) để không leak tương lai.

---

## 3. Training (`train_models.py`)

- **Đầu vào**: Một file Parquet từ feature_builder (có đủ cột trong `get_feature_names()` + `is_attack_label` + `attack_type_label`).
- **Xử lý**: Sort theo timestamp, chia 70% train / 15% val / 15% test theo thời gian. Fit `StandardScaler` trên train, scale val/test.
- **Model**:
  - Binary: Logistic Regression (class_weight=balanced, GridSearchCV với TimeSeriesSplit), dự đoán `is_attack_label`.
  - Multiclass: Logistic Regression multinomial, dự đoán `attack_type_label` (LabelEncoder lưu trong metadata).
- **Threshold**: Từ precision-recall curve trên test: `t_high_recall`, `t_balanced`, `t_high_precision` (lưu vào metadata).
- **Đầu ra**: `binary_model.joblib`, `multiclass_model.joblib`, `scaler.joblib`, `model_metadata.json` (feature_names, label_encoding, thresholds, metrics).
- **CLI**: `python -m ml.train_models --input-parquet <path> --output-dir models [--random-state 42]`.

---

## 4. Inference (`inference.py`)

- **load_models(models_dir=None, use_cache=True)**  
  Load binary_model, multiclass_model, scaler, model_metadata.json; trả về `LoadedModels` (feature_names, class_labels, thresholds). Mặc định `models_dir` = `<project_root>/models`.

- **predict_attack_from_features(features, models_dir=None, threshold=None, threshold_key="t_balanced")**  
  `features` là dict (tên feature -> giá trị) hoặc array đúng thứ tự. Trả về: score (P(attack)), label (0/1), threshold_used, thresholds_flags (above_high_recall, above_balanced, above_high_precision), raw_thresholds.

- **predict_attack_type_from_features(features, models_dir=None)**  
  Trả về: class_index, class_label, class_probabilities (dict label -> prob).

- **predict_attack_and_type(...)**  
  Gộp hai hàm trên: score, label, attack_type, attack_type_probabilities, thresholds.

- **extract_features_for_event(event, aggregator_state)**  
  Hiện chỉ raise NotImplementedError; dự kiến sau này tính feature real-time từ event + state (ML-aggregator).

---

## 5. Đánh giá ML vs Rule (`evaluate_ml_vs_rule.py`)

- Load NDJSON, chạy rule-based evaluation (gọi logic tương tự `scripts/run_rulebase.py` / evaluate_events), build feature cho cùng events, load ML models, predict với threshold đã chọn (t_balanced hoặc custom).
- Tính precision/recall/F1 cho rule và cho ML; detection rate theo từng `attack_type`.
- In bảng so sánh, ghi report JSON vào `reports/ml_vs_rule_*.json`.
- **CLI**: `python -m ml.evaluate_ml_vs_rule <dataset.ndjson> [--models-dir models] [--threshold-key t_balanced] [--output-dir reports]`.

---

## 6. Chạy pipeline từ scripts

- Dùng **scripts/run_ml.py** (xem [scripts/README.md](../scripts/README.md)):
  - `run_ml.py build` — NDJSON -> Parquet (mặc định data/train_events.ndjson, data/test_events.ndjson -> data/features/).
  - `run_ml.py train` — Parquet -> train -> models/.
  - `run_ml.py evaluate` — So sánh ML vs rule trên NDJSON.
  - `run_ml.py all` — build -> train -> evaluate với path mặc định.
