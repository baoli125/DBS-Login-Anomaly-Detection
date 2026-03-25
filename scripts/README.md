# Scripts

Các script chạy pipeline: generate data, setup database, đánh giá dựa trên quy tắc, chạy pipeline ML (xây dựng / train / evaluate), và khởi động web application.

---

## Cấu trúc

```
scripts/
├── __init__.py
├── README.md           # (file này)
├── run_generator.py    # Gọi data_generator, sinh train/kiểm tra NDJSON (+ optional ghi DB)
├── run_rulebase.py     # Đánh giá dựa trên quy tắc trên file NDJSON (evaluate_events, report, lưu alerts)
├── run_ml.py           # Pipeline ML: xây dựng | train | evaluate | all
├── run_web.py          # Khởi động web application với đầy đủ tính năng phát hiện
├── setup_database.py   # Tạo database + bảng (schema), không chèn dữ liệu mẫu
├── extract_logs.py     # Trích xuất và hiển thị logs từ database
└── attack_simulator.py # Demo thực tế các loại tấn công
```

---

## 1. run_generator.py — Sinh dữ liệu NDJSON

- **Mục đích**: Tạo sự kiện login (normal + tấn công) theo thời gian, dùng cho train/eval rule và ML.
- **Luồng**: Gọi `SimpleDataGenerator` (từ data_generator), sinh train (7 ngày) và kiểm tra (24 giờ) với attack_mix và scenario "mixed". Có thể ghi vào bảng `auth_logs` (MySQL) và/hoặc lưu file NDJSON.
- **Output file (nếu chọn lưu)**: `data/train_events.ndjson`, `data/test_events.ndjson`, `data/all_events.ndjson`.
- **Cách chạy**: `python scripts/run_generator.py`. Khi chạy xong có thể nhập `y` để lưu thêm file (nếu không ghi DB thì vẫn cần file để chạy rule/ML).
- **Chi tiết generator**: Xem [data_generator/README.md](../data_generator/README.md).

---

## 2. run_rulebase.py — Đánh giá dựa trên quy tắc trên NDJSON

- **Mục đích**: Kiểm tra dựa trên quy tắc phát hiện trên cùng loại data đã generate: tải NDJSON, duyệt từng sự kiện, gọi `evaluate_realtime(aggregator, sự kiện)`, thu thập alerts, tính precision/recall/F1 và phát hiện rate theo attack_type.
- **Thành phần dùng**: `SimpleAggregator`, `RuleLoader`, `RuleEvaluator` từ detection_system; logic giống web app (real-time, không leak tương lai).
- **Tham số**: path tập dữ liệu NDJSON, `--max-events`, `--no-cooldown`, `--verbose`, `--output-dir` (reports).
- **Output**: In bảng tổng hợp (TP/FP/FN, precision, recall, F1, phát hiện theo attack_type, rule performance); lưu report JSON và file alerts NDJSON trong `reports/`.
- **Cách chạy**: `python scripts/run_rulebase.py data/test_events.ndjson [--no-cooldown] [--output-dir reports]`.
- **Chi tiết phát hiện**: Xem [detection_system/README.md](../detection_system/README.md).

---

## 3. run_ml.py — Pipeline ML (xây dựng / train / evaluate / all)

- **Mục đích**: Một điểm vào cho toàn bộ pipeline ML: xây dựng đặc trưng từ NDJSON, train model từ Parquet, so sánh ML vs rule trên NDJSON.
- **Lệnh con**:
  - **xây dựng**: Đọc NDJSON (mặc định `data/train_events.ndjson`, `data/test_events.ndjson`), gọi `ml.feature_builder.build_dataset_from_ndjson`, ghi Parquet vào `data/đặc trưng/` (train_features.parquet, test_features.parquet).
  - **train**: Đọc Parquet (mặc định `data/đặc trưng/train_features.parquet`), gọi `ml.train_models.train_models`, ghi model + scaler + metadata vào `models/`.
  - **evaluate**: Tải NDJSON (mặc định `data/test_events.ndjson`), chạy rule evaluation và ML inference (xây dựng đặc trưng + predict), in so sánh precision/recall/F1 và phát hiện theo attack_type, lưu report vào `reports/`.
  - **all**: Chạy lần lượt xây dựng -> train -> evaluate với path mặc định (nếu thiếu kiểm tra NDJSON thì bỏ qua bước evaluate).
- **Tham số chung**: Mỗi lệnh có option riêng (--train-ndjson, --đặc trưng-dir, --input-parquet, --output-dir, --models-dir, --threshold-key, --no-cooldown, ...). Xem `python scripts/run_ml.py <command> --help`.

---

## 4. run_web.py — Khởi động Web Application

- **Mục đích**: Khởi động Flask web application với đầy đủ tính năng phát hiện bảo mật tích hợp (dựa trên quy tắc + ML + agent + classification).
- **Tính năng**: 
  - Login system với phát hiện pipeline
  - Dashboard hiển thị thống kê real-time
  - Admin panel quản lý alerts và blocked IPs
  - REST API cho integration
  - Session management và security
- **Cách chạy**: `python scripts/run_web.py`
- **URL mặc định**: http://localhost:5000
  - Dashboard: `/dashboard`
  - Admin: `/admin`
  - API: `/api/*`
- **Yêu cầu**: Database MySQL phải được setup trước (`python scripts/setup_database.py`)
- **Chi tiết web app**: Xem [web_app/README.md](../web_app/README.md).

---

## 5. extract_logs.py — Trích xuất Logs từ Database

- **Mục đích**: Trích xuất và hiển thị authentication logs, security alerts, và blocked IPs từ database.
- **Output**: Hiển thị formatted logs trên console với timestamp, user, IP, status, etc.
- **Cách chạy**: `python scripts/extract_logs.py`
- **Yêu cầu**: Database connection phải hoạt động.

---

## 6. attack_simulator.py — Demo Tấn công Thực tế

- **Mục đích**: Simulate các loại tấn công thực tế để kiểm tra và demo hệ thống phát hiện.
- **Loại tấn công**:
  - Brute force: Thử nhiều password với 1 username
  - Credential stuffing: Thử cặp username/password có sẵn
  - Rapid brute force: Thử nhanh các biến thể password
  - Distributed tấn công: Simulate từ nhiều IP
- **Cách chạy**:
  - Full demo: `python scripts/attack_simulator.py`
  - Tấn công cụ thể: `python scripts/attack_simulator.py --tấn công <type>`
- **Yêu cầu**: Web app phải đang chạy (`python scripts/run_web.py`)
- **Cách chạy**:  
  `python scripts/run_ml.py xây dựng`  
  `python scripts/run_ml.py train`  
  `python scripts/run_ml.py evaluate`  
  `python scripts/run_ml.py all`
- **Chi tiết ML**: Xem [ml/README.md](../ml/README.md).

---

## 4. setup_database.py — Tạo database và bảng

- **Mục đích**: Tạo database MySQL (eaglepro), tạo user (nếu cần), tạo tất cả bảng theo schema (users, documents, hidden_files, auth_logs, blocked_ips, alerts, ...) **không** chèn dữ liệu mẫu.
- **Kết nối**: Cấu hình trong script (host, port, user, password, db_name). Có thể chỉnh cho phù hợp môi trường.
- **Cách chạy**: `python scripts/setup_database.py`. Cần MySQL đã cài và quyền tạo DB/user.
- **Chi tiết schema**: Xem [database/README.md](../database/README.md) và [database/schema.sql](../database/schema.sql).

---

## 5. init.py

- Chỉ đánh dấu `scripts` là Python package; không chứa logic.

---

## Thứ tự chạy gợi ý

1. **Setup DB**: `python scripts/setup_database.py` (một lần hoặc khi reset).
2. **Generate data**: `python scripts/run_generator.py` → chọn lưu file NDJSON nếu cần cho rule/ML.
3. **Test rule**: `python scripts/run_rulebase.py data/test_events.ndjson`.
4. **ML full**: `python scripts/run_ml.py all` (hoặc từng bước xây dựng -> train -> evaluate).
