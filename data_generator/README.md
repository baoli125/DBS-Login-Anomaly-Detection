# Data Generator

Sinh dữ liệu event đăng nhập (NDJSON) gồm traffic bình thường và nhiều loại tấn công, dùng cho train/eval rule-based và ML.

---

## Cấu trúc

```
data_generator/
├── core/
│   ├── config.py       # USERS, NORMAL_IPS, ATTACK_IPS, DB_CONFIG, USER_AGENTS, OUTPUT_FIELDS, ...
│   ├── generator.py    # SimpleDataGenerator: generate_event(), generate() — sinh list event theo scenario
│   ├── utils.py        # random_ip(), random_user_agent(), random_geo(), generate_fingerprint(), ...
│   └── __init__.py
├── patterns/
│   ├── patterns.py     # PATTERNS (normal, weekend, rapid_bruteforce, credential_stuffing, distributed_attack, targeted_slow_low), get_pattern(), load_scenario_config()
│   └── __init__.py
├── scenarios/          # JSON scenario (tùy chọn): normal.json, weekend.json, rapid_bruteforce.json, ...
│   └── __init__.py
├── __init__.py
└── README.md
```

---

## 1. Config (`config.py`)

- **DB_CONFIG**: Kết nối MySQL (host, port, user, password, database) — dùng khi script run_generator ghi vào auth_logs.
- **USERS**: List dict (id, username, is_admin) — user sẽ xuất hiện trong event.
- **NORMAL_IPS**, **ATTACK_IPS**: IP nguồn cho traffic bình thường và cho attack (theo pattern có thể chọn ip_pool: normal / attack / attack_multi).
- **USER_AGENTS**, **COUNTRIES**: Dùng cho trường user_agent, geo trong event.
- **OUTPUT_FIELDS**: Các trường event (timestamp, username, src_ip, success, is_attack, attack_type, ...) khớp schema auth_logs / NDJSON.

---

## 2. Patterns (`patterns.py`)

- **PATTERNS**: Dict cấu hình từng kiểu hành vi / tấn công:
  - **normal**, **weekend**: success_rate, attempts_per_hour, ip_pool=normal, time_between_attempts, is_attack=False.
  - **rapid_bruteforce**: attempts_per_second, duration_seconds, ip_pool=attack, success_rate rất thấp, attack_type='rapid_bruteforce'.
  - **credential_stuffing**: nhiều user từ cùng IP, ip_pool=attack, attack_type='credential_stuffing'.
  - **distributed_attack**: nhiều IP tấn công một user, ip_pool=attack_multi, attack_type='distributed_attack'.
  - **targeted_slow_low**: tốc độ chậm, kéo dài, ip_pool=attack, attack_type='targeted_slow_low'.
- **get_pattern(name)**: Trả về config pattern theo tên.
- **is_attack_pattern(name)**: Kiểm tra có phải pattern tấn công không.
- **load_scenario_config()**: Đọc scenario từ thư mục scenarios/ (JSON) nếu cần.

---

## 3. Utils (`utils.py`)

- Hàm tiện ích: random_ip(pool), random_user_agent(), random_geo(), generate_fingerprint(...) — dùng trong generator để tạo từng trường event.

---

## 4. Generator (`generator.py`)

- **SimpleDataGenerator(seed=42)**  
  Giữ list users, normal_ips, attack_ips từ config.

- **generate_event(pattern, timestamp, is_attack=..., attack_type=..., targeted_user=..., fixed_ip=...)**  
  Sinh một event dict: chọn user (hoặc targeted_user), chọn src_ip theo pattern (ip_pool: normal/attack/attack_multi), success theo success_rate của pattern, điền đủ OUTPUT_FIELDS (timestamp, username, src_ip, success, user_agent, is_attack, attack_type, ...).

- **generate(seed, start_ts, duration, volume_per_minute, attack_mix, scenario="mixed")**  
  Sinh chuỗi event trong khoảng thời gian: trộn normal/weekend với các attack pattern theo attack_mix và scenario; trả về list event (mỗi phần tử là dict), có thể sort theo timestamp.

- Event trả về có đủ field để ghi NDJSON hoặc insert vào auth_logs; có `is_attack` và `attack_type` để ML và rule-based đánh giá.

---

## 5. Scenarios (`scenarios/`)

- Các file JSON (normal.json, weekend.json, rapid_bruteforce.json, credential_stuffing.json, distributed_burst.json, targeted_slow_low.json) mô tả cấu hình scenario (có thể dùng bởi load_scenario_config hoặc logic generate tùy phiên bản).

---

## 6. Cách dùng từ scripts

- **scripts/run_generator.py** import SimpleDataGenerator và config, gọi generate() cho train (7 ngày) và test (24 giờ), có thể ghi DB và/hoặc lưu file:
  - `data/train_events.ndjson`
  - `data/test_events.ndjson`
  - `data/all_events.ndjson`
- File NDJSON: mỗi dòng một JSON object event (timestamp, username, src_ip, success, is_attack, attack_type, ...). Format này được dùng bởi ml.feature_builder, scripts/run_rulebase.py, scripts/run_ml.py.
