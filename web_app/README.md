#  EaglePro Web Application - Complete Integration

**Complete web application integrating rule-based detection, ML classification, and intelligent response decisions.**

## Quick Start

```bash
# 1. Setup database
python setup_db.py

# 2. Run tests
cd ../scripts && python test_complete_system.py

# 3. Start application
cd ../web_app && python app_complete.py
```

Application runs at: **http://localhost:5000**

## File Structure

```
web_app/
├── __init__.py
├── app.py              # create_app(), Flask app, đăng ký blueprint, error handlers
├── config.py           # Config: SECRET_KEY, DB, ...
├── routes.py           # Blueprint main_bp: /, /dashboard, /logout, /document/<id>, admin, API detection
├── models.py           # Database: check_login, log_login, block_ip, get_blocked_ips, alerts, ...
├── detection_integration.py  # Khởi tạo SimpleAggregator + RuleEvaluator, process_login_event()
├── README.md
├── templates/          # login, dashboard, document, admin_*, 404, 500, hidden_file
└── static/
    └── css/
        └── style.css
```

---

## 1. App & Config (`app.py`, `config.py`)

- **app.py**: `create_app()` tạo Flask app, load Config, secret_key, đăng ký blueprint `main_bp`, error 404/500. Chạy với `python web_app/app.py` (host 0.0.0.0, port 5000).
- **config.py**: Cấu hình DB (MySQL), SECRET_KEY, và các biến môi trường cần thiết cho web app.

---

## 2. Routes (`routes.py`)

- **/ (GET)**: Trang login.
- **/ (POST)**: Xử lý login: kiểm tra IP block -> gọi `process_login_event` (detection) -> check_login (DB) -> nếu block thì block IP và flash; nếu thành công thì log và redirect dashboard; nếu thất bại thì log và có thể block sau khi kiểm tra lại detection.
- **/dashboard**: Trang chính sau khi đăng nhập (user docs, admin panel nếu is_admin).
- **/logout**: Xóa session, redirect /.
- **/document/<doc_id>**: Xem document — **cố ý không kiểm tra ownership** (IDOR vulnerability demo).
- **/admin/documents**, **/admin/security**: Trang admin (cần is_admin): danh sách document, security dashboard (alerts, blocked IPs, login stats).
- **/debug**: API JSON: status DB, detection_initialized, recent logs.
- **/api/detection/status**: Trạng thái detection system.
- **/api/detection/simulate**: POST simulate attack (rapid_bruteforce, credential_stuffing) để test detection.
- **/api/detection/blocked**: Danh sách IP bị block.

Database dùng qua `web_app.models` (hoặc `AppDatabase` trong code): check_login, log_login, block_ip, get_user_documents, get_all_users, get_all_documents, log_alert, get_connection.

---

## 3. Detection integration (`detection_integration.py`)

- **initialize_detection_system(debug_enabled=False)**: Khởi tạo global `SimpleAggregator`, `RuleLoader`, `RuleEvaluator` (từ detection_system.rule_based). Gọi một lần khi app start (trong routes khi import).
- **process_login_event(username, src_ip, success, user_agent=None, debug=False)**:  
  Tạo event dict (timestamp, username, src_ip, success, ...), gọi `RuleEvaluator.evaluate_realtime(aggregator, event)`. Nếu `Decision.matched`: trả về should_block, block_reason, alert_message, detection_type, rule_id, action, confidence, debug_info. Có thể block IP qua `Database.block_ip`.
- **get_blocked_ips()**, **is_ip_blocked(ip_address)**: Đọc từ bảng blocked_ips trong DB.

Nếu import detection_system thất bại thì dùng fallback (aggregator/evaluator rỗng, không block).

---

## 4. Models (`models.py`)

- Kết nối MySQL (theo config): users, documents, auth_logs, alerts, blocked_ips.
- **Check login**: check_login(username, password) — có thể dùng query dễ bị SQL injection (demo).
- **Log**: log_login(username, src_ip, success, user_agent), log_alert(...).
- **Block**: block_ip(ip_address, reason, duration_hours), get_blocked_ips(), và logic kiểm tra blocked trong routes.
- **Documents**: get_user_documents(user_id), get_all_documents(); get_all_users() cho admin.

---

## 5. Templates & Static

- **templates/**: login.html, dashboard.html, document.html, admin_documents.html, admin_security.html, hidden_file.html, 404.html, 500.html.
- **static/css/style.css**: Style chung cho giao diện.

---

## 6. Demo accounts & đặc điểm

- Demo: user1 / pass123; admin / admin123.
- Một số user đặc biệt (SPECIAL_USERS) có hidden file trong dashboard.
- IDOR: truy cập document theo doc_id không kiểm tra user_id.
- SQL injection: login form dùng query dễ inject (cố ý cho mục đích demo).
