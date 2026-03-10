# EaglePro Web App - Database & Setup Guide

##  Vấn Đề Được Phát Hiện & Sửa

### Column Name Mismatch Error
- **Lỗi**: `Unknown column 'block_until' in 'where clause'`
- **Nguyên Nhân**: Database schema sử dụng `blocked_until` nhưng code đang dùng `block_until`
- **Sửa**:  Tất cả SQL queries đã sửa thành `blocked_until`

### Files Được Sửa:
1.  `web_app/models_enhanced.py` - 3 SQL queries
2.  `web_app/generate_admin_template.py` - JavaScript function

---

##  Hướng Dẫn Setup Đầy Đủ

### Step 1: Khởi Động MySQL Server

#### Trên Windows:
```bash
# Option A: Services Control Panel
# Tìm MySQL service (MySQL80, MySQL57, etc) trong services.msc

# Option B: WSL / Command Line
wsl sudo systemctl start mysql

# Option C: Kiểm tra MySQL running
netstat -an | find ":3306"
# Hoặc
netstat -an | grep 3306
```

#### Kiểm Tra MySQL Chạy:
```bash
# Thử kết nối MySQL
mysql -u bao -pBaoli125@ -e "SELECT 1"
# Nếu thấy dòng chứa "1" => MySQL chạy OK
```

### Step 2: Setup Database Schema

Chạy script này (sau khi MySQL chạy):
```bash
cd e:\share_Ubuntu\eaglepro
python scripts/setup_database.py
```

**Output Expected:**
```
============================================================
  EaglePro Database Schema Setup
============================================================
 Database 'eaglepro' created
 Table 'users' created
 Table 'documents' created
 Table 'hidden_files' created
 Table 'auth_logs' created
 Table 'alerts' created
 Table 'blocked_ips' created  <-- CÓ CỘT: blocked_until 
 Table 'detection_events' created
 Table 'ml_models' created
 Insert sample data: user1, user2, admin
============================================================
```

### Step 3: Khởi Động Web App

```bash
cd e:\share_Ubuntu\eaglepro
python scripts/run_web.py
```

**Output Expected:**
```
[INFO] Database connection successful 
[INFO] Detection system initialized
[INFO] 16 unique routes registered
[INFO] Running on http://0.0.0.0:5000
```

### Step 4: Test Web App

Mở browser:
- URL: `http://localhost:5000`
- Login: `user1 / password123`
- Bạn sẽ thấy Dashboard

---

##  Kiểm Tra Database Schema

### Xem cấu trúc bảng blocked_ips:

```bash
mysql -u bao -pBaoli125@ eaglepro -e "DESCRIBE blocked_ips"
```

**Output Expected:**
```
| Field        | Type        | Null | Key |
|--------------|-------------|------|-----|
| id           | int         | NO   | PRI |
| ip_address   | varchar(45) | NO   | MUL |
| blocked_at   | timestamp   | NO   | MUL |
| blocked_until| timestamp   | YES  | MUL | <--  Quan trọng
| reason       | varchar(200)| YES  |     |
| alert_id     | int         | YES  | MUL |
```

### Xem dữ liệu mẫu:

```bash
mysql -u bao -pBaoli125@ eaglepro -e "SELECT * FROM users"
mysql -u bao -pBaoli125@ eaglepro -e "SELECT * FROM blocked_ips"
mysql -u bao -pBaoli125@ eaglepro -e "SELECT * FROM auth_logs LIMIT 5"
```

---

##  Troubleshooting

### Lỗi: "Can't connect to MySQL server"
-  **Fix**: Khởi động MySQL server (xem Step 1)
-  Kiểm tra credentials: user=`bao`, password=`Baoli125@`, host=`localhost`

### Lỗi: "Unknown column 'blocked_until'"
-  **Fix**: Chạy `python scripts/setup_database.py` để tạo schema mới
-  Có thể cần `DROP DATABASE eaglepro; CREATE ...` nếu cũ

### Lỗi: "Unknown column 'block_until'" (cũ)
-  **FIXED**: Tất cả code đã sửa sang `blocked_until`
-  Re-run setup database script

### Route errors / Duplicate endpoints
-  Tất cả đã fix
-  16 unique routes registered

---

##  Demo Attacks (Sau khi web app chạy successfully)

```bash
# Terminal 1: Run web app
python scripts/run_web.py

# Terminal 2: Simulate attacks
python scripts/attack_simulator.py

# Terminal 3: View logs
python scripts/extract_logs.py
```

---

##  Verification Checklist

- [ ] MySQL server running
- [ ] `setup_database.py` executed successfully
- [ ] Web app starts without errors
- [ ] Can access http://localhost:5000
- [ ] Login with user1/password123 works
- [ ] Dashboard loads with stats
- [ ] No "Unknown column" errors in logs

---

##  Database Schema Changes

### blocked_ips table structure:
```sql
CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NULL,           --  Key column for duration
    reason VARCHAR(200),
    alert_id INT,
    INDEX idx_ip_address (ip_address),
    INDEX idx_blocked_until (blocked_until)
)
```

### How IP blocking works:
1. User triggers alert (brute force, credential stuffing, etc)
2. `block_ip()` creates entry with `blocked_until = now + duration`
3. Each login checks: `WHERE blocked_until > NOW()`
4. If expired: check passes, IP can login again

---

##  Related Scripts

- `scripts/setup_database.py` - Create database schema
- `scripts/run_web.py` - Start Flask web app
- `scripts/attack_simulator.py` - Test detection system
- `scripts/extract_logs.py` - View audit logs
- `web_app/models_enhanced.py` - Database abstraction layer
- `web_app/integration.py` - Detection pipeline integration
