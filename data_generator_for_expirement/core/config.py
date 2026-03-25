#data_generator/cấu hình.py
"""
Cấu hình cho tạo dữ liệu
Đơn giản, cứng mã để dễ debug
"""

import os
from datetime import datetime, timedelta

# Kết nối cơ sở dữ liệu (giống web app)
DB_CONFIG = {
    'host': 'localhost',
    'port': 3306,
    'user': 'bao',
    'password': 'Baoli125@',
    'database': 'eaglepro'
}

# Thư mục đầu ra
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
TRAIN_DIR = os.path.join(DATA_DIR, 'train')
TEST_DIR = os.path.join(DATA_DIR, 'test')

# Cài đặt thời gian
NOW = datetime.now()
DEFAULT_START = NOW - timedelta(days=7)
DEFAULT_END = NOW

# Danh sách user (từ database hoặc cứng mã)
USERS = [
    {'id': 1, 'username': 'admin', 'is_admin': True},
    {'id': 2, 'username': 'user1', 'is_admin': False},
    {'id': 3, 'username': 'HusThien_IA', 'is_admin': False},
    {'id': 4, 'username': 'Collie_Min', 'is_admin': False},
    {'id': 5, 'username': 'LazyBeo', 'is_admin': False},
    {'id': 6, 'username': 'employee1', 'is_admin': False},
    {'id': 7, 'username': 'employee2', 'is_admin': False},
    {'id': 8, 'username': 'manager1', 'is_admin': False},
    {'id': 9, 'username': 'auditor1', 'is_admin': False},
    {'id': 10, 'username': 'guest1', 'is_admin': False},
]

# IP phổ biến
NORMAL_IPS = [
    '192.168.1.100', '192.168.1.101', '192.168.1.102',
    '10.0.0.10', '10.0.0.11', '10.0.0.12',
    '172.16.0.100', '172.16.0.101'
]

ATTACK_IPS = [
    '185.165.190.10', '185.165.190.11', '185.165.190.12',
    '45.155.205.50', '45.155.205.51', '45.155.205.52',
    '198.98.60.90', '198.98.60.91', '198.98.60.92'
]

# User agents
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
]

# Quốc gia cho dữ liệu địa lý
COUNTRIES = ['US', 'VN', 'CN', 'JP', 'KR', 'GB', 'DE', 'FR', 'CA', 'AU']

# Định dạng đầu ra (khớp schema auth_logs)
OUTPUT_FIELDS = [
    'timestamp', 'username', 'src_ip', 'success', 
    'user_agent', 'request_path', 'http_method', 'http_status',
    'failure_reason', 'request_duration_ms', 'geo', 'device_fingerprint',
    'is_attack', 'attack_type'
]