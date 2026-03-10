#!/usr/bin/env python3
"""
EaglePro Database Schema Setup
CHỈ tạo database và bảng - KHÔNG chèn dữ liệu
"""

import os
import pymysql
import sys

class DatabaseSchemaSetup:
    def __init__(self):
        # Database connection settings
        self.db_host = 'localhost'
        self.db_port = 3306
        self.db_user = 'bao'
        self.db_password = 'Baoli125@'
        self.db_name = 'eaglepro'
    
    def get_connection(self, use_database=False):
        """Kết nối MySQL"""
        try:
            conn_params = {
                'host': self.db_host,
                'port': self.db_port,
                'user': self.db_user,
                'password': self.db_password,
                'charset': 'utf8mb4',
                'cursorclass': pymysql.cursors.DictCursor
            }
            
            if use_database:
                conn_params['database'] = self.db_name
            
            conn = pymysql.connect(**conn_params)
            print(" Connected to MySQL")
            return conn
        except Exception as e:
            print(f" Connection failed: {e}")
            sys.exit(1)
    
    def create_database(self, conn):
        """Tạo database nếu chưa tồn tại"""
        with conn.cursor() as cursor:
            cursor.execute(f"DROP DATABASE IF EXISTS {self.db_name}")
            cursor.execute(f"""
                CREATE DATABASE {self.db_name} 
                CHARACTER SET utf8mb4 
                COLLATE utf8mb4_unicode_ci
            """)
            conn.commit()
            print(f" Database '{self.db_name}' created")
    
    def create_tables(self, conn):
        """Tạo tất cả bảng (KHÔNG có dữ liệu)"""
        with conn.cursor() as cursor:
            cursor.execute(f"USE {self.db_name}")
            
            # 1. Bảng users
            cursor.execute("""
                CREATE TABLE users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(100) NOT NULL,
                    full_name VARCHAR(100),
                    avatar VARCHAR(100) DEFAULT 'default.png',
                    is_admin BOOLEAN DEFAULT FALSE,
                    department VARCHAR(50),
                    position VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_username (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'users' created")
            
            # 2. Bảng documents
            cursor.execute("""
                CREATE TABLE documents (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    title VARCHAR(200) NOT NULL,
                    content TEXT,
                    doc_type VARCHAR(50),
                    sensitivity VARCHAR(20) DEFAULT 'Low',
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    file_size VARCHAR(20),
                    file_format VARCHAR(20),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    INDEX idx_user_id (user_id),
                    INDEX idx_doc_type (doc_type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'documents' created")
            
            # 3. Bảng hidden_files
            cursor.execute("""
                CREATE TABLE hidden_files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    title VARCHAR(200) DEFAULT ' My Secret File',
                    content TEXT,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE KEY unique_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'hidden_files' created")
            
            # 4. Bảng auth_logs (cho detection system)
            cursor.execute("""
                CREATE TABLE auth_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    src_ip VARCHAR(45) NOT NULL,
                    success BOOLEAN NOT NULL,
                    user_agent TEXT,
                    request_path VARCHAR(100),
                    http_method VARCHAR(10),
                    http_status INT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    failure_reason VARCHAR(100) DEFAULT NULL,
                    request_duration_ms INT DEFAULT 0,
                    geo VARCHAR(10) DEFAULT NULL,
                    device_fingerprint VARCHAR(100) DEFAULT NULL,
                    is_attack BOOLEAN DEFAULT FALSE,
                    attack_type VARCHAR(50) DEFAULT NULL,
                    INDEX idx_is_attack(is_attack),
                    INDEX idx_attack_type(attack_type),
                    INDEX idx_username (username),
                    INDEX idx_src_ip (src_ip),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_success (success),
                    INDEX idx_ip_time (src_ip, timestamp),
                    INDEX idx_user_time (username, timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'auth_logs' created")
            
            # 5. Bảng alerts
            cursor.execute("""
                CREATE TABLE alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    alert_type VARCHAR(50) NOT NULL,
                    entity_type VARCHAR(20) NOT NULL,
                    entity_value VARCHAR(100) NOT NULL,
                    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    score FLOAT,
                    confidence FLOAT,
                    attack_type VARCHAR(50),
                    rule_name VARCHAR(100),
                    features JSON,
                    action_taken VARCHAR(50),
                    action_details TEXT,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMP NULL,
                    INDEX idx_alert_type (alert_type),
                    INDEX idx_detection_time (detection_time),
                    INDEX idx_entity (entity_type, entity_value),
                    INDEX idx_attack_type (attack_type),
                    INDEX idx_resolved (resolved)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'alerts' created")
            
            # 6. Bảng blocked_ips
            cursor.execute("""
                CREATE TABLE blocked_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    blocked_until TIMESTAMP NULL,
                    reason VARCHAR(200),
                    alert_id INT,
                    INDEX idx_ip_address (ip_address),
                    INDEX idx_blocked_until (blocked_until),
                    INDEX idx_blocked_at (blocked_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'blocked_ips' created")
            
            # 7. Bảng feature_cache
            cursor.execute("""
                CREATE TABLE feature_cache (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    entity_type VARCHAR(20) NOT NULL,
                    entity_value VARCHAR(100) NOT NULL,
                    feature_name VARCHAR(100) NOT NULL,
                    feature_value FLOAT,
                    window_start TIMESTAMP NOT NULL,
                    window_end TIMESTAMP NOT NULL,
                    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_feature (entity_type, entity_value, feature_name, window_start),
                    INDEX idx_entity (entity_type, entity_value),
                    INDEX idx_feature (feature_name),
                    INDEX idx_window (window_start, window_end)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'feature_cache' created")
            
            # 8. Bảng ml_models
            cursor.execute("""
                CREATE TABLE ml_models (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_name VARCHAR(100) NOT NULL,
                    model_version VARCHAR(50) NOT NULL,
                    model_type VARCHAR(50) NOT NULL,
                    model_data LONGBLOB,
                    features_list JSON,
                    accuracy FLOAT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    UNIQUE KEY unique_model (model_name, model_version),
                    INDEX idx_model_type (model_type),
                    INDEX idx_is_active (is_active)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            print(" Table 'ml_models' created")
            
            conn.commit()

    def load_sample_data(self, conn):
        """Load sample data from database/sample_data.sql"""
        sample_sql_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'sample_data.sql')
        print(f" Loading sample data from: {sample_sql_path}")

        if not os.path.exists(sample_sql_path):
            print(" Sample data file not found, skipping sample data load.")
            return

        with open(sample_sql_path, 'r', encoding='utf-8') as f:
            sql_commands = f.read()

        with conn.cursor() as cursor:
            for statement in sql_commands.split(';'):
                stmt = statement.strip()
                if stmt:
                    cursor.execute(stmt)
        conn.commit()
        print(" Sample data loaded")

    def verify_schema(self, conn):
        """Xác nhận schema đã được tạo"""
        print("\n Verifying database schema...")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT DATABASE()")
            db_name = cursor.fetchone()['DATABASE()']
            print(f"Database: {db_name}")
            
            cursor.execute("SHOW TABLES")
            tables = [row[f'Tables_in_{db_name}'] for row in cursor.fetchall()]
            
            print("\n Tables created:")
            for table in sorted(tables):
                cursor.execute(f"DESCRIBE {table}")
                columns = [row['Field'] for row in cursor.fetchall()]
                print(f"   {table} ({len(columns)} columns)")
    
    def run(self):
        """Thực thi tạo schema"""
        print("=" * 60)
        print("  EaglePro Database Schema Setup")
        print("=" * 60)
        print(f"Database: {self.db_name}")
        print(f"User: {self.db_user}")
        print("=" * 60)
        
        # Kết nối (không dùng database)
        conn = self.get_connection(use_database=False)
        
        # Tạo database
        self.create_database(conn)
        conn.close()
        
        # Kết nối lại với database
        conn = self.get_connection(use_database=True)
        
        # Tạo bảng
        self.create_tables(conn)

        # Nạp sample data
        self.load_sample_data(conn)
        
        # Xác nhận
        self.verify_schema(conn)
        
        conn.close()
        
        print("\n" + "=" * 60)
        print(" Database schema created successfully!")
        print("=" * 60)
        print("\n 8 tables created:")
        print("   1. users          - Người dùng hệ thống")
        print("   2. documents      - Tài liệu người dùng")
        print("   3. hidden_files   - File ẩn đặc biệt")
        print("   4. auth_logs      - Logs đăng nhập (cho detection)")
        print("   5. alerts         - Cảnh báo phát hiện")
        print("   6. blocked_ips    - IP bị chặn")
        print("   7. feature_cache  - Cache tính năng real-time")
        print("   8. ml_models      - ML models lưu trữ")
        print("\n Ready for web app và detection system!")

if __name__ == "__main__":
    setup = DatabaseSchemaSetup()
    setup.run()