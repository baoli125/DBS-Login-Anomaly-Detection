"""
Database models - VERSION WITH DEBUG
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config import Config
except ImportError:
    from web_app.config import Config

import pymysql
from pymysql.cursors import DictCursor
from datetime import datetime
import traceback

class Database:
    @staticmethod
    def get_connection():
        """Kết nối database với debug"""
        try:
            print(f"\n DATABASE CONNECTION ATTEMPT:")
            print(f"   Host: {Config.DB_HOST}:{Config.DB_PORT}")
            print(f"   User: {Config.DB_USER}")
            print(f"   Database: {Config.DB_NAME}")
            
            conn = pymysql.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                db=Config.DB_NAME,
                cursorclass=DictCursor,
                charset='utf8mb4',
                autocommit=True
            )
            
            print(" Database connection successful")
            return conn
            
        except Exception as e:
            print(f" DATABASE CONNECTION ERROR: {e}")
            print(f"   Check if MySQL is running: sudo systemctl status mysql")
            print(f"   Check if database exists: mysql -u {Config.DB_USER} -p{Config.DB_PASSWORD} -e 'SHOW DATABASES;'")
            raise
    
    @staticmethod
    def check_login(username, password):
        """Kiểm tra đăng nhập - VỚI DEBUG CHI TIẾT"""
        print(f"\n LOGIN ATTEMPT DEBUG:")
        print(f"   Username: '{username}'")
        print(f"   Password: '{password}'")
        
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            #  CỐ Ý VULNERABLE - SQL INJECTION DEMO
            # Tạo query với SQL injection
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            
            print(f"\n SQL QUERY EXECUTED:")
            print(f"   {query}")
            
            # Thực thi query
            cursor.execute(query)
            result = cursor.fetchone()
            
            print(f"\n QUERY RESULT:")
            if result:
                print(f"    FOUND USER: {result['username']} (ID: {result['id']})")
                print(f"   Is Admin: {bool(result.get('is_admin', 0))}")
            else:
                print(f"    NO USER FOUND with these credentials")
            
            # DEBUG: Kiểm tra tất cả users trong database
            cursor.execute("SELECT id, username, password FROM users LIMIT 10")
            all_users = cursor.fetchall()
            
            print(f"\n ALL USERS IN DATABASE (first 10):")
            for user in all_users:
                print(f"   ID: {user['id']}, Username: '{user['username']}', Password: '{user['password']}'")
            
            return result
            
        except Exception as e:
            print(f"\n SQL QUERY ERROR: {e}")
            print(f"   Stack trace:")
            traceback.print_exc()
            return None
            
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def log_login(username, ip_address, success, user_agent=None):
        """Ghi log đăng nhập với debug"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            sql = """
            INSERT INTO auth_logs 
            (username, src_ip, success, user_agent, request_path, http_method, http_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(sql, (
                username,
                ip_address,
                success,
                user_agent or '',
                '/login',
                'POST',
                200 if success else 401
            ))
            
            log_id = cursor.lastrowid
            print(f" LOGIN LOGGED: ID={log_id}, User='{username}', IP={ip_address}, Success={success}")
            
            return log_id
            
        except Exception as e:
            print(f" LOGGING ERROR: {e}")
            return None
            
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def check_login(username, password):
        """Kiểm tra đăng nhập - CÓ SQL INJECTION CỐ Ý (cho demo)"""
        conn = Database.get_connection()
        try:
            cursor = conn.cursor()
            #  CỐ Ý VULNERABLE - KHÔNG DÙNG Parameterized Query
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cursor.execute(query)
            return cursor.fetchone()
        finally:
            conn.close()
    
    @staticmethod
    def get_user_documents(user_id):
        """Lấy documents của user"""
        conn = Database.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM documents WHERE user_id = %s ORDER BY created_date DESC',
                (user_id,)
            )
            return cursor.fetchall()
        finally:
            conn.close()
    
    @staticmethod
    def get_all_users():
        """Lấy tất cả users (cho admin panel)"""
        conn = Database.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, full_name, avatar, department, position FROM users')
            return cursor.fetchall()
        finally:
            conn.close()
    
    @staticmethod
    def get_all_documents():
        """Lấy tất cả documents (cho admin panel)"""
        conn = Database.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM documents')
            return cursor.fetchall()
        finally:
            conn.close()
    
    @staticmethod
    def log_alert(alert_data):
        """Ghi alert vào database"""
        conn = Database.get_connection()
        try:
            cursor = conn.cursor()
            sql = """
            INSERT INTO alerts 
            (alert_type, entity_type, entity_value, detection_time, 
             attack_type, rule_name, action_taken, features)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                alert_data.get('alert_type', 'rule'),
                alert_data.get('entity_type', 'ip'),
                alert_data.get('entity_value', 'unknown'),
                alert_data.get('detection_time', datetime.now()),
                alert_data.get('attack_type'),
                alert_data.get('rule_name'),
                alert_data.get('action_taken', 'alert'),
                alert_data.get('features', '{}')
            ))
            return cursor.lastrowid
        finally:
            conn.close()
    
    @staticmethod
    def block_ip(ip_address, reason, duration_hours=1, alert_id=None):
        """Block IP trong database"""
        conn = Database.get_connection()
        try:
            cursor = conn.cursor()
            blocked_until = datetime.now().timestamp() + (duration_hours * 3600)
            
            sql = """
            INSERT INTO blocked_ips 
            (ip_address, blocked_at, blocked_until, reason, alert_id)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                ip_address,
                datetime.now(),
                datetime.fromtimestamp(blocked_until),
                reason,
                alert_id
            ))
            return cursor.lastrowid
        finally:
            conn.close()