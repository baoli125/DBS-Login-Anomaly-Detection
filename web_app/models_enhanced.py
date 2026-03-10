"""
Enhanced Database Models - Full Integration
Hỗ trợ: Authentication, Alerts, Blocked IPs, Detection History
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
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger('Database')

class Database:
    """Enhanced database class with full schema support"""
    
    @staticmethod
    def get_connection():
        """Get database connection"""
        try:
            logger.debug(f" Connecting to {Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}")
            
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
            
            logger.debug(" Database connection successful")
            return conn
            
        except Exception as e:
            logger.error(f" Database connection failed: {e}")
            raise
    
    # ==================== AUTHENTICATION ====================
    
    @staticmethod
    def check_login(username: str, password: str):
        """Check login credentials"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # Parameterized query (correct way, but demo shows injection vulnerability)
            cursor.execute(
                'SELECT id, username, password, is_admin FROM users WHERE username = %s AND password = %s',
                (username, password)
            )
            
            result = cursor.fetchone()
            logger.info(f" Login check: {username} - {' Success' if result else ' Failed'}")
            return result
            
        except Exception as e:
            logger.error(f"Login check error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_user_by_id(user_id: int):
        """Get user by ID"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT id, username, is_admin FROM users WHERE id = %s',
                (user_id,)
            )
            
            return cursor.fetchone()
            
        except Exception as e:
            logger.error(f"Get user error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    # ==================== AUTHENTICATION LOGGING ====================
    
    @staticmethod
    def log_login(username: str, src_ip: str, success: bool, user_agent: str = None, 
                  request_path: str = '/login', http_method: str = 'POST'):
        """Log authentication attempt"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            sql = """
            INSERT INTO auth_logs 
            (username, src_ip, success, user_agent, request_path, http_method, http_status, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            http_status = 200 if success else 401
            
            cursor.execute(sql, (
                username, src_ip, success, user_agent or '', 
                request_path, http_method, http_status, datetime.now()
            ))
            
            log_id = cursor.lastrowid
            logger.info(f" Auth logged: ID={log_id}, User={username}, IP={src_ip}, Status={'' if success else ''}")
            
            return log_id
            
        except Exception as e:
            logger.error(f"Login logging error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_recent_login_attempts(username: str = None, limit: int = 100):
        """Get recent login attempts"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            if username:
                cursor.execute(
                    'SELECT * FROM auth_logs WHERE username = %s ORDER BY timestamp DESC LIMIT %s',
                    (username, limit)
                )
            else:
                cursor.execute(
                    'SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT %s',
                    (limit,)
                )
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get login attempts error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    # ==================== ALERTS ====================
    
    @staticmethod
    def log_alert(alert_data: dict):
        """Log security alert"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()

            # map to schema with entity_type/entity_value (no username/src_ip columns)
            entity_type = alert_data.get('entity_type')
            entity_value = alert_data.get('entity_value')
            if not entity_type or not entity_value:
                if alert_data.get('username'):
                    entity_type = 'user'
                    entity_value = alert_data.get('username')
                elif alert_data.get('src_ip'):
                    entity_type = 'ip'
                    entity_value = alert_data.get('src_ip')
                else:
                    entity_type = 'unknown'
                    entity_value = 'unknown'

            sql = """
            INSERT INTO alerts 
            (alert_type, entity_type, entity_value, detection_time,
             score, confidence, attack_type, rule_name, action_taken, action_details, features)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """

            # map store: ml score in `score`, keep risk_score in features for debugging
            alert_features = alert_data.get('features', {}) or {}
            alert_features['risk_score'] = alert_data.get('risk_score', 0.0)

            cursor.execute(sql, (
                alert_data.get('alert_type', 'rule_based'),
                entity_type,
                entity_value,
                alert_data.get('detection_time', datetime.now()),
                alert_data.get('score', alert_data.get('ml_score', 0.0)),
                alert_data.get('confidence', 0.0),
                alert_data.get('attack_type', 'unknown'),
                alert_data.get('rule_name', None),
                alert_data.get('action', 'allow'),
                alert_data.get('action_details', ''),
                json.dumps(alert_features)
            ))

            alert_id = cursor.lastrowid
            logger.info(f" Alert logged: ID={alert_id}, Type={alert_data.get('alert_type')}")

            return alert_id

        except Exception as e:
            logger.error(f"Alert logging error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_alerts(limit: int = 100, offset: int = 0, status: str = None):
        """Get alerts with pagination"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            if status:
                cursor.execute(
                    'SELECT * FROM alerts WHERE status = %s ORDER BY timestamp DESC LIMIT %s OFFSET %s',
                    (status, limit, offset)
                )
            else:
                cursor.execute(
                    'SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s OFFSET %s',
                    (limit, offset)
                )
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get alerts error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_alert_by_id(alert_id: int):
        """Get alert by ID"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM alerts WHERE id = %s', (alert_id,))
            
            return cursor.fetchone()
            
        except Exception as e:
            logger.error(f"Get alert error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def update_alert_status(alert_id: int, status: str, resolution_notes: str = None):
        """Update alert status"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            sql = 'UPDATE alerts SET status = %s, resolved_at = %s'
            params = [status, datetime.now()]
            
            if resolution_notes:
                sql += ', resolution_notes = %s'
                params.append(resolution_notes)
            
            sql += ' WHERE id = %s'
            params.append(alert_id)
            
            cursor.execute(sql, params)
            
            logger.info(f" Alert {alert_id} updated to {status}")
            
            return True
            
        except Exception as e:
            logger.error(f"Update alert error: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_alert_stats(days: int = 7):
        """Get alert statistics"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            since = datetime.now() - timedelta(days=days)
            
            # Total alerts
            cursor.execute(
                'SELECT COUNT(*) as count FROM alerts WHERE timestamp >= %s',
                (since,)
            )
            total = cursor.fetchone()['count']
            
            # By alert type
            cursor.execute(
                'SELECT alert_type, COUNT(*) as count FROM alerts WHERE timestamp >= %s GROUP BY alert_type',
                (since,)
            )
            by_type = cursor.fetchall()
            
            # By detection type
            cursor.execute(
                'SELECT detection_type, COUNT(*) as count FROM alerts WHERE timestamp >= %s GROUP BY detection_type',
                (since,)
            )
            by_detection = cursor.fetchall()
            
            # By action
            cursor.execute(
                'SELECT action, COUNT(*) as count FROM alerts WHERE timestamp >= %s GROUP BY action',
                (since,)
            )
            by_action = cursor.fetchall()
            
            return {
                'total': total,
                'by_type': by_type,
                'by_detection': by_detection,
                'by_action': by_action,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Get alert stats error: {e}")
            return {}
        finally:
            if conn:
                conn.close()
    
    # ==================== BLOCKED IPS ====================
    
    @staticmethod
    def block_ip(src_ip: str, block_duration: int = 3600, reason: str = None, alert_id: int = None):
        """Add IP to blocklist"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            block_until = datetime.now() + timedelta(seconds=block_duration)
            
            sql = """
            INSERT INTO blocked_ips 
            (ip_address, blocked_at, blocked_until, reason, alert_id)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            blocked_until = VALUES(blocked_until),
            reason = VALUES(reason)
            """
            
            cursor.execute(sql, (
                src_ip, datetime.now(), block_until, reason or 'Security alert', alert_id
            ))
            
            logger.info(f" IP blocked: {src_ip} until {block_until}")
            
            return True
            
        except Exception as e:
            logger.error(f"Block IP error: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def is_ip_blocked(src_ip: str):
        """Check if IP is blocked"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT * FROM blocked_ips WHERE ip_address = %s AND blocked_until > %s',
                (src_ip, datetime.now())
            )
            
            blocked = cursor.fetchone()
            
            if blocked:
                logger.warning(f" Access blocked for {src_ip} until {blocked['blocked_until']}")
            
            return blocked is not None
            
        except Exception as e:
            logger.error(f"Check blocked IP error: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_blocked_ips(limit: int = 100):
        """Get list of blocked IPs"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT * FROM blocked_ips WHERE blocked_until > %s ORDER BY blocked_at DESC LIMIT %s',
                (datetime.now(), limit)
            )
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get blocked IPs error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def unblock_ip(src_ip: str):
        """Remove IP from blocklist"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM blocked_ips WHERE ip_address = %s', (src_ip,))
            
            logger.info(f" IP unblocked: {src_ip}")
            
            return True
            
        except Exception as e:
            logger.error(f"Unblock IP error: {e}")
            return False
        finally:
            if conn:
                conn.close()
    
    # ==================== ML MODELS ====================
    
    @staticmethod
    def register_ml_model(model_name: str, model_path: str, version: str, status: str = 'active'):
        """Register ML model in database"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            sql = """
            INSERT INTO ml_models 
            (model_name, model_path, version, status, registered_at)
            VALUES (%s, %s, %s, %s, %s)
            """
            
            cursor.execute(sql, (model_name, model_path, version, status, datetime.now()))
            
            model_id = cursor.lastrowid
            logger.info(f" ML model registered: {model_name} (v{version})")
            
            return model_id
            
        except Exception as e:
            logger.error(f"Register ML model error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_active_ml_models():
        """Get active ML models"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM ml_models WHERE status = "active"')
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get ML models error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    # ==================== DETECTION HISTORY ====================
    
    @staticmethod
    def log_detection_event(event_data: dict):
        """Log detection event for analysis"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            sql = """
            INSERT INTO detection_events
            (username, src_ip, event_type, rule_triggered, ml_score, decision, 
             action_taken, features, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(sql, (
                event_data.get('username', 'unknown'),
                event_data.get('src_ip', '0.0.0.0'),
                event_data.get('event_type', 'login'),
                event_data.get('rule_triggered', None),
                event_data.get('ml_score', 0.0),
                event_data.get('decision', 'allow'),
                event_data.get('action_taken', 'none'),
                json.dumps(event_data.get('features', {})),
                event_data.get('timestamp', datetime.now())
            ))
            
            return cursor.lastrowid
            
        except Exception as e:
            logger.error(f"Log detection event error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_detection_events(src_ip: str = None, username: str = None, limit: int = 100):
        """Get detection events"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            sql = 'SELECT * FROM detection_events WHERE 1=1'
            params = []
            
            if src_ip:
                sql += ' AND src_ip = %s'
                params.append(src_ip)
            
            if username:
                sql += ' AND username = %s'
                params.append(username)
            
            sql += ' ORDER BY timestamp DESC LIMIT %s'
            params.append(limit)
            
            cursor.execute(sql, params)
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get detection events error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    # ==================== DOCUMENTS & USERS ====================
    
    @staticmethod
    def get_user_documents(user_id: int):
        """Get documents for a specific user"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT * FROM documents WHERE user_id = %s ORDER BY created_date DESC',
                (user_id,)
            )
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get user documents error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_all_users(limit: int = 1000):
        """Get all users (for admin panel)"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT id, username, full_name, avatar, department, position FROM users LIMIT %s',
                (limit,)
            )
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get all users error: {e}")
            return []
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def get_all_documents(limit: int = 1000):
        """Get all documents (for admin panel)"""
        conn = None
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT * FROM documents ORDER BY created_date DESC LIMIT %s',
                (limit,)
            )
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Get all documents error: {e}")
            return []
        finally:
            if conn:
                conn.close()

