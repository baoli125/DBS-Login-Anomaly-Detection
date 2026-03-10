import sys
import os

from web_app.models import Database
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime
from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify
import traceback

# ==================== FIXED IMPORTS ====================
# Import models MỘT LẦN DUY NHẤT ở đầu file
try:
    # Try absolute import first
    from web_app.models import Database as AppDatabase
    print(" Imported Database from web_app.models")
except ImportError:
    try:
        # Fallback: relative import
        from .models import Database as AppDatabase
        print(" Imported Database from .models")
    except ImportError as e:
        print(f" CRITICAL: Cannot import Database: {e}")
        # Emergency fallback
        class AppDatabase:
            @staticmethod
            def check_login(u, p): 
                return None
            @staticmethod 
            def log_login(*args, **kwargs): 
                pass
            @staticmethod
            def get_user_documents(*args, **kwargs):
                return []
            @staticmethod
            def get_all_users():
                return []
            @staticmethod
            def get_all_documents():
                return []
            @staticmethod
            def log_alert(*args, **kwargs):
                pass
            @staticmethod
            def block_ip(*args, **kwargs):
                pass
            @staticmethod
            def get_connection():
                return None

# Import detection integration
try:
    from web_app.detection_integration import (
        initialize_detection_system,
        process_login_event,
        get_blocked_ips,
        is_ip_blocked
    )
except ImportError:
    try:
        from .detection_integration import (
            initialize_detection_system,
            process_login_event,
            get_blocked_ips,
            is_ip_blocked
        )
    except ImportError as e:
        print(f" Cannot import detection_integration: {e}")
        # Fallback functions
        def initialize_detection_system(*args, **kwargs):
            print("  Detection system not available")
            return False
        def process_login_event(*args, **kwargs):
            return {'should_block': False}
        def get_blocked_ips():
            return []
        def is_ip_blocked(ip):
            return False

# Tạo blueprint
main_bp = Blueprint('main', __name__)

# Danh sách user đặc biệt
SPECIAL_USERS = ['HusThien_IA', 'Collie_Min', 'LazyBeo']

# Khởi tạo detection system - SỬA: dùng biến global
print("\n" + "="*60)
print(" EAGLEPRO SECURITY SYSTEM STARTING...")
print("="*60)

detection_initialized = False
try:
    detection_initialized = initialize_detection_system(debug_enabled=False)
except Exception as e:
    print(f" Detection system initialization failed: {e}")

print(f" Detection System: {' READY' if detection_initialized else ' DISABLED'}")
print("="*60 + "\n")

# ==================== HELPER FUNCTIONS ====================
def create_login_event(username: str, ip_address: str, success: bool, user_agent: str = None) -> dict:
    """Tạo event dictionary cho login"""
    return {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'src_ip': ip_address,
        'success': success,
        'user_agent': user_agent or request.headers.get('User-Agent', ''),
        'request_path': '/login',
        'http_method': 'POST',
        'http_status': 200 if success else 401,
        'failure_reason': None if success else 'Invalid credentials'
    }

# ==================== MAIN ROUTES ====================

@main_bp.route('/')
def index():
    """Trang login"""
    return render_template('login.html')

@main_bp.route('/', methods=['POST'])
def login():
    """Xử lý login - INTEGRATED với Detection System"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('Username and password required!', 'error')
        return render_template('login.html')
    
    # Thu thập thông tin
    src_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    try:
        # 1. KIỂM TRA IP BLOCK (từ database)
        if is_ip_blocked(src_ip):
            flash(f' IP {src_ip} has been blocked due to suspicious activity!', 'error')
            AppDatabase.log_login(username, src_ip, False, user_agent)  # SỬA: dùng AppDatabase
            return render_template('login.html')
        
        # 2. KIỂM TRA với Detection System (TRƯỚC khi check login)
        detection_result = process_login_event(username, src_ip, False, user_agent, debug=False)
        
        if detection_result.get('should_block'):
            # Block IP trong database
            AppDatabase.block_ip(  # SỬA: dùng AppDatabase
                ip_address=src_ip,
                reason=detection_result.get('block_reason', 'Rule triggered'),
                duration_hours=1
            )
            
            flash(f' Access blocked: {detection_result.get("block_reason")}', 'error')
            AppDatabase.log_login(username, src_ip, False, user_agent)  # SỬA
            return render_template('login.html')
        
        # 3. HIỂN THỊ ALERT nếu có
        if detection_result.get('alert_message'):
            flash(detection_result['alert_message'], 'warning')
        
        # 4. KIỂM TRA ĐĂNG NHẬP (vulnerable SQL injection)
        user = AppDatabase.check_login(username, password)  # SỬA: dùng AppDatabase
        
        if user:
            # LOGIN THÀNH CÔNG
            success = True
            
            # Ghi log thành công
            AppDatabase.log_login(username, src_ip, True, user_agent)  # SỬA
            
            # Set session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['avatar'] = user.get('avatar', 'default.png')
            session['is_admin'] = bool(user.get('is_admin', 0))
            
            # Process successful login với detection system
            success_detection = process_login_event(username, src_ip, True, user_agent)
            
            # Nếu có alert từ successful login
            if success_detection.get('alert_message'):
                flash(success_detection['alert_message'], 'warning')
            
            return redirect('/dashboard')
        
        else:
            # LOGIN THẤT BẠI
            success = False
            
            # Ghi log thất bại
            AppDatabase.log_login(username, src_ip, False, user_agent)  # SỬA
            
            # Process failed login với detection system
            # (đã xử lý ở trên, nhưng cần cập nhật metrics)
            _ = process_login_event(username, src_ip, False, user_agent)
            
            # Kiểm tra lại xem có nên block không (sau khi cập nhật metrics)
            second_check = process_login_event(username, src_ip, False, user_agent)
            
            if second_check.get('should_block'):
                AppDatabase.block_ip(  # SỬA
                    ip_address=src_ip,
                    reason=second_check.get('block_reason', 'Too many failed attempts'),
                    duration_hours=1
                )
                flash(' Your IP has been blocked due to suspicious activity!', 'error')
            
            flash('Invalid username or password!', 'error')
            return render_template('login.html')
            
    except Exception as e:
        print(f"Login error: {e}")
        traceback.print_exc()
        flash('System error', 'error')
        return render_template('login.html')

@main_bp.route('/dashboard')
def dashboard():
    """Dashboard chính"""
    if 'user_id' not in session:
        return redirect('/')
    
    try:
        user_docs = AppDatabase.get_user_documents(session['user_id'])  # SỬA
        has_hidden_file = session['username'] in SPECIAL_USERS
        
        # Lấy thêm dữ liệu cho admin panel
        all_users = []
        all_docs = []
        if session.get('is_admin'):
            all_users = AppDatabase.get_all_users()  # SỬA
            all_docs = AppDatabase.get_all_documents()  # SỬA
        
        return render_template(
            'dashboard.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'default.png'),
            user_docs=user_docs,
            all_users=all_users,
            all_docs=all_docs,
            total_docs=len(all_docs) if session.get('is_admin') else len(user_docs),
            is_admin=session.get('is_admin', False),
            has_hidden_file=has_hidden_file,
            special_users=SPECIAL_USERS
        )
    except Exception as e:
        print(f"Dashboard error: {e}")
        traceback.print_exc()
        return f"Dashboard error: {e}", 500

@main_bp.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect('/')

@main_bp.route('/debug')
def debug():
    """Debug endpoint"""
    try:
        conn = AppDatabase.get_connection()  # SỬA
        cursor = conn.cursor()
        
        # Basic stats
        cursor.execute('SELECT COUNT(*) as count FROM auth_logs')
        log_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM users')
        user_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM alerts')
        alert_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM blocked_ips WHERE blocked_until > NOW()')
        blocked_count = cursor.fetchone()['count']
        
        # Recent logs
        cursor.execute('SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT 10')
        recent_logs = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'status': 'online',
            'database': {
                'users': user_count,
                'auth_logs': log_count,
                'alerts': alert_count,
                'blocked_ips': blocked_count
            },
            'detection_system': {
                'initialized': detection_initialized,
                'timestamp': datetime.now().isoformat()
            },
            'recent_logs': recent_logs
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ADMIN ROUTES ====================

@main_bp.route('/admin/documents')
def admin_documents():
    """Admin view all documents"""
    if 'user_id' not in session:
        return redirect('/')
    
    if not session.get('is_admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect('/dashboard')
    
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT d.*, u.username, u.full_name, u.avatar 
            FROM documents d 
            JOIN users u ON d.user_id = u.id 
            ORDER BY d.created_date DESC
        ''')
        all_documents = cursor.fetchall()
        
        conn.close()
        
        return render_template(
            'admin_documents.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'admin_avatar.png'),
            all_documents=all_documents,
            total_documents=len(all_documents)
        )
    except Exception as e:
        print(f"Admin documents error: {e}")
        return f"Admin documents error: {e}", 500

@main_bp.route('/admin/security')
def admin_security():
    """Admin security dashboard"""
    if 'user_id' not in session:
        return redirect('/')
    
    if not session.get('is_admin'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect('/dashboard')
    
    try:
        # Lấy blocked IPs
        blocked_ips = get_blocked_ips()
        
        # Lấy alerts từ database - SỬA: dùng AppDatabase
        conn = AppDatabase.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alerts ORDER BY detection_time DESC LIMIT 50')
        alerts = cursor.fetchall()
        
        cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE resolved = FALSE')
        active_alerts = cursor.fetchone()['count']
        
        # Login stats
        cursor.execute('''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total_logins,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_logins,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_logins
            FROM auth_logs 
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        ''')
        login_stats = cursor.fetchall()
        
        conn.close()
        
        return render_template(
            'admin_security.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'admin_avatar.png'),
            alerts=alerts,
            active_alerts=active_alerts,
            blocked_ips=blocked_ips,
            login_stats=login_stats,
            detection_initialized=detection_initialized,
            special_users=SPECIAL_USERS
        )
    except Exception as e:
        print(f"Admin security error: {e}")
        return f"Admin security error: {e}", 500

# ==================== DOCUMENT ROUTES (IDOR VULNERABILITY) ====================

@main_bp.route('/document/<int:doc_id>')
def view_document(doc_id):
    """View document - CÓ IDOR VULNERABILITY"""
    if 'user_id' not in session:
        return redirect('/')
    
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        # Lấy document - KHÔNG kiểm tra ownership (IDOR)
        cursor.execute('''
            SELECT d.*, u.username, u.full_name 
            FROM documents d 
            JOIN users u ON d.user_id = u.id 
            WHERE d.id = %s
        ''', (doc_id,))
        doc = cursor.fetchone()
        
        if not doc:
            return "Document not found", 404
        
        #  VULNERABILITY: KHÔNG kiểm tra quyền truy cập
        is_vulnerable = doc['user_id'] != session['user_id']
        
        # Navigation (chỉ cho documents của user hiện tại)
        cursor.execute('SELECT id FROM documents WHERE user_id = %s ORDER BY id', (session['user_id'],))
        user_docs = cursor.fetchall()
        
        conn.close()
        
        # Tìm previous/next
        user_doc_ids = [d['id'] for d in user_docs]
        prev_doc_id = None
        next_doc_id = None
        
        if user_doc_ids:
            try:
                current_index = user_doc_ids.index(doc_id)
                if current_index > 0:
                    prev_doc_id = user_doc_ids[current_index - 1]
                if current_index < len(user_doc_ids) - 1:
                    next_doc_id = user_doc_ids[current_index + 1]
            except ValueError:
                pass
        
        return render_template(
            'document.html', 
            doc=dict(doc),
            current_user_avatar=session.get('avatar', 'default.png'),
            username=session['username'],
            user_id=session['user_id'],
            is_admin=session.get('is_admin', False),
            is_vulnerable=is_vulnerable,
            prev_doc_id=prev_doc_id,
            next_doc_id=next_doc_id
        )
    except Exception as e:
        print(f"Document error: {e}")
        return f"Error: {e}", 500

# ==================== DETECTION SYSTEM API ====================

@main_bp.route('/api/detection/status', methods=['GET'])
def detection_status():
    """API lấy trạng thái detection system"""
    return jsonify({
        'success': True,
        'detection_initialized': detection_initialized,
        'timestamp': datetime.now().isoformat()
    })

@main_bp.route('/api/detection/simulate', methods=['POST'])
def simulate_attack():
    """API simulate attack để test detection"""
    if not detection_initialized:
        return jsonify({'success': False, 'error': 'Detection system not initialized'})
    
    try:
        from .detection_integration import process_login_event
        
        data = request.json
        attack_type = data.get('attack_type', 'rapid_bruteforce')
        ip = data.get('ip', '192.168.1.100')
        username = data.get('username', 'attacker')
        attempts = data.get('attempts', 25)
        
        results = []
        
        if attack_type == 'rapid_bruteforce':
            # Simulate rapid attacks
            for i in range(attempts):
                result = process_login_event(username, ip, False, f"Simulated Attack {i}")
                results.append(result)
                
                if result.get('should_block'):
                    break
        
        elif attack_type == 'credential_stuffing':
            # Simulate credential stuffing (1 IP, nhiều users)
            for i in range(attempts):
                user = f"victim{i}"
                result = process_login_event(user, ip, False, f"Credential Stuffing")
                results.append(result)
        
        # Tổng kết
        blocked = any(r.get('should_block') for r in results)
        alerts = sum(1 for r in results if r.get('alert_message'))
        
        return jsonify({
            'success': True,
            'attack_type': attack_type,
            'attempts': attempts,
            'blocked': blocked,
            'alerts': alerts,
            'ip': ip,
            'results_summary': {
                'first_result': results[0] if results else None,
                'last_result': results[-1] if results else None
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@main_bp.route('/api/detection/blocked', methods=['GET'])
def get_blocked():
    """API lấy danh sách IP bị block"""
    blocked_ips = get_blocked_ips()
    return jsonify({
        'success': True,
        'blocked_ips': blocked_ips,
        'count': len(blocked_ips)
    })

# ==================== ERROR HANDLERS ====================

@main_bp.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@main_bp.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500