"""
Complete Web App Routes - Full Integration
Tích hợp: Authentication + Detection System + Admin Dashboard
"""

import os
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime
import logging

# Import database and detection system
from models_enhanced import Database
from integration import (
    initialize_detection_system, process_login_event, 
    is_ip_blocked, get_active_alerts, get_blocked_ips, 
    get_detection_stats, resolve_alert, DETECTION_AVAILABLE
)

logger = logging.getLogger('Routes')

# Create blueprint
bp = Blueprint('main', __name__)

# ==================== CONSTANTS ====================

SPECIAL_USERS = ['HusThien_IA', 'Collie_Min', 'LazyBeo']

# ==================== INITIALIZATION ====================

# Initialize detection system at startup
DETECTION_INITIALIZED = False
DETECTION_DEBUG = os.getenv('DETECTION_DEBUG', 'false').lower() in ('1', 'true', 'yes')
try:
    if initialize_detection_system(debug_enabled=DETECTION_DEBUG):
        DETECTION_INITIALIZED = True
        logger.info(" Detection system initialized")
        if DETECTION_DEBUG:
            logger.debug(" Detection debug mode enabled: verbose rule metrics and decisions")
    else:
        logger.warning("  Detection system not fully initialized")
except Exception as e:
    logger.error(f" Failed to initialize detection system: {e}")

# ==================== AUTHENTICATION ROUTES ====================

@bp.route('/', methods=['GET', 'POST'])
@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with detection integration"""
    
    if request.method == 'GET':
        return render_template('login.html')
    
    # POST request - process login
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    src_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    logger.info(f" Login attempt: {username} from {src_ip}")
    
    # ==================== SECURITY CHECKS ====================
    
    # 1. Check if IP is blocked
    if Database.is_ip_blocked(src_ip):
        logger.warning(f" Access blocked for {src_ip}")
        return jsonify({
            'success': False,
            'message': 'Your IP is temporarily blocked. Try again later.',
            'blocked': True
        }), 429
    
    # ==================== DETECTION PIPELINE ====================
    
    # 2. Process login event through detection system
    detection_result = None
    if DETECTION_AVAILABLE:
        try:
            detection_result = process_login_event(
                username=username,
                src_ip=src_ip,
                success=False,  # Assume failure until proven otherwise
                user_agent=user_agent,
                debug=True
            )
            
            if detection_result.get('detection_type') != 'none':
                logger.info(f" Detection alert: type={detection_result.get('detection_type')}, rule={detection_result.get('rule_triggered')}, action={detection_result.get('action')}, ip={src_ip}")
            else:
                logger.debug(f" Detection result: {detection_result}")
            
            # 3. Apply detection decision BEFORE checking credentials
            if detection_result.get('should_block'):
                # Log detection
                Database.log_alert({
                    'username': username,
                    'src_ip': src_ip,
                    'alert_type': detection_result.get('detection_type'),
                    'attack_type': detection_result.get('attack_type'),
                    'rule_name': detection_result.get('rule_triggered'),
                    'confidence': detection_result.get('confidence'),
                    'risk_score': detection_result.get('risk_score'),
                    'action': 'blocked'
                })
                
                # Block IP if needed
                Database.block_ip(src_ip, reason=detection_result.get('block_reason'))
                
                logger.warning(f" Blocking due to detection: {detection_result.get('block_reason')}")
                
                return jsonify({
                    'success': False,
                    'message': 'Suspicious activity detected. Access denied.',
                    'blocked': True,
                    'reason': detection_result.get('block_reason')
                }), 403
            
            # 4. Check if 2FA is required
            if detection_result.get('needs_2fa'):
                logger.info(f" 2FA required for {username}")
                # TODO: Implement 2FA flow
        
        except Exception as e:
            logger.error(f"Detection error: {e}")
            import traceback
            traceback.print_exc()
    
    # ==================== CREDENTIAL CHECK ====================
    
    # 5. Verify credentials
    user = Database.check_login(username, password)
    
    if user:
        success = True
        logger.info(f" Login successful: {username} from {src_ip}")
        if detection_result:
            detection_result['success'] = True
    else:
        success = False
        logger.warning(f" Login failed: {username} from {src_ip}")
        
        # Run detection on failed attempt
        if DETECTION_AVAILABLE and not detection_result:
            try:
                detection_result = process_login_event(
                    username=username,
                    src_ip=src_ip,
                    success=False,
                    user_agent=user_agent,
                    debug=True
                )
            except Exception as e:
                logger.error(f"Detection error on failed login: {e}")
    
    # ==================== LOGGING & PERSISTENCE ====================
    
    # 6. Log authentication attempt
    try:
        log_id = Database.log_login(
            username=username,
            src_ip=src_ip,
            success=success,
            user_agent=user_agent,
            request_path='/login',
            http_method='POST'
        )
        logger.info(f" Auth logged: ID={log_id}")
    except Exception as e:
        logger.error(f"Error logging auth: {e}")
    
    # 7. Log detection event if triggered
    if detection_result and detection_result.get('detection_type') != 'none':
        try:
            Database.log_alert({
                'username': username,
                'src_ip': src_ip,
                'alert_type': detection_result.get('detection_type'),
                'attack_type': detection_result.get('attack_type'),
                'rule_name': detection_result.get('rule_triggered'),
                'detection_type': detection_result.get('detection_type'),
                'confidence': detection_result.get('confidence'),
                'risk_score': detection_result.get('risk_score'),
                'action': detection_result.get('action'),
                'features': detection_result.get('metrics', {})
            })
        except Exception as e:
            logger.error(f"Error logging alert: {e}")

    # Result summary line (single-line overview for demo)
    final_line = (
        f"RESULT: {'SUCCESS' if success else 'FAIL'} | "
        f"user={username} | ip={src_ip} | "
        f"rule={detection_result.get('rule_triggered', 'none')} | "
        f"det_type={detection_result.get('detection_type', 'none')} | "
        f"action={detection_result.get('action', 'allow')} | "
        f"risk={detection_result.get('risk_score', 0.0):.2f}"
    )
    logger.info(final_line)
    
    # ==================== RESPONSE ====================
    
    # Determine if this is an AJAX/JSON request
    is_json_request = request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if not user:
        if is_json_request:
            return jsonify({
                'success': False,
                'message': 'Invalid username or password',
                'blocked': False
            }), 401

        # render login page for normal form submission
        from flask import flash
        flash('Invalid username or password', 'error')
        return render_template('login.html'), 401
    
    # Successful login
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = user.get('is_admin', False)

    if is_json_request:
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': url_for('main.dashboard')
        }), 200

    # redirect for normal form submission
    return redirect(url_for('main.dashboard'))

@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout"""
    session.clear()
    logger.info(f" User logged out")
    return redirect(url_for('main.login'))

@bp.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    try:
        username = session.get('username')
        user_id = session.get('user_id')
        logger.info(f" Dashboard accessed by {username}")
        
        # Fetch user documents
        user_docs = Database.get_user_documents(user_id)
        
        # Check if user has hidden file
        has_hidden_file = username in SPECIAL_USERS
        
        # Fetch admin data if user is admin
        all_users = []
        all_docs = []
        if session.get('is_admin'):
            all_users = Database.get_all_users()
            all_docs = Database.get_all_documents()
        
        return render_template(
            'dashboard.html',
            username=username,
            user_id=user_id,
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
        logger.error(f"Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return f"Dashboard error: {e}", 500

# ==================== ADMIN ROUTES ====================

@bp.route('/admin')
@bp.route('/admin/documents')
def admin_documents():
    """Admin documents dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    if not session.get('is_admin'):
        logger.warning(f"  Unauthorized admin access by {session.get('username')}")
        return redirect(url_for('main.dashboard'))
    
    try:
        all_documents = Database.get_all_documents()
        
        return render_template(
            'admin_documents.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'admin_avatar.png'),
            all_documents=all_documents,
            total_documents=len(all_documents)
        )
    except Exception as e:
        logger.error(f"Admin documents error: {e}")
        return f"Error: {e}", 500

@bp.route('/admin/security')
def admin_security():
    """Admin security dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    if not session.get('is_admin'):
        logger.warning(f"  Unauthorized admin access by {session.get('username')}")
        return redirect(url_for('main.dashboard'))
    
    try:
        recent_alerts = Database.get_alerts(limit=50)
        blocked_ips = Database.get_blocked_ips(limit=20)
        auth_logs = Database.get_recent_login_attempts(limit=50)
        
        return render_template(
            'admin_security.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'admin_avatar.png'),
            recent_alerts=recent_alerts,
            blocked_ips=blocked_ips,
            auth_logs=auth_logs
        )
    except Exception as e:
        logger.error(f"Admin security error: {e}")
        return f"Error: {e}", 500

# ==================== DOCUMENT ROUTES ====================

@bp.route('/document/<int:doc_id>')
def view_document(doc_id):
    """View a document"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM documents WHERE id = %s', (doc_id,))
        doc = cursor.fetchone()
        conn.close()
        
        if not doc:
            return render_template('404.html'), 404
        
        # Check permission
        if doc['user_id'] != session['user_id'] and not session.get('is_admin'):
            return render_template('500.html'), 403
        
        return render_template(
            'document.html',
            username=session['username'],
            user_id=session['user_id'],
            current_user_avatar=session.get('avatar', 'default.png'),
            document=doc
        )
    except Exception as e:
        logger.error(f"Document error: {e}")
        return render_template('500.html'), 500

# ==================== DETECTION SYSTEM ROUTES ====================

@bp.route('/api/detection/status')
def detection_status():
    """Get detection system status"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        stats = get_detection_stats()
        return jsonify({
            'status': 'operational' if DETECTION_INITIALIZED else 'degraded',
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Error getting detection status: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/alerts', methods=['GET'])
def get_alerts_api():
    """Get recent alerts (API endpoint)"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        alerts = Database.get_alerts(limit=limit, offset=offset)
        
        return jsonify({
            'alerts': alerts,
            'count': len(alerts),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/alerts/<int:alert_id>', methods=['GET'])
def get_alert_api(alert_id):
    """Get alert details"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        alert = Database.get_alert_by_id(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        return jsonify(alert), 200
    
    except Exception as e:
        logger.error(f"Error getting alert: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/alerts/<int:alert_id>/status', methods=['PUT'])
def update_alert_status_api(alert_id):
    """Update alert status"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        status = data.get('status', 'resolved')
        notes = data.get('notes', '')
        
        success = Database.update_alert_status(alert_id, status, notes)
        
        if success:
            return jsonify({'message': 'Alert status updated'}), 200
        else:
            return jsonify({'error': 'Failed to update alert'}), 500
    
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== BLOCKED IPS ROUTES ====================

@bp.route('/api/blocked_ips', methods=['GET'])
def get_blocked_ips_api():
    """Get list of blocked IPs"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        limit = request.args.get('limit', 100, type=int)
        ips = Database.get_blocked_ips(limit=limit)
        
        return jsonify({
            'blocked_ips': ips,
            'count': len(ips),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/blocked_ips/<ip>', methods=['DELETE'])
def unblock_ip_api(ip):
    """Unblock an IP"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        success = Database.unblock_ip(ip)
        
        if success:
            logger.info(f" IP unblocked: {ip}")
            return jsonify({'message': f'IP {ip} unblocked'}), 200
        else:
            return jsonify({'error': 'Failed to unblock IP'}), 500
    
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== DETECTION STATS ROUTES ====================

@bp.route('/api/stats/alerts', methods=['GET'])
def get_alert_stats_api():
    """Get alert statistics"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        days = request.args.get('days', 7, type=int)
        stats = Database.get_alert_stats(days=days)
        
        return jsonify({
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting alert stats: {e}")
        return jsonify({'error': str(e)}), 500

@bp.route('/api/stats/detection', methods=['GET'])
def get_detection_stats_api():
    """Get detection statistics"""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        stats = get_detection_stats()
        
        return jsonify({
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting detection stats: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== ERROR HANDLERS ====================

@bp.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404

@bp.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500
