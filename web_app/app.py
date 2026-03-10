"""
Main Flask application - SIMPLIFIED VERSION
"""

import sys
import os

# Thêm paths
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, current_dir)
sys.path.insert(0, parent_dir)

from flask import Flask, render_template
from web_app.config import Config
from web_app.routes import main_bp

def create_app():
    """Tạo Flask application"""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Load config
    app.config.from_object(Config)
    
    # Secret key cho session
    app.secret_key = app.config.get('SECRET_KEY', 'eaglepro-demo-key-2024')
    
    # Đăng ký blueprint
    app.register_blueprint(main_bp)
    
    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('500.html'), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    print("\n" + "="*60)
    print(" EAGLEPRO SECURITY DEMO")
    print("="*60)
    print(" Features:")
    print("  • Web Application với IDOR Vulnerability")
    print("  • SQL Injection Vulnerability (cố ý)")
    print("  • Rule-Based Detection System (3 core rules)")
    print("  • Real-time Attack Detection")
    print("  • Admin Security Dashboard")
    print("="*60)
    print(" Server running at: http://localhost:5000")
    print(" Demo account: user1 / pass123")
    print(" Admin account: admin / admin123")
    print("="*60 + "\n")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)