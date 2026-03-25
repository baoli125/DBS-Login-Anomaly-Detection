#!/usr/bin/env python3
"""
EaglePro Web Application Trình chạy
Khởi động web app với đầy đủ tính năng phát hiện
"""

import sys
import os

# Thêm thư mục gốc và web_app vào path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
web_app_dir = os.path.join(project_root, 'web_app')
sys.path.insert(0, project_root)
sys.path.insert(0, web_app_dir)

import argparse
import os
from flask import Flask, session
import logging
from datetime import timedelta

# Ensure Unicode output even on cp1252 Windows terminals
os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

# Import routes
from web_app.routes_complete import bp

logger = logging.getLogger('EaglePro')

def setup_logging(debug: bool = False):
    """Khởi tạo logging levels based on mode."""
    log_level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    # Suppress verbose request logs unless debugging
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    # Keep database logs quiet
    db_logger = logging.getLogger('Database')
    db_logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    if debug:
        logger.debug('Debug mode: verbose logging enabled')

def create_app():
    """Create and configure Flask application"""

    logger.info(" Initializing EaglePro Web Application")

    app = Flask(__name__,
                template_folder=os.path.join(web_app_dir, 'templates'),
                static_folder=os.path.join(web_app_dir, 'static'))

    # Cấu hình
    app.config['SECRET_KEY'] = 'eaglepro-secret-key-2024'
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

    # Register blueprint
    app.register_blueprint(bp)

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not found'}, 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal error: {error}")
        return {'error': 'Internal server error'}, 500

    @app.before_request
    def before_request():
        session.permanent = True

    logger.info(" Flask application configured")

    return app

def main():
    """Chính function to run the web application"""
    parser = argparse.ArgumentParser(description='Run EaglePro web application')
    parser.add_argument('--debug', action='store_true', help='Enable verbose debug logs')
    args = parser.parse_args()

    setup_logging(args.debug)

    # Control phát hiện-system debug for consistency
    import os
    os.environ['DETECTION_DEBUG'] = 'true' if args.debug else 'false'

    try:
        app = create_app()

        # Run Flask app
        print("Starting Flask application on http://localhost:5000")
        print("Dashboard: http://localhost:5000/dashboard")
        print("Admin: http://localhost:5000/admin")
        print("============================================================")

        app.run(
            host='0.0.0.0',
            port=5000,
            debug=args.debug,
            use_reloader=args.debug,
            use_debugger=args.debug,
            threaded=True,
        )
    except KeyboardInterrupt:
        # Minimal output when stopping
        print("\nApplication stopped by user")
    except Exception as e:
        logger.error(f" Failed to start application: {e}")
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())