"""
Complete Flask Application - EaglePro Web App
Integrated with Detection System (Rule-Based + ML + Agent + Classification)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, session
import logging
from datetime import timedelta

# Import routes
from routes_complete import bp

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('EaglePro')

# Create Flask app
def create_app():
    """Create and configure Flask application"""
    
    logger.info(" Initializing EaglePro Web Application")
    
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Configuration
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

# Create app instance
app = create_app()

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info(" EAGLEPRO WEB APPLICATION STARTING")
    logger.info("=" * 60)
    
    try:
        # Run Flask app
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=True,
            use_debugger=True
        )
    except Exception as e:
        logger.error(f" Failed to start application: {e}")
        import traceback
        traceback.print_exc()
