"""
Cấu hình cho web app - SIMPLIFIED VERSION
"""

import os
from dotenv import load_dotenv

# Load environment variables
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()

class Config:
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = int(os.getenv('DB_PORT', 3306))
    DB_USER = os.getenv('DB_USER', 'bao')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'Baoli125@')
    DB_NAME = os.getenv('DB_NAME', 'eaglepro')
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'eaglepro-demo-key-2024')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # Detection System
    RULE_ENABLED = os.getenv('RULE_ENABLED', 'True').lower() == 'true'
    ML_ENABLED = os.getenv('ML_ENABLED', 'False').lower() == 'true'
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RULES_DIR = os.path.join(BASE_DIR, 'detection_system', 'rule_based', 'rules')
    
    # Timezone
    TIMEZONE = 'Asia/Ho_Chi_Minh'