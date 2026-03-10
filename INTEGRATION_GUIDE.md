"""
Complete Integration Guide - EaglePro Web Application
Includes Detection System (Rule-Based + ML + Agent + Classification)

FOLDER STRUCTURE:
web_app/
├── app_complete.py              ← Main Flask application
├── routes_complete.py           ← Complete routes with detection integration
├── models_enhanced.py           ← Enhanced database models
├── integration.py               ← Detection system integration layer
├── setup_db.py                  ← Database schema setup
├── config.py                    ← Configuration
├── templates/                   ← HTML templates
│   ├── base.html
│   ├── entry.html
│   ├── home.html
│   ├── systems.html
│   ├── notes.html
│   ├── experiments.html
│   ├── index.html
│   ├── archive.html
│   └── admin_dashboard.html     ← New admin dashboard
└── static/
    └── style.css

scripts/
└── test_complete_system.py      ← Comprehensive test suite

INTEGRATION COMPONENTS:
1. Detection System:
   - Rule-Based Detection (aggregator, evaluator, loader)
   - ML Classification (binary/multiclass models)
   - Response Agent (decision engine)
   - Event Classifier (attack type prediction)

2. Web Routes:
   - Authentication (/login, /logout, /dashboard)
   - API endpoints (/api/alerts, /api/blocked_ips, /api/stats/*)
   - Admin dashboard (/admin)
   - Content management (/systems, /notes, /experiments, /archive, /index)

3. Database Integration:
   - auth_logs (authentication attempts)
   - alerts (security alerts)
   - blocked_ips (temporary IP blocks)
   - ml_models (ML model registry)
   - detection_events (detection history)

4. Detection Pipeline:
   Request → Pre-check IP blocked?
           → Feature extraction
           → Rule evaluation → Generate alert
           → ML inference → Generate alert
           → Agent decision → Block/Throttle/Allow
           → Log to database
           → Return decision to user

TEST CATEGORIES:
 2.1 - Basic Authentication (non-attack)
 2.2 - Brute Force Detection (rapid failed attempts)
 2.3 - Credential Stuffing (multiple users from same IP)
 2.4 - Distributed Attack (multiple IPs targeting account)
 2.5 - ML Classification (attack type detection)
 2.6 - Agent Decision Logic (risk-based actions)
 4.1 - Threshold Boundaries (alert trigger thresholds)
 4.2 - Cooldown/Circuit Breaker (IP block duration)
 4.3 - Database Persistence (alert storage)
 4.4 - Invalid Input Handling (injection/XSS defense)
"""

QUICK_START_GUIDE = """
QUICK START GUIDE
================

1. SETUP DATABASE
   cd web_app
   python setup_db.py

   This will:
   - Create 'eaglepro' database
   - Create 8 tables (users, auth_logs, alerts, blocked_ips, etc.)
   - Insert sample data (admin user, test users, ML models)

2. VERIFY CONFIG
   Check config.py for database connection settings:
   - DB_HOST: localhost
   - DB_PORT: 3306
   - DB_USER: root
   - DB_PASSWORD: your_password
   - DB_NAME: eaglepro

3. BACKUP OLD FILES (OPTIONAL)
   # If you have existing web_app files:
   cp routes.py routes.py.backup
   cp models.py models.py.backup
   cp app.py app.py.backup

4. USE NEW INTEGRATION FILES
   Replace old files with complete versions:
   - app.py → app_complete.py (or rename)
   - routes.py → routes_complete.py (or rename)
   - models.py → models_enhanced.py (or import from it)
   
   Option A: Direct replacement
   cp app_complete.py app.py
   cp routes_complete.py routes.py
   
   Option B: Rename and update imports
   Update imports in app_complete.py/routes_complete.py

5. RUN TESTS
   cd ../scripts
   python test_complete_system.py

   This will execute:
   - 6 complete detection flow tests
   - 4 edge case tests
   - 10 total test scenarios
   - Report detection statistics

6. START WEB APPLICATION
   cd ../web_app
   python app_complete.py

   Application will be available at:
   - Web UI: http://localhost:5000
   - Login: http://localhost:5000/login
   - Admin: http://localhost:5000/admin (after login as admin)

7. TEST LOGIN SCENARIOS
   Sample Users:
   - admin / admin123 (admin user)
   - user1 / password1 (regular user)
   - user2 / password2 (regular user)

   Security Tests:
   - Enter correct credentials → Normal flow
   - Enter wrong password 3+ times → Brute force detection
   - Try SQL injection: admin'; DROP--
   - Try XSS: user\" onload=\"alert(1)
"""

DETECTION_PIPELINE = """
DETECTION PIPELINE FLOW
=======================

1. REQUEST RECEIVED
   User attempts login with username/password

2. PRE-CHECKS
   ├─ Is IP blocked? → Return 429 (Too Many Requests)
   └─ Is in blacklist? → Return 403 (Forbidden)

3. DETECTION PROCESSING
   ├─ Rule-Based Detection
   │  ├─ R-BRUTE-RAPID: 5+ failed attempts in 60 seconds
   │  ├─ R-CRED-STUFF: 5+ different users from same IP
   │  └─ R-DIST-ATTACK: 5+ IPs targeting same account
   │
   ├─ ML Detection (if not ruled out)
   │  ├─ Extract features (IP, user agent, etc.)
   │  └─ Binary classifier: Attack or Normal?
   │
   └─ Classification (if attack detected)
       └─ Multiclass classifier: Attack type?

4. AGENT DECISION
   ├─ Risk Score = 0.6 * (rule_confidence) + 0.4 * (ml_score)
   │
   ├─ risk_score > 0.85 → Action: BLOCK (IP blocked 1 hour)
   ├─ risk_score > 0.60 → Action: THROTTLE (require 2FA)
   ├─ risk_score > 0.40 → Action: CHALLENGE (verify)
   └─ risk_score ≤ 0.40 → Action: ALLOW

5. CREDENTIALS CHECK
   ├─ If action = BLOCK → Reject (don't check credentials)
   ├─ If action = ALLOW → Check credentials normally
   └─ Else → Prompt for 2FA

6. LOGGING & PERSISTENCE
   ├─ Log authentication attempt (auth_logs)
   ├─ Create alert if detected (alerts)
   ├─ Block IP if action = BLOCK (blocked_ips)
   ├─ Record detection event (detection_events)
   └─ Update statistics

7. RESPONSE
   ├─ Success: Set session, redirect to dashboard
   ├─ Failed: Return error message
   └─ Blocked: Return block notice

DURATION: ~150-300ms total (most time in ML inference)
"""

API_ENDPOINTS = """
API ENDPOINTS
=============

AUTHENTICATION:
  POST   /login               - User login
  GET    /logout              - User logout
  GET    /dashboard           - User dashboard

ALERTS:
  GET    /api/alerts                  - List all alerts
  GET    /api/alerts/<id>             - Get alert details
  PUT    /api/alerts/<id>/status      - Update alert status

BLOCKED IPS:
  GET    /api/blocked_ips             - List blocked IPs
  DELETE /api/blocked_ips/<ip>        - Unblock an IP

STATISTICS:
  GET    /api/stats/detection         - Detection stats
  GET    /api/stats/alerts            - Alert statistics by type

DETECTION STATUS:
  GET    /api/detection/status        - System status

PAGES:
  GET    /systems                     - Systems page
  GET    /notes                       - Notes page
  GET    /experiments                 - Experiments page
  GET    /archive                     - Archive page
  GET    /index                       - Index page

REFERENCE:
  - All API requests require authentication (session)
  - Admin endpoints require is_admin=True
  - Returns JSON with data or error message
"""

DATABASE_SCHEMA = """
DATABASE SCHEMA
===============

users:
  id (PK)
  username (UNIQUE)
  password
  is_admin
  created_at

auth_logs:
  id (PK)
  username
  src_ip (INDEX)
  success
  user_agent
  request_path
  http_method
  http_status
  timestamp (INDEX)

alerts:
  id (PK)
  username
  src_ip (INDEX)
  alert_type (rule_based | ml | combined)
  attack_type
  rule_name
  detection_type
  confidence
  risk_score
  action
  features (JSON)
  status (active | resolved | false_positive)
  resolved_at
  resolution_notes
  timestamp (INDEX)

blocked_ips:
  src_ip (PK)
  blocked_at
  block_until (INDEX)
  reason
  source_alert_id (FK → alerts)

ml_models:
  id (PK)
  model_name
  model_path
  version
  status (active | inactive)
  registered_at
  last_used

detection_events:
  id (PK)
  username
  src_ip (INDEX)
  event_type
  rule_triggered
  ml_score
  decision
  action_taken
  features (JSON)
  timestamp (INDEX)
"""

TROUBLESHOOTING = """
TROUBLESHOOTING
===============

1. DATABASE CONNECTION FAILED
   Error: "Can't connect to MySQL server"
   
   Solutions:
   a) Check MySQL is running:
      sudo service mysql status
   b) Verify connection settings in config.py
   c) Test connection:
      mysql -u root -p -h localhost
   d) Create database manually:
      mysql -u root -p < schema.sql

2. DETECTION SYSTEM NOT INITIALIZING
   Error: "Some detection modules not available"
   
   Solutions:
   a) Check all backend modules are installed
   b) Verify imports in integration.py
   c) Check models/ folder has all .joblib files
   d) Run: python -c "from agent.core.agent import ResponseAgent"

3. MODELS NOT LOADING
   Error: "Failed to load ML models"
   
   Solutions:
   a) Check models/ folder structure
   b) Verify model paths in config.py
   c) Test individually:
      python -c "import joblib; joblib.load('models/binary_model.joblib')"

4. TEMPLATES NOT FOUND
   Error: "TemplateNotFound: entry.html"
   
   Solutions:
   a) Verify templates/ folder exists
   b) Check all HTML files are present
   c) Verify Flask template_folder path

5. SESSION NOT WORKING
   Error: "User session lost after login"
   
   Solutions:
   a) Check app.config['SECRET_KEY'] is set
   b) Verify browser cookies are enabled
   c) Check session timeout settings

6. ALERTS NOT APPEARING IN DASHBOARD
   Error: "No alerts displayed after detection"
   
   Solutions:
   a) Trigger alerts manually via test script
   b) Check database has alerts table
   c) Verify alerts are being inserted:
      SELECT * FROM alerts;
   d) Check alert status is 'active'
"""

PERFORMANCE_NOTES = """
PERFORMANCE NOTES
=================

Detection Latency:
- Rule-based: ~10-20ms
- ML inference: ~50-100ms  
- Total pipeline: ~150-300ms

Optimization Tips:
1. ML model caching - models loaded once at startup
2. Rule aggregator - sliding window algorithm for efficiency
3. Database indexes on: src_ip, timestamp, alert_type
4. Connection pooling for database

Scalability:
- Horizontal: Multiple web app instances with shared database
- Vertical: Increase ML inference batch size
- Caching: Redis for blocked IP list

Monitoring:
- Check detection_stats endpoint regularly
- Monitor alert queue size
- Track ML model accuracy over time
- Review false positive rates
"""

if __name__ == '__main__':
    print(QUICK_START_GUIDE)
    print("\n" + "="*60 + "\n")
    print(DETECTION_PIPELINE)
    print("\n" + "="*60 + "\n")
    print(API_ENDPOINTS)
    print("\n" + "="*60 + "\n")
    print(DATABASE_SCHEMA)
    print("\n" + "="*60 + "\n")
    print(TROUBLESHOOTING)
    print("\n" + "="*60 + "\n")
    print(PERFORMANCE_NOTES)
