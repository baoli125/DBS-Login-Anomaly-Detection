#!/usr/bin/env python3
"""
EaglePro Log Extractor
Trích xuất và hiển thị logs từ database
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_app.models_enhanced import Database
from datetime import datetime, timedelta
import json

def extract_auth_logs(limit=50):
    """Trích xuất authentication logs"""
    print(" AUTHENTICATION LOGS")
    print("=" * 80)

    logs = Database.get_recent_login_attempts(limit=limit)
    if not logs:
        print(" No authentication logs found")
        return

    for log in logs:
        timestamp = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        status = " SUCCESS" if log['success'] else " FAILED"
        print(f"[{timestamp}] {log['username']} @ {log['src_ip']} - {status}")
        if log['user_agent']:
            print(f"  User-Agent: {log['user_agent']}")
        print(f"  Method: {log['http_method']} {log['request_path']} -> {log['http_status']}")
        print("-" * 40)

def extract_alerts(limit=50):
    """Trích xuất security alerts"""
    print("\n SECURITY ALERTS")
    print("=" * 80)

    alerts = Database.get_alerts(limit=limit)
    if not alerts:
        print(" No alerts found")
        return

    for alert in alerts:
        timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] ALERT #{alert['id']}")
        print(f"  User: {alert['username']} | IP: {alert['src_ip']}")
        print(f"  Type: {alert['alert_type']} | Attack: {alert['attack_type']}")
        print(f"  Rule: {alert['rule_name']} | Detection: {alert['detection_type']}")
        print(f"  Confidence: {alert['confidence']:.2f} | Risk Score: {alert['risk_score']:.2f}")
        print(f"  Action: {alert['action']} | Status: {alert['status']}")
        if alert['features']:
            features = json.loads(alert['features'])
            print(f"  Features: {features}")
        print("-" * 40)

def extract_blocked_ips():
    """Trích xuất blocked IPs"""
    print("\n BLOCKED IPs")
    print("=" * 80)

    # Giả sử có hàm get_blocked_ips, nhưng từ code không thấy, có thể query trực tiếp
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT 20")
        blocked = cursor.fetchall()
        conn.close()

        if not blocked:
            print(" No blocked IPs found")
            return

        for ip in blocked:
            blocked_at = ip['blocked_at'].strftime('%Y-%m-%d %H:%M:%S')
            expires_at = ip['expires_at'].strftime('%Y-%m-%d %H:%M:%S') if ip['expires_at'] else 'Never'
            print(f"[{blocked_at}] {ip['ip_address']} - Expires: {expires_at}")
            print(f"  Reason: {ip['reason']} | Alert ID: {ip['alert_id']}")
            print("-" * 40)
    except Exception as e:
        print(f" Error extracting blocked IPs: {e}")

def main():
    print(" EaglePro Log Extractor")
    print("=" * 80)

    try:
        # Test connection
        conn = Database.get_connection()
        conn.close()
        print(" Database connection successful")
    except Exception as e:
        print(f" Database connection failed: {e}")
        print(" Please ensure MySQL server is running and database is set up")
        return

    # Extract logs
    extract_auth_logs()
    extract_alerts()
    extract_blocked_ips()

    print("\n Log extraction completed!")

if __name__ == "__main__":
    main()