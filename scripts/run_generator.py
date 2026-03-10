#!/home/group3/eaglepro/scripts/run_generator_fixed.py
"""
EaglePro Data Generator - FIXED VERSION
Sửa lỗi tham số và tối ưu hóa
"""

import sys
import os
from datetime import datetime, timedelta
import json
import random

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from data_generator.core.generator import SimpleDataGenerator
    from data_generator.core.config import DB_CONFIG
except ImportError as e:
    print(f" Import error: {e}")
    print("Make sure you have run: pip install -e .")
    sys.exit(1)

def generate_simple_dataset():
    """Tạo dataset đơn giản với generator chính - FIXED PARAMETERS"""
    
    print(" EaglePro Data Generator - Simple Version")
    print("=" * 60)
    
    # 1. Khởi tạo generator
    generator = SimpleDataGenerator(seed=42)
    
    # 2. Tạo dữ liệu training (7 ngày)
    print("\n Generating TRAINING data (7 days)...")
    train_start = datetime.now() - timedelta(days=7)
    
    train_events = generator.generate(
        seed=42,
        start_ts=train_start,
        duration=168,  # 7 ngày × 24 giờ = 168 giờ
        volume_per_minute=2,
        attack_mix=0.15,
        scenario="mixed"
    )
    
    print(f" Generated {len(train_events)} training events")
    
    # 3. Tạo dữ liệu testing (24 giờ)
    print("\n Generating TESTING data (24 hours)...")
    test_start = datetime.now() - timedelta(hours=24)
    
    test_events = generator.generate(
        seed=123,
        start_ts=test_start,
        duration=24,  # 24 giờ
        volume_per_minute=3,
        attack_mix=0.20,  # 20% attacks cho testing
        scenario="mixed"
    )
    
    print(f" Generated {len(test_events)} testing events")
    
    # 4. Kết hợp và sắp xếp theo thời gian
    all_events = train_events + test_events
    all_events.sort(key=lambda x: x['timestamp'])
    
    return all_events, train_events, test_events

def save_to_database_fixed(events):
    """Lưu events vào database - FIXED VERSION"""
    try:
        import pymysql
        
        print(f"\n Saving {len(events)} events to database...")
        
        conn = pymysql.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # SQL insert statement
        insert_sql = """
        INSERT INTO auth_logs 
        (username, src_ip, success, user_agent, request_path, 
         http_method, http_status, failure_reason, request_duration_ms,
         geo, device_fingerprint, is_attack, attack_type, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        batch_size = 1000
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            
            batch_data = []
            for event in batch:
                batch_data.append((
                    event['username'],
                    event['src_ip'],
                    event['success'],
                    event.get('user_agent', ''),
                    event.get('request_path', '/login'),
                    event.get('http_method', 'POST'),
                    event.get('http_status', 200 if event['success'] else 401),
                    event.get('failure_reason', None),
                    event.get('request_duration_ms', 100),
                    event.get('geo', 'US'),
                    event.get('device_fingerprint', ''),
                    event.get('is_attack', False),
                    event.get('attack_type', None),
                    event['timestamp']
                ))
            
            cursor.executemany(insert_sql, batch_data)
            conn.commit()
            print(f"  → Saved batch {i//batch_size + 1}: {len(batch)} events")
        
        conn.close()
        print(f" Successfully saved {len(events)} events to database")
        
    except ImportError:
        print("  pymysql not installed, skipping database insert")
    except Exception as e:
        print(f" Database error: {e}")
        import traceback
        traceback.print_exc()

def print_statistics(events, name="Dataset"):
    """In thống kê chi tiết"""
    total = len(events)
    if total == 0:
        print(f" {name}: No events")
        return
    
    attacks = sum(1 for e in events if e.get('is_attack', False))
    normal = total - attacks
    
    print(f"\n {name} STATISTICS:")
    print("=" * 50)
    print(f"Total events: {total}")
    print(f"Normal events: {normal} ({normal/total*100:.1f}%)")
    print(f"Attack events: {attacks} ({attacks/total*100:.1f}%)")
    
    # Attack type breakdown
    attack_types = {}
    for e in events:
        if e.get('is_attack') and e.get('attack_type'):
            atype = e['attack_type']
            attack_types[atype] = attack_types.get(atype, 0) + 1
    
    if attack_types:
        print("\nAttack types:")
        for atype, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {atype}: {count} ({count/attacks*100:.1f}%)")
    
    # Success rates
    attack_success = sum(1 for e in events if e.get('is_attack') and e.get('success'))
    normal_success = sum(1 for e in events if not e.get('is_attack') and e.get('success'))
    
    if attacks > 0:
        attack_success_rate = attack_success / attacks * 100
    else:
        attack_success_rate = 0
    
    if normal > 0:
        normal_success_rate = normal_success / normal * 100
    else:
        normal_success_rate = 0
    
    print(f"\nSuccess rates:")
    print(f"  - Normal: {normal_success}/{normal} = {normal_success_rate:.1f}%")
    print(f"  - Attacks: {attack_success}/{attacks} = {attack_success_rate:.1f}%")
    
    # IP analysis for rule testing
    print("\n RULE TESTING ANALYSIS:")
    print("-" * 30)
    
    # Tìm IPs có nhiều failed attempts
    from collections import defaultdict
    ip_failed = defaultdict(int)
    
    for e in events:
        if not e.get('success') and e.get('src_ip'):
            ip_failed[e['src_ip']] += 1
    
    # Top 10 IPs với nhiều failed attempts nhất
    top_ips = sorted(ip_failed.items(), key=lambda x: x[1], reverse=True)[:10]
    
    for ip, count in top_ips:
        status = " WOULD TRIGGER RULE" if count >= 100 else " below threshold"
        print(f"  IP {ip}: {count} failed attempts - {status}")

def main():
    """Hàm chính - đơn giản, chỉ làm một việc"""
    
    print(" EAGLEPRO DATA GENERATOR - ONE CLICK VERSION")
    print("=" * 60)
    
    # Tạo dữ liệu
    all_events, train_events, test_events = generate_simple_dataset()
    
    # In thống kê
    print_statistics(all_events, "COMBINED DATASET")
    print_statistics(train_events, "TRAINING SET")
    print_statistics(test_events, "TESTING SET")
    
    # Lưu vào database
    save_to_database_fixed(all_events)
    
    # Tùy chọn lưu file
    try:
        save_files = input("\n Save to files as well? (y/N): ").strip().lower()
        if save_files == 'y':
            # Tạo thư mục
            os.makedirs('data', exist_ok=True)
            
            # Lưu training data
            train_file = 'data/train_events.ndjson'
            with open(train_file, 'w', encoding='utf-8') as f:
                for event in train_events:
                    f.write(json.dumps(event) + '\n')
            print(f" Saved {len(train_events)} events to {train_file}")
            
            # Lưu testing data
            test_file = 'data/test_events.ndjson'
            with open(test_file, 'w', encoding='utf-8') as f:
                for event in test_events:
                    f.write(json.dumps(event) + '\n')
            print(f" Saved {len(test_events)} events to {test_file}")
            
            # Lưu all data
            all_file = 'data/all_events.ndjson'
            with open(all_file, 'w', encoding='utf-8') as f:
                for event in all_events:
                    f.write(json.dumps(event) + '\n')
            print(f" Saved {len(all_events)} events to {all_file}")
    except:
        pass  # Bỏ qua nếu không muốn lưu file
    
    print("\n GENERATION COMPLETE!")
    print("=" * 60)
    print(" Data has been saved to database table 'auth_logs'")
    print("\n Next steps:")
    print("1. Check database: SELECT COUNT(*) FROM auth_logs;")
    print("2. Run rule-based detection")
    print("3. Train ML model")
    print("\n Quick test query:")
    print("   SELECT attack_type, COUNT(*) FROM auth_logs WHERE is_attack=1 GROUP BY attack_type;")

if __name__ == "__main__":
    main()