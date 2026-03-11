#!/usr/bin/env python3
"""EaglePro Data Generator 2 - Balanced attacks for rule overfitting test"""

import sys
import os
import json
import random
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_generator.core.generator import SimpleDataGenerator
from data_generator.core.config import DB_CONFIG


def generate_normal_traffic(generator, start_ts, end_ts, total_events):
    events = []
    duration_seconds = (end_ts - start_ts).total_seconds()

    for _ in range(total_events):
        ts = start_ts + timedelta(seconds=random.uniform(0, duration_seconds))
        ev = generator.generate_event('normal', ts, is_attack=False)
        events.append(ev)
    return events


def generate_credential_stuffing(generator, start_ts, duration_minutes, total_events):
    events = []
    duration_seconds = duration_minutes * 60
    target_users = [u['username'] for u in generator.users]
    # attack from multiple IPs, moderately fast but not extreme
    for i in range(total_events):
        ts = start_ts + timedelta(seconds=random.uniform(0, duration_seconds))
        tgt = random.choice(target_users)
        fixed_ip = random.choice(generator.attack_ips)
        # 5% success to mimic compromised creds mixed with brute-force
        forced_success = random.random() < 0.05

        ev = generator.generate_event(
            'credential_stuffing',
            ts,
            is_attack=True,
            attack_type='credential_stuffing',
            targeted_user=tgt,
            fixed_ip=fixed_ip,
            force_success=forced_success
        )
        ev['is_attack'] = True
        ev['attack_type'] = 'credential_stuffing'
        events.append(ev)

    return events


def generate_rapid_bruteforce_burst(generator, start_ts, bursts):
    events = []
    # mỗi burst ~ 400 attempts trong 30s
    for i in range(bursts):
        burst_start = start_ts + timedelta(minutes=i * 10)
        burst = generator.generate_rapid_attack_fixed(burst_start, duration_seconds=30)
        for ev in burst:
            ev['is_attack'] = True
            ev['attack_type'] = 'rapid_bruteforce'
        events.extend(burst)
    return events


def generate_distributed_attacks(generator, start_ts, runs):
    events = []
    # mỗi run 10 IP x 30 attempts trong 30s = ~300 events
    for i in range(runs):
        run_start = start_ts + timedelta(minutes=i * 15)
        run_end = run_start + timedelta(seconds=35)
        burst = generator.generate_distributed_burst_attack(run_start, run_end)
        for ev in burst:
            ev['is_attack'] = True
            ev['attack_type'] = 'distributed_attack'
        events.extend(burst)
    return events


def save_ndjson(path, events):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + '\n')


def main():
    random.seed(42)

    print('Run generator 2: overfitting check with 3 balanced attack types')

    generator = SimpleDataGenerator(seed=42)

    # Total target ~50k
    total_events = 50000
    attack_fraction = 0.12
    total_attack = int(total_events * attack_fraction)  # ~6000
    normal_count = total_events - total_attack

    per_attack_type = total_attack // 3

    # Thời gian 24 giờ
    start_ts = datetime.now() - timedelta(hours=24)
    end_ts = datetime.now()

    print(f'  Generating normal events: {normal_count}')
    normal_events = generate_normal_traffic(generator, start_ts, end_ts, normal_count)

    print(f'  Generating credential stuffing events: {per_attack_type}')
    cs = generate_credential_stuffing(generator, start_ts, duration_minutes=180, total_events=per_attack_type)

    print(f'  Generating rapid bruteforce events (bursts)')
    # mỗi burst ~400, 5 bursts -> 2000
    rb = generate_rapid_bruteforce_burst(generator, start_ts + timedelta(minutes=60), bursts=5)
    # cắt về target count
    rb = rb[:per_attack_type]

    print(f'  Generating distributed attack events (runs)')
    da = generate_distributed_attacks(generator, start_ts + timedelta(hours=12), runs=7)
    da = da[:per_attack_type]

    all_events = normal_events + cs + rb + da
    all_events.sort(key=lambda e: e['timestamp'])

    actual_total = len(all_events)
    attack_count = sum(1 for e in all_events if e.get('is_attack'))

    print(f'  Total events generated: {actual_total}')
    print(f'  Total attack events: {attack_count}')
    print('  Attack breakdown:')
    types = {}
    for e in all_events:
        if e.get('is_attack'):
            types[e.get('attack_type')] = types.get(e.get('attack_type'), 0) + 1
    for k,v in types.items():
        print(f'   - {k}: {v}')

    # Write to files
    output_file = os.path.join('data', 'all_events.ndjson')
    save_ndjson(output_file, all_events)
    print(f'Saved all events to {output_file}')

    # Optionally save to database
    try:
        import pymysql
        print('  Writing to database (auth_logs)...')
        conn = pymysql.connect(**DB_CONFIG)
        cursor = conn.cursor()
        insert_sql = '''
        INSERT INTO auth_logs 
        (username, src_ip, success, user_agent, request_path, 
         http_method, http_status, failure_reason, request_duration_ms,
         geo, device_fingerprint, is_attack, attack_type, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        '''

        batch_size = 1000
        for i in range(0, len(all_events), batch_size):
            batch = all_events[i:i+batch_size]
            values = []
            for ev in batch:
                values.append((
                    ev['username'], ev['src_ip'], ev['success'], ev['user_agent'],
                    ev['request_path'], ev['http_method'], ev['http_status'],
                    ev['failure_reason'], ev['request_duration_ms'], ev['geo'],
                    ev['device_fingerprint'], ev['is_attack'], ev['attack_type'], ev['timestamp']
                ))
            cursor.executemany(insert_sql, values)
            conn.commit()
        conn.close()
        print('  Saved events to DB successfully')
    except Exception as ex:
        print('  DB save skipped or failed:', ex)

    print('\nDone.')


if __name__ == '__main__':
    main()
