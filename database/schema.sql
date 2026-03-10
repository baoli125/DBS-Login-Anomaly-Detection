-- Database: eaglepro
CREATE DATABASE IF NOT EXISTS eaglepro CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- User: bao với password Baoli125@
CREATE USER IF NOT EXISTS 'bao'@'localhost' IDENTIFIED BY 'Baoli125@';
GRANT ALL PRIVILEGES ON eaglepro.* TO 'bao'@'localhost';
FLUSH PRIVILEGES;

USE eaglepro;

-- Bảng users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    full_name VARCHAR(100),
    avatar VARCHAR(100) DEFAULT 'default.png',
    is_admin BOOLEAN DEFAULT FALSE,
    department VARCHAR(50),
    position VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
);

-- Bảng documents (cho web app)
CREATE TABLE IF NOT EXISTS documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    doc_type VARCHAR(50),
    sensitivity VARCHAR(20) DEFAULT 'Low',
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_size VARCHAR(20),
    file_format VARCHAR(20),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id)
);

-- Bảng hidden_files (cho web app)
CREATE TABLE IF NOT EXISTS hidden_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(200) DEFAULT '🔒 My Secret File',
    content TEXT,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user (user_id)
);

-- Bảng auth_logs (cho detection system) - RULE 1: KEEP IT SIMPLE
CREATE TABLE IF NOT EXISTS auth_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,  -- IPv6 support
    success BOOLEAN NOT NULL,
    user_agent TEXT,
    request_path VARCHAR(100),
    http_method VARCHAR(10),
    http_status INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_src_ip (src_ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_success (success)
);

-- Bảng alerts (cho cả rule-based và ML-based)
CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,  -- 'rule', 'ml', 'classification'
    entity_type VARCHAR(20) NOT NULL, -- 'ip', 'user'
    entity_value VARCHAR(100) NOT NULL,
    detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    score FLOAT,                     -- ML score (0-1)
    confidence FLOAT,                -- Confidence level
    attack_type VARCHAR(50),         -- Phân loại attack
    rule_name VARCHAR(100),          -- Rule triggered
    features JSON,                   -- Features used for ML
    action_taken VARCHAR(50),        -- 'block', 'alert', 'monitor'
    action_details TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL,
    INDEX idx_alert_type (alert_type),
    INDEX idx_detection_time (detection_time),
    INDEX idx_entity (entity_type, entity_value)
);

-- Bảng blocked_ips (cho enforcement)
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NULL,
    reason VARCHAR(200),
    alert_id INT,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
    INDEX idx_ip_address (ip_address),
    INDEX idx_blocked_until (blocked_until)
);