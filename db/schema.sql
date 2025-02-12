-- Create database if not exists
CREATE DATABASE IF NOT EXISTS smart_attendance;
USE smart_attendance;

-- Users table for both teachers and students
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    role ENUM('teacher', 'student') NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) UNIQUE,           -- For teachers
    roll_number VARCHAR(100) UNIQUE,        -- For students
    email VARCHAR(255) UNIQUE,              -- For teachers
    course VARCHAR(100),                    -- For students
    academic_year VARCHAR(50),              -- For students
    phone VARCHAR(20) NOT NULL,
    highest_degree VARCHAR(100),            -- For teachers
    experience VARCHAR(50),                 -- For teachers
    password_hash VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_role (role),
    INDEX idx_email (email),
    INDEX idx_roll_number (roll_number)
);

-- Admin Users table
CREATE TABLE IF NOT EXISTS admins (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin', 'moderator') NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_admin_role (role)
);

-- Admin Audit Logs table
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    admin_id VARCHAR(36) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admins(id),
    INDEX idx_admin_logs (admin_id),
    INDEX idx_admin_actions (action)
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id VARCHAR(36) PRIMARY KEY,
    report_type ENUM('attendance', 'user_activity', 'security') NOT NULL,
    generated_by VARCHAR(36) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    data JSON,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (generated_by) REFERENCES admins(id),
    INDEX idx_report_type (report_type),
    INDEX idx_generated_by (generated_by)
);

-- OTP Verification table
CREATE TABLE IF NOT EXISTS otp_verifications (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_user_otp (user_id, otp_code)
);

-- Attendance Sessions table
CREATE TABLE IF NOT EXISTS attendance_sessions (
    id VARCHAR(36) PRIMARY KEY,
    teacher_id VARCHAR(36) NOT NULL,
    subject VARCHAR(100) NOT NULL,
    academic_year VARCHAR(50) NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    status ENUM('active', 'completed', 'cancelled') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (teacher_id) REFERENCES users(id),
    INDEX idx_teacher_sessions (teacher_id, status),
    INDEX idx_active_sessions (status, academic_year)
);

-- Attendance Records table
CREATE TABLE IF NOT EXISTS attendance_records (
    id VARCHAR(36) PRIMARY KEY,
    session_id VARCHAR(36) NOT NULL,
    student_id VARCHAR(36) NOT NULL,
    location_lat DECIMAL(10, 8),
    location_long DECIMAL(11, 8),
    wifi_ssid VARCHAR(100),
    wifi_bssid VARCHAR(100),
    device_info JSON,
    marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES attendance_sessions(id),
    FOREIGN KEY (student_id) REFERENCES users(id),
    UNIQUE KEY unique_attendance (session_id, student_id),
    INDEX idx_session_records (session_id),
    INDEX idx_student_records (student_id)
);

-- Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_user_logs (user_id),
    INDEX idx_action_logs (action)
);

-- Insert default super admin (password: project@2025)
INSERT IGNORE INTO admins (
    id,
    username,
    email,
    password_hash,
    role,
    full_name
) VALUES (
    'admin-001',
    'admin',
    'admin@smartattendance.com',
    '$2a$10$rQAUtbuDV9GQzixXXIdkJeORauJq2OeJqW690v2K3xAUqxAx9KAsO',
    'super_admin',
    'System Administrator'
); 