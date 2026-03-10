USE eaglepro;

-- Thêm users mẫu
INSERT INTO users (username, password, full_name, avatar, is_admin, department, position) VALUES
('admin', 'admin123', 'System Administrator', 'admin_avatar.png', 1, 'IT', 'System Admin'),
('HusThien_IA', 'Thie2104n', 'HusThi IA', 'husthi_avatar.png', 0, 'AI Research', 'Senior AI Researcher'),
('Collie_Min', 'Minh1304', 'Collie Minh', 'collie_avatar.png', 0, 'Security', 'Security Analyst'),
('LazyBeo', 'iloveyou', 'LazyBeo', 'lazybeo_avatar.png', 0, 'Research', 'Research Specialist'),
('user1', 'pass123', 'John Doe', 'normal.png', 0, 'Title Insurance', 'Underwriter'),
('user2', 'pass123', 'Jane Smith', 'normal.png', 0, 'Escrow Services', 'Escrow Officer');

-- Thêm documents mẫu
INSERT INTO documents (user_id, title, content, doc_type, sensitivity, file_size, file_format) VALUES
(1, 'System Security Policy', 'Complete security policy document...', 'Security Report', 'High', '2.5MB', 'PDF'),
(2, 'AI Research Paper', 'Latest findings in AI security...', 'Research Paper', 'Medium', '3.2MB', 'PDF'),
(3, 'Penetration Test Report', 'Quarterly penetration test results...', 'Security Report', 'High', '4.1MB', 'DOCX'),
(4, 'Market Analysis', 'Financial market trends...', 'Financial Report', 'Medium', '1.8MB', 'PDF'),
(5, 'Escrow Agreement Template', 'Standard escrow agreement...', 'Legal', 'Low', '1.2MB', 'DOCX'),
(6, 'Insurance Policy Review', 'Annual policy review...', 'Insurance', 'Medium', '2.3MB', 'PDF');

-- Thêm hidden files cho special users
INSERT INTO hidden_files (user_id, title, content) VALUES
(2, '🔒 Secret Research Notes', 'teemo 1'),
(3, '🔒 Security Investigation', 'teemo 2'),
(4, '🔒 Private Thoughts', '1 Lazy Mew do all of this shit');