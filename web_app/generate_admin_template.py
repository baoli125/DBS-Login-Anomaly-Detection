"""
Admin Dashboard Template HTML
Shows alerts, blocked IPs, detection statistics
"""

admin_dashboard_html = """
{% extends "base.html" %}

{% block title %}Admin Dashboard - EaglePro{% endblock %}

{% block content %}
<div class="page-container">
    <div class="page-header">
        <h1> Admin Dashboard</h1>
        <p>Security monitoring and detection system management</p>
    </div>
    
    <!-- Statistics Cards -->
    <div class="stats-grid">
        <div class="stat-card" id="total-alerts">
            <div class="stat-icon"></div>
            <div class="stat-content">
                <div class="stat-label">Total Alerts</div>
                <div class="stat-value">0</div>
            </div>
        </div>
        
        <div class="stat-card" id="active-alerts">
            <div class="stat-icon"></div>
            <div class="stat-content">
                <div class="stat-label">Active Alerts</div>
                <div class="stat-value">0</div>
            </div>
        </div>
        
        <div class="stat-card" id="blocked-ips">
            <div class="stat-icon"></div>
            <div class="stat-content">
                <div class="stat-label">Blocked IPs</div>
                <div class="stat-value">0</div>
            </div>
        </div>
        
        <div class="stat-card" id="rule-alerts">
            <div class="stat-icon"></div>
            <div class="stat-content">
                <div class="stat-label">Rule-Based</div>
                <div class="stat-value">0</div>
            </div>
        </div>
        
        <div class="stat-card" id="ml-alerts">
            <div class="stat-icon"></div>
            <div class="stat-content">
                <div class="stat-label">ML Detected</div>
                <div class="stat-value">0</div>
            </div>
        </div>
        
        <div class="stat-card" id="combined-alerts">
            <div class="stat-icon"></div>
            <div class="stat-content">
                <div class="stat-label">Combined</div>
                <div class="stat-value">0</div>
            </div>
        </div>
    </div>
    
    <!-- Tabs -->
    <div class="admin-tabs">
        <button class="tab-button active" data-tab="alerts">
             Recent Alerts
        </button>
        <button class="tab-button" data-tab="blocked-ips">
             Blocked IPs
        </button>
        <button class="tab-button" data-tab="settings">
             Settings
        </button>
    </div>
    
    <!-- Alerts Tab -->
    <div class="tab-content active" id="tab-alerts">
        <div class="section-header">
            <h2>Recent Security Alerts</h2>
            <div class="action-buttons">
                <button class="btn-small" onclick="refreshAlerts()"> Refresh</button>
                <button class="btn-small" onclick="exportAlerts()"> Export</button>
            </div>
        </div>
        
        <div class="alerts-container" id="alerts-list">
            <div class="loading">Loading alerts...</div>
        </div>
    </div>
    
    <!-- Blocked IPs Tab -->
    <div class="tab-content" id="tab-blocked-ips">
        <div class="section-header">
            <h2>Blocked IP Addresses</h2>
            <div class="action-buttons">
                <button class="btn-small" onclick="refreshBlockedIPs()"> Refresh</button>
                <button class="btn-small" onclick="unblockAll()"> Unblock Expired</button>
            </div>
        </div>
        
        <div class="blocked-ips-container" id="blocked-ips-list">
            <div class="loading">Loading blocked IPs...</div>
        </div>
    </div>
    
    <!-- Settings Tab -->
    <div class="tab-content" id="tab-settings">
        <div class="section-header">
            <h2>Detection System Settings</h2>
        </div>
        
        <div class="settings-panel">
            <div class="setting-item">
                <label>Alert Threshold (confidence)</label>
                <input type="range" min="0" max="1" step="0.1" value="0.6" id="threshold-slider">
                <span id="threshold-value">0.60</span>
            </div>
            
            <div class="setting-item">
                <label>Block Duration (seconds)</label>
                <input type="number" value="3600" id="block-duration">
            </div>
            
            <div class="setting-item">
                <label>Enable ML Detection</label>
                <input type="checkbox" checked id="enable-ml">
            </div>
            
            <div class="setting-item">
                <label>Enable Rule-Based Detection</label>
                <input type="checkbox" checked id="enable-rules">
            </div>
            
            <button class="btn-primary" onclick="saveSettings()"> Save Settings</button>
        </div>
    </div>
</div>

<!-- Alert Detail Modal -->
<div class="modal" id="alert-modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>Alert Details</h2>
            <button class="modal-close" onclick="closeAlertModal()"></button>
        </div>
        <div class="modal-body" id="alert-detail-content">
            <!-- Content will be populated by JavaScript -->
        </div>
        <div class="modal-footer">
            <button class="btn-secondary" onclick="closeAlertModal()">Close</button>
            <button class="btn-primary" onclick="resolveAlert()"> Resolve</button>
        </div>
    </div>
</div>

<style>
/* Admin Dashboard Styles */
.page-container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

.page-header {
    margin-bottom: 30px;
    border-bottom: 2px solid #00d4ff;
    padding-bottom: 15px;
}

.page-header h1 {
    margin: 0;
    color: #00d4ff;
    font-size: 28px;
}

.page-header p {
    margin: 5px 0 0;
    color: #888;
}

/* Statistics Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 30px;
}

.stat-card {
    background: #1f2d4d;
    border: 1px solid #00d4ff;
    border-radius: 8px;
    padding: 20px;
    display: flex;
    align-items: center;
    gap: 15px;
    transition: all 0.3s ease;
}

.stat-card:hover {
    background: #252d42;
    border-color: #00e6ff;
    transform: translateY(-2px);
}

.stat-icon {
    font-size: 28px;
}

.stat-content {
    flex: 1;
}

.stat-label {
    color: #888;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.stat-value {
    color: #00d4ff;
    font-size: 24px;
    font-weight: bold;
    margin-top: 5px;
}

/* Tabs */
.admin-tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
    border-bottom: 1px solid #151d3b;
}

.tab-button {
    background: transparent;
    border: none;
    color: #888;
    padding: 12px 20px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.3s ease;
    font-size: 14px;
}

.tab-button:hover {
    color: #00d4ff;
}

.tab-button.active {
    color: #00d4ff;
    border-bottom-color: #00d4ff;
}

/* Tab Content */
.tab-content {
    display: none;
    animation: fadeIn 0.3s ease;
}

.tab-content.active {
    display: block;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.section-header h2 {
    margin: 0;
    color: #00d4ff;
}

.action-buttons {
    display: flex;
    gap: 10px;
}

/* Alerts Container */
.alerts-container,
.blocked-ips-container {
    background: #151d3b;
    border: 1px solid #1f2d4d;
    border-radius: 8px;
    overflow: hidden;
}

.alert-item,
.blocked-ip-item {
    padding: 15px;
    border-bottom: 1px solid #1f2d4d;
    cursor: pointer;
    transition: background 0.3s ease;
}

.alert-item:hover,
.blocked-ip-item:hover {
    background: #1f2d4d;
}

.alert-item:last-child,
.blocked-ip-item:last-child {
    border-bottom: none;
}

.alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.alert-type {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}

.alert-type.rule-based {
    background: #ff6b6b;
    color: white;
}

.alert-type.ml {
    background: #4ecdc4;
    color: white;
}

.alert-type.combined {
    background: #a78bfa;
    color: white;
}

.alert-info {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    font-size: 13px;
}

.alert-detail {
    color: #888;
}

.alert-detail-label {
    color: #666;
    font-size: 11px;
    text-transform: uppercase;
}

.alert-detail-value {
    color: #00d4ff;
    margin-top: 3px;
}

/* Settings Panel */
.settings-panel {
    background: #151d3b;
    border: 1px solid #1f2d4d;
    border-radius: 8px;
    padding: 20px;
}

.setting-item {
    margin-bottom: 20px;
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 15px;
    align-items: center;
}

.setting-item label {
    color: #00d4ff;
    font-weight: bold;
}

.setting-item input[type="range"],
.setting-item input[type="number"] {
    background: #0a0e27;
    border: 1px solid #1f2d4d;
    color: #00d4ff;
    padding: 8px;
    border-radius: 4px;
}

.setting-item input[type="checkbox"] {
    width: 20px;
    height: 20px;
}

.setting-item #threshold-value {
    color: #00d4ff;
    font-weight: bold;
}

/* Buttons */
.btn-small,
.btn-primary,
.btn-secondary {
    padding: 8px 16px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
    transition: all 0.3s ease;
}

.btn-small {
    background: #1f2d4d;
    color: #00d4ff;
    border: 1px solid #00d4ff;
}

.btn-small:hover {
    background: #00d4ff;
    color: #0a0e27;
}

.btn-primary {
    background: #00d4ff;
    color: #0a0e27;
    font-weight: bold;
}

.btn-primary:hover {
    background: #00e6ff;
}

.btn-secondary {
    background: #1f2d4d;
    border: 1px solid #888;
    color: #888;
}

.btn-secondary:hover {
    background: #252d42;
    color: #00d4ff;
}

/* Modal */
.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(10, 14, 39, 0.8);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}

.modal.active {
    display: flex;
}

.modal-content {
    background: #1f2d4d;
    border: 1px solid #00d4ff;
    border-radius: 8px;
    width: 90%;
    max-width: 600px;
    max-height: 80vh;
    overflow-y: auto;
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px;
    border-bottom: 1px solid #00d4ff;
}

.modal-header h2 {
    margin: 0;
    color: #00d4ff;
}

.modal-close {
    background: none;
    border: none;
    color: #00d4ff;
    font-size: 24px;
    cursor: pointer;
}

.modal-body {
    padding: 20px;
}

.modal-footer {
    padding: 20px;
    border-top: 1px solid #1f2d4d;
    display: flex;
    justify-content: flex-end;
    gap: 10px;
}

.loading {
    text-align: center;
    padding: 40px;
    color: #888;
}

/* Responsive */
@media (max-width: 768px) {
    .stats-grid {
        grid-template-columns: 1fr;
    }
    
    .admin-tabs {
        overflow-x: auto;
    }
    
    .alert-header {
        flex-direction: column;
        align-items: flex-start;
    }
}
</style>

<script>
// Tab switching
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', function() {
        const tabName = this.dataset.tab;
        
        // Hide all tabs
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Remove active from buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        
        // Show selected tab
        document.getElementById(`tab-${tabName}`).classList.add('active');
        this.classList.add('active');
        
        // Load data
        if (tabName === 'alerts') {
            refreshAlerts();
        } else if (tabName === 'blocked-ips') {
            refreshBlockedIPs();
        }
    });
});

// Load statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats/detection');
        const data = await response.json();
        const stats = data.stats;
        
        document.getElementById('total-alerts').querySelector('.stat-value').textContent = stats.total_alerts;
        document.getElementById('active-alerts').querySelector('.stat-value').textContent = stats.active_alerts;
        document.getElementById('blocked-ips').querySelector('.stat-value').textContent = stats.blocked_ips;
        document.getElementById('rule-alerts').querySelector('.stat-value').textContent = stats.rule_based_alerts;
        document.getElementById('ml-alerts').querySelector('.stat-value').textContent = stats.ml_alerts;
        document.getElementById('combined-alerts').querySelector('.stat-value').textContent = stats.combined_alerts;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load alerts
async function refreshAlerts() {
    try {
        const response = await fetch('/api/alerts?limit=50');
        const data = await response.json();
        
        const alertsList = document.getElementById('alerts-list');
        alertsList.innerHTML = '';
        
        if (data.alerts.length === 0) {
            alertsList.innerHTML = '<div class="loading">No alerts found</div>';
            return;
        }
        
        data.alerts.forEach(alert => {
            const item = createAlertItem(alert);
            alertsList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading alerts:', error);
        document.getElementById('alerts-list').innerHTML = '<div class="loading" style="color: #ff6b6b;">Error loading alerts</div>';
    }
}

function createAlertItem(alert) {
    const item = document.createElement('div');
    item.className = 'alert-item';
    
    const type = alert.alert_type || 'unknown';
    const typeClass = `alert-type ${type}`;
    
    item.innerHTML = `
        <div class="alert-header">
            <span class="${typeClass}">${type.toUpperCase()}</span>
            <span style="color: #888; font-size: 12px;">${new Date(alert.timestamp).toLocaleString()}</span>
        </div>
        <div class="alert-info">
            <div class="alert-detail">
                <div class="alert-detail-label">User</div>
                <div class="alert-detail-value">${alert.username || 'unknown'}</div>
            </div>
            <div class="alert-detail">
                <div class="alert-detail-label">IP</div>
                <div class="alert-detail-value">${alert.src_ip}</div>
            </div>
            <div class="alert-detail">
                <div class="alert-detail-label">Risk Score</div>
                <div class="alert-detail-value">${(alert.risk_score || 0).toFixed(2)}</div>
            </div>
            <div class="alert-detail">
                <div class="alert-detail-label">Action</div>
                <div class="alert-detail-value">${alert.action || 'unknown'}</div>
            </div>
        </div>
    `;
    
    item.addEventListener('click', () => showAlertDetail(alert));
    return item;
}

// Load blocked IPs
async function refreshBlockedIPs() {
    try {
        const response = await fetch('/api/blocked_ips');
        const data = await response.json();
        
        const ipsList = document.getElementById('blocked-ips-list');
        ipsList.innerHTML = '';
        
        if (data.blocked_ips.length === 0) {
            ipsList.innerHTML = '<div class="loading">No blocked IPs</div>';
            return;
        }
        
        data.blocked_ips.forEach(ip => {
            const item = createBlockedIPItem(ip);
            ipsList.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading blocked IPs:', error);
        document.getElementById('blocked-ips-list').innerHTML = '<div class="loading" style="color: #ff6b6b;">Error loading blocked IPs</div>';
    }
}

function createBlockedIPItem(ipInfo) {
    const item = document.createElement('div');
    item.className = 'blocked-ip-item';
    
    const expiresAt = new Date(ipInfo.blocked_until);
    const now = new Date();
    const timeRemaining = Math.max(0, (expiresAt - now) / 1000 / 60);
    
    item.innerHTML = `
        <div class="alert-header">
            <span style="color: #00d4ff; font-weight: bold;">${ipInfo.ip}</span>
            <button class="btn-small" onclick="unblockIP('${ipInfo.ip}', event)" style="font-size: 11px;"> Unblock</button>
        </div>
        <div class="alert-info">
            <div class="alert-detail">
                <div class="alert-detail-label">Reason</div>
                <div class="alert-detail-value">${ipInfo.reason}</div>
            </div>
            <div class="alert-detail">
                <div class="alert-detail-label">Blocked At</div>
                <div class="alert-detail-value">${new Date(ipInfo.blocked_at).toLocaleString()}</div>
            </div>
            <div class="alert-detail">
                <div class="alert-detail-label">Time Remaining</div>
                <div class="alert-detail-value">${Math.round(timeRemaining)} min</div>
            </div>
        </div>
    `;
    
    return item;
}

async function unblockIP(ip, event) {
    event.stopPropagation();
    
    try {
        const response = await fetch(`/api/blocked_ips/${ip}`, { method: 'DELETE' });
        if (response.ok) {
            refreshBlockedIPs();
        }
    } catch (error) {
        console.error('Error unblocking IP:', error);
    }
}

// Modal functions
function showAlertDetail(alert) {
    const content = document.getElementById('alert-detail-content');
    content.innerHTML = `
        <div style="color: #888; line-height: 1.8;">
            <p><strong style="color: #00d4ff;">Username:</strong> ${alert.username || 'N/A'}</p>
            <p><strong style="color: #00d4ff;">Source IP:</strong> ${alert.src_ip}</p>
            <p><strong style="color: #00d4ff;">Alert Type:</strong> ${alert.alert_type}</p>
            <p><strong style="color: #00d4ff;">Attack Type:</strong> ${alert.attack_type || 'N/A'}</p>
            <p><strong style="color: #00d4ff;">Rule Triggered:</strong> ${alert.rule_name || 'N/A'}</p>
            <p><strong style="color: #00d4ff;">Confidence:</strong> ${alert.confidence || 'N/A'}</p>
            <p><strong style="color: #00d4ff;">Risk Score:</strong> ${(alert.risk_score || 0).toFixed(2)}</p>
            <p><strong style="color: #00d4ff;">Action:</strong> ${alert.action}</p>
            <p><strong style="color: #00d4ff;">Status:</strong> ${alert.status}</p>
            <p><strong style="color: #00d4ff;">Timestamp:</strong> ${new Date(alert.timestamp).toLocaleString()}</p>
        </div>
    `;
    
    document.getElementById('alert-modal').classList.add('active');
}

function closeAlertModal() {
    document.getElementById('alert-modal').classList.remove('active');
}

// Save settings
function saveSettings() {
    alert('Settings saved! (in production, this would persist to backend)');
}

// Load data on page load
window.addEventListener('load', () => {
    loadStats();
    refreshAlerts();
    
    // Refresh stats every 10 seconds
    setInterval(loadStats, 10000);
});
</script>
"""

# Write to file
if __name__ == '__main__':
    with open('templates/admin_dashboard.html', 'w') as f:
        f.write(admin_dashboard_html)
    print(" Admin dashboard template created")
