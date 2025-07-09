// CoyoteKey Dashboard JavaScript
class CoyoteKeyDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.isAttackRunning = false;
        this.attackConfig = {};
        this.stats = {
            totalSessions: 0,
            activeSessions: 0,
            totalRequests: 0,
            successfulRequests: 0,
            successRate: 0,
            avgResponseTime: 0
        };
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.initWebSocket();
        this.loadInitialData();
        this.initCharts();
        this.startPeriodicUpdates();
    }
    
    setupEventListeners() {
        // Attack form submission
        const attackForm = document.getElementById('attackForm');
        if (attackForm) {
            attackForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startAttack();
            });
        }
        
        // Stop attack button
        const stopBtn = document.getElementById('stopAttack');
        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                this.stopAttack();
            });
        }
        
        // Clear results button
        const clearBtn = document.getElementById('clearResults');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearResults();
            });
        }
        
        // Export results button
        const exportBtn = document.getElementById('exportResults');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportResults();
            });
        }
        
        // File upload handlers
        const wordlistUpload = document.getElementById('wordlistFile');
        if (wordlistUpload) {
            wordlistUpload.addEventListener('change', (e) => {
                this.handleFileUpload(e, 'wordlist');
            });
        }
        
        const targetsUpload = document.getElementById('targetsFile');
        if (targetsUpload) {
            targetsUpload.addEventListener('change', (e) => {
                this.handleFileUpload(e, 'targets');
            });
        }
        
        // Tab switching
        const tabButtons = document.querySelectorAll('.tab-button');
        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });
        
        // Settings form
        const settingsForm = document.getElementById('settingsForm');
        if (settingsForm) {
            settingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveSettings();
            });
        }
    }
    
    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.showNotification('Connected to CoyoteKey server', 'success');
            
            // Subscribe to channels
            this.subscribeToChannel('stats');
            this.subscribeToChannel('notifications');
            this.subscribeToChannel('results');
            this.subscribeToChannel('alerts');
        };
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWebSocketMessage(data);
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.showNotification('Disconnected from server', 'error');
            
            // Attempt to reconnect after 5 seconds
            setTimeout(() => {
                this.initWebSocket();
            }, 5000);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.showNotification('Connection error', 'error');
        };
    }
    
    subscribeToChannel(channel) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'subscribe',
                channel: channel
            }));
        }
    }
    
    handleWebSocketMessage(data) {
        switch (data.channel) {
            case 'stats':
                this.updateStats(data.data);
                break;
            case 'notifications':
                this.showNotification(data.data.message, data.data.level);
                break;
            case 'results':
                this.addResult(data.data);
                break;
            case 'alerts':
                this.handleAlert(data.data);
                break;
        }
    }
    
    async loadInitialData() {
        try {
            // Load stats
            const statsResponse = await this.apiCall('/api/stats');
            if (statsResponse.success) {
                this.updateStats(statsResponse.data);
            }
            
            // Load recent results
            const resultsResponse = await this.apiCall('/api/results?limit=50');
            if (resultsResponse.success) {
                this.displayResults(resultsResponse.data);
            }
            
            // Load system health
            const healthResponse = await this.apiCall('/api/health');
            if (healthResponse.success) {
                this.updateSystemHealth(healthResponse.data);
            }
            
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showNotification('Error loading data', 'error');
        }
    }
    
    async apiCall(endpoint, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        };
        
        // Add API key if available
        const apiKey = localStorage.getItem('coyotekey_api_key');
        if (apiKey) {
            defaultOptions.headers['X-API-Key'] = apiKey;
        }
        
        const response = await fetch(endpoint, { ...defaultOptions, ...options });
        return await response.json();
    }
    
    updateStats(data) {
        this.stats = { ...this.stats, ...data };
        
        // Update stat cards
        this.updateElement('totalSessions', this.stats.total_sessions || 0);
        this.updateElement('activeSessions', this.stats.active_sessions || 0);
        this.updateElement('totalRequests', this.stats.total_requests || 0);
        this.updateElement('successRate', `${((this.stats.successful_requests || 0) / (this.stats.total_requests || 1) * 100).toFixed(1)}%`);
        
        // Update progress bar if attack is running
        if (this.isAttackRunning) {
            this.updateProgress();
        }
        
        // Update charts
        this.updateCharts();
    }
    
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }
    
    startAttack() {
        // Collect form data
        const formData = new FormData(document.getElementById('attackForm'));
        this.attackConfig = Object.fromEntries(formData.entries());
        
        // Validate required fields
        if (!this.attackConfig.target && !this.attackConfig.targetsFile) {
            this.showNotification('Please specify a target URL or upload targets file', 'error');
            return;
        }
        
        if (!this.attackConfig.wordlist && !this.attackConfig.wordlistFile) {
            this.showNotification('Please specify a wordlist or upload wordlist file', 'error');
            return;
        }
        
        // Start attack
        this.isAttackRunning = true;
        this.updateAttackUI(true);
        
        // Send attack configuration to server
        this.sendAttackConfig();
        
        this.showNotification('Attack started successfully', 'success');
    }
    
    stopAttack() {
        this.isAttackRunning = false;
        this.updateAttackUI(false);
        
        // Send stop command to server
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'stop_attack'
            }));
        }
        
        this.showNotification('Attack stopped', 'warning');
    }
    
    updateAttackUI(isRunning) {
        const startBtn = document.getElementById('startAttack');
        const stopBtn = document.getElementById('stopAttack');
        const progressContainer = document.getElementById('progressContainer');
        
        if (startBtn) {
            startBtn.disabled = isRunning;
            startBtn.innerHTML = isRunning ? 
                '<span class="loading"></span> Running...' : 
                '🚀 Start Attack';
        }
        
        if (stopBtn) {
            stopBtn.disabled = !isRunning;
        }
        
        if (progressContainer) {
            progressContainer.style.display = isRunning ? 'block' : 'none';
        }
    }
    
    updateProgress() {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        if (progressFill && progressText) {
            const progress = this.stats.total_requests > 0 ? 
                (this.stats.completed_requests || 0) / this.stats.total_requests * 100 : 0;
            
            progressFill.style.width = `${progress}%`;
            progressText.textContent = `${progress.toFixed(1)}% Complete (${this.stats.completed_requests || 0}/${this.stats.total_requests || 0})`;
        }
    }
    
    addResult(result) {
        const resultsTable = document.getElementById('resultsTableBody');
        if (!resultsTable) return;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(result.timestamp).toLocaleTimeString()}</td>
            <td><code>${result.key}</code></td>
            <td>${result.url}</td>
            <td><span class="status-badge ${result.success ? 'status-success' : 'status-error'}">${result.status_code}</span></td>
            <td>${result.response_time}ms</td>
            <td>${result.content_length} bytes</td>
        `;
        
        // Add to top of table
        resultsTable.insertBefore(row, resultsTable.firstChild);
        
        // Limit table rows
        const maxRows = 100;
        while (resultsTable.children.length > maxRows) {
            resultsTable.removeChild(resultsTable.lastChild);
        }
        
        // Update activity feed
        this.addActivity({
            type: result.success ? 'success' : 'error',
            title: result.success ? 'Key Found!' : 'Key Failed',
            description: `${result.key} on ${result.url}`,
            time: new Date(result.timestamp)
        });
    }
    
    addActivity(activity) {
        const activityFeed = document.getElementById('activityFeed');
        if (!activityFeed) return;
        
        const activityItem = document.createElement('div');
        activityItem.className = 'activity-item';
        activityItem.innerHTML = `
            <div class="activity-icon ${activity.type}">
                ${activity.type === 'success' ? '✅' : activity.type === 'error' ? '❌' : 'ℹ️'}
            </div>
            <div class="activity-content">
                <div class="activity-title">${activity.title}</div>
                <div class="activity-description">${activity.description}</div>
            </div>
            <div class="activity-time">${activity.time.toLocaleTimeString()}</div>
        `;
        
        activityFeed.insertBefore(activityItem, activityFeed.firstChild);
        
        // Limit activity items
        const maxItems = 50;
        while (activityFeed.children.length > maxItems) {
            activityFeed.removeChild(activityFeed.lastChild);
        }
    }
    
    showNotification(message, type = 'info') {
        const notificationsContainer = document.getElementById('notifications');
        if (!notificationsContainer) return;
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-icon">
                ${type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'}
            </div>
            <div class="notification-content">${message}</div>
            <button class="notification-close" onclick="this.parentElement.remove()">×</button>
        `;
        
        notificationsContainer.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }
    
    initCharts() {
        // Initialize Chart.js charts
        this.initSuccessRateChart();
        this.initResponseTimeChart();
        this.initStatusCodeChart();
        this.initTargetChart();
    }
    
    initSuccessRateChart() {
        const ctx = document.getElementById('successRateChart');
        if (!ctx) return;
        
        this.charts.successRate = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Success Rate (%)',
                    data: [],
                    borderColor: '#27ae60',
                    backgroundColor: 'rgba(39, 174, 96, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }
    
    initResponseTimeChart() {
        const ctx = document.getElementById('responseTimeChart');
        if (!ctx) return;
        
        this.charts.responseTime = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Response Time (ms)',
                    data: [],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    initStatusCodeChart() {
        const ctx = document.getElementById('statusCodeChart');
        if (!ctx) return;
        
        this.charts.statusCode = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['200', '401', '403', '404', '500', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#27ae60',
                        '#f39c12',
                        '#e74c3c',
                        '#95a5a6',
                        '#8e44ad',
                        '#34495e'
                    ]
                }]
            },
            options: {
                responsive: true
            }
        });
    }
    
    initTargetChart() {
        const ctx = document.getElementById('targetChart');
        if (!ctx) return;
        
        this.charts.target = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Requests per Target',
                    data: [],
                    backgroundColor: '#3498db'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    updateCharts() {
        // Update charts with current data
        const now = new Date().toLocaleTimeString();
        
        // Success rate chart
        if (this.charts.successRate) {
            const successRate = (this.stats.successful_requests || 0) / (this.stats.total_requests || 1) * 100;
            this.addDataToChart(this.charts.successRate, now, successRate);
        }
        
        // Response time chart
        if (this.charts.responseTime) {
            this.addDataToChart(this.charts.responseTime, now, this.stats.avg_response_time || 0);
        }
    }
    
    addDataToChart(chart, label, data) {
        chart.data.labels.push(label);
        chart.data.datasets[0].data.push(data);
        
        // Keep only last 20 data points
        if (chart.data.labels.length > 20) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
        }
        
        chart.update();
    }
    
    handleFileUpload(event, type) {
        const file = event.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            
            if (type === 'wordlist') {
                const keys = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
                document.getElementById('wordlistPreview').textContent = `${keys.length} keys loaded`;
            } else if (type === 'targets') {
                const targets = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
                document.getElementById('targetsPreview').textContent = `${targets.length} targets loaded`;
            }
        };
        
        reader.readAsText(file);
    }
    
    switchTab(tabName) {
        // Hide all tab contents
        const tabContents = document.querySelectorAll('.tab-content');
        tabContents.forEach(content => {
            content.style.display = 'none';
        });
        
        // Remove active class from all tab buttons
        const tabButtons = document.querySelectorAll('.tab-button');
        tabButtons.forEach(button => {
            button.classList.remove('active');
        });
        
        // Show selected tab content
        const selectedTab = document.getElementById(`${tabName}Tab`);
        if (selectedTab) {
            selectedTab.style.display = 'block';
        }
        
        // Add active class to selected button
        const selectedButton = document.querySelector(`[data-tab="${tabName}"]`);
        if (selectedButton) {
            selectedButton.classList.add('active');
        }
    }
    
    startPeriodicUpdates() {
        // Update stats every 5 seconds
        setInterval(async () => {
            if (!this.isAttackRunning) return;
            
            try {
                const response = await this.apiCall('/api/stats');
                if (response.success) {
                    this.updateStats(response.data);
                }
            } catch (error) {
                console.error('Error updating stats:', error);
            }
        }, 5000);
    }
    
    exportResults() {
        // Export results as JSON
        const results = this.collectResults();
        const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `coyotekey_results_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Results exported successfully', 'success');
    }
    
    collectResults() {
        const resultsTable = document.getElementById('resultsTableBody');
        if (!resultsTable) return [];
        
        const results = [];
        const rows = resultsTable.querySelectorAll('tr');
        
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length >= 6) {
                results.push({
                    timestamp: cells[0].textContent,
                    key: cells[1].textContent,
                    url: cells[2].textContent,
                    status_code: cells[3].textContent,
                    response_time: cells[4].textContent,
                    content_length: cells[5].textContent
                });
            }
        });
        
        return results;
    }
    
    clearResults() {
        const resultsTable = document.getElementById('resultsTableBody');
        if (resultsTable) {
            resultsTable.innerHTML = '';
        }
        
        const activityFeed = document.getElementById('activityFeed');
        if (activityFeed) {
            activityFeed.innerHTML = '';
        }
        
        this.showNotification('Results cleared', 'info');
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new CoyoteKeyDashboard();
});

// Chart.js configuration
Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
Chart.defaults.color = '#666';
