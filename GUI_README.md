# 🖥️ CoyoteKey GUI - Web-Based Interface

CoyoteKey GUI provides a modern, responsive web-based interface for API security testing with real-time monitoring, interactive configuration, and comprehensive analytics.

## 🌟 Features

### 🎨 Modern Web Interface
- **Responsive Design**: Mobile-friendly interface that works on all devices
- **Glassmorphism UI**: Modern design with backdrop blur effects
- **Dark/Light Theme**: Customizable appearance
- **Smooth Animations**: Fluid transitions and interactive elements

### 📊 Real-time Dashboard
- **Live Statistics**: Real-time attack progress and success rates
- **Interactive Charts**: Dynamic graphs using Chart.js
- **Progress Monitoring**: Live progress bars and completion tracking
- **Activity Feed**: Real-time stream of attack events

### 🎯 Interactive Configuration
- **Form-based Setup**: Easy-to-use attack configuration forms
- **File Upload**: Drag-and-drop wordlist and target file uploads
- **Advanced Options**: Comprehensive feature toggles and settings
- **Validation**: Real-time form validation and error handling

### 📈 Visual Analytics
- **Success Rate Charts**: Time-series success rate visualization
- **Response Time Graphs**: Performance monitoring charts
- **Status Code Distribution**: Pie charts for HTTP status analysis
- **Target Comparison**: Bar charts for multi-target analysis

### 🔔 Real-time Notifications
- **Toast Notifications**: Non-intrusive success/error messages
- **WebSocket Updates**: Live data streaming from server
- **Alert System**: Configurable alerts for important events
- **Sound Notifications**: Optional audio alerts

## 🚀 Quick Start

### 1. Start GUI Dashboard
```bash
# Basic GUI with default settings
./coyotekey -web -web-port 8080

# GUI with authentication
./coyotekey -web -web-auth -web-user admin -web-password secret123

# Complete GUI with all features
./coyotekey -web -real-time -notifications -web-api -db -ml
```

### 2. Access Dashboard
Open your web browser and navigate to:
- **Main Dashboard**: http://localhost:8080
- **With Authentication**: Login with configured credentials

### 3. Configure Attack
1. Go to **Attack Config** tab
2. Enter target URL or upload targets file
3. Enter wordlist or upload wordlist file
4. Configure advanced options
5. Click **Start Attack**

## 📱 Interface Overview

### 🏠 Dashboard Tab
- **Statistics Cards**: Total sessions, active sessions, requests, success rate
- **Progress Bar**: Live attack progress (when running)
- **Charts**: Success rate and response time trends
- **Activity Feed**: Real-time event stream

### 🚀 Attack Config Tab
- **Target Configuration**: URL, method, headers, success codes
- **Wordlist Management**: Text input or file upload
- **Performance Settings**: Threads, rate limiting, delays, timeouts
- **Advanced Features**: ML, database, evasion techniques
- **Action Buttons**: Start/stop attack controls

### 📋 Results Tab
- **Results Table**: Live table of attack results
- **Export Options**: JSON/CSV export functionality
- **Filtering**: Search and filter results
- **Pagination**: Handle large result sets

### 📊 Analytics Tab
- **Performance Metrics**: Response times, requests/second
- **Visual Charts**: Status codes, target distribution
- **Statistics**: Success rates, unique targets, keys found
- **Historical Data**: Trends and patterns

### ⚙️ Settings Tab
- **API Configuration**: API key management
- **Display Settings**: Refresh intervals, result limits
- **Preferences**: Auto-refresh, notifications, themes
- **System Info**: CPU, memory, disk, network usage

## 🔧 Configuration Options

### Web Dashboard Flags
```bash
-web                    # Enable web dashboard
-web-port 8080         # Dashboard port
-web-host localhost    # Dashboard host
-web-auth              # Enable authentication
-web-user admin        # Username
-web-password secret   # Password
-web-ssl               # Enable HTTPS
-web-cert cert.pem     # SSL certificate
-web-key key.pem       # SSL private key
```

### Real-time Features
```bash
-real-time             # Enable real-time monitoring
-notifications         # Enable notification system
-websocket             # Enable WebSocket support
-web-api               # Enable API endpoints
-api-key "key123"      # API authentication key
-cors                  # Enable CORS support
```

## 🌐 API Endpoints

The GUI communicates with the backend through RESTful API endpoints:

### Statistics & Monitoring
- `GET /api/stats` - Real-time attack statistics
- `GET /api/health` - System health status
- `GET /api/sessions` - Active attack sessions

### Data & Results
- `GET /api/results` - Recent attack results
- `GET /api/targets` - Target information
- `GET /api/analytics` - Comprehensive analytics

### Notifications & Alerts
- `GET /api/notifications` - User notifications
- `GET /api/alerts` - System alerts

### WebSocket Channels
- `stats` - Real-time statistics updates
- `notifications` - Live notifications
- `results` - Live attack results
- `alerts` - System alerts

## 🎨 Customization

### CSS Variables
The interface uses CSS custom properties for easy theming:

```css
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --success-color: #27ae60;
    --warning-color: #f39c12;
    --danger-color: #e74c3c;
}
```

### JavaScript Configuration
Customize dashboard behavior in `dashboard.js`:

```javascript
// Update intervals
const STATS_UPDATE_INTERVAL = 5000; // 5 seconds
const CHART_MAX_POINTS = 20;        // Chart data points

// Notification settings
const NOTIFICATION_TIMEOUT = 5000;   // Auto-hide timeout
const MAX_NOTIFICATIONS = 10;        // Maximum notifications
```

## 📱 Mobile Support

The GUI is fully responsive and optimized for mobile devices:

- **Touch-friendly**: Large buttons and touch targets
- **Responsive Grid**: Adaptive layout for different screen sizes
- **Mobile Navigation**: Collapsible navigation menu
- **Optimized Charts**: Mobile-optimized chart rendering

## 🔒 Security Features

### Authentication
- **Session Management**: Secure session handling
- **API Key Authentication**: Secure API access
- **CSRF Protection**: Cross-site request forgery protection

### HTTPS Support
```bash
# Enable HTTPS with SSL certificates
./coyotekey -web -web-ssl -web-cert server.crt -web-key server.key
```

### CORS Configuration
```bash
# Enable CORS for external integrations
./coyotekey -web -cors
```

## 🛠️ Development

### File Structure
```
web/
├── static/
│   ├── css/
│   │   └── dashboard.css    # Main stylesheet
│   ├── js/
│   │   └── dashboard.js     # Dashboard JavaScript
│   └── img/                 # Images and icons
└── templates/
    └── dashboard.html       # Main HTML template
```

### Building Custom Features
1. **Add CSS**: Extend `dashboard.css` with custom styles
2. **Add JavaScript**: Extend `dashboard.js` with new functionality
3. **Add API Endpoints**: Implement new backend endpoints
4. **Add WebSocket Channels**: Create new real-time channels

## 🚀 Production Deployment

### Recommended Configuration
```bash
./coyotekey \
  -web -web-port 443 -web-ssl \
  -web-cert /etc/ssl/certs/coyotekey.crt \
  -web-key /etc/ssl/private/coyotekey.key \
  -web-auth -web-user admin -web-password "$(openssl rand -base64 32)" \
  -real-time -notifications -websocket \
  -web-api -api-key "$(openssl rand -base64 32)" \
  -db -db-type postgres -persistent-storage \
  -ml -success-prediction -adaptive-learning
```

### Security Considerations
- Use strong passwords and API keys
- Enable HTTPS in production
- Configure proper firewall rules
- Regular security updates
- Monitor access logs

## 📊 Performance

### Optimization Tips
- **Enable Caching**: Use browser caching for static assets
- **Compress Assets**: Gzip compression for CSS/JS files
- **Optimize Charts**: Limit chart data points for performance
- **WebSocket Efficiency**: Use appropriate update intervals

### Resource Usage
- **Memory**: ~50MB for GUI components
- **CPU**: Minimal overhead for real-time updates
- **Network**: WebSocket connections for live data
- **Storage**: Static assets (~2MB total)

## 🎯 Use Cases

### Security Teams
- **Collaborative Testing**: Multi-user dashboard access
- **Real-time Monitoring**: Live attack progress tracking
- **Report Generation**: Export results for documentation
- **Historical Analysis**: Track testing over time

### Penetration Testers
- **Interactive Configuration**: Easy attack setup
- **Visual Feedback**: Real-time success/failure indication
- **Progress Tracking**: Monitor long-running attacks
- **Result Analysis**: Visual analytics and charts

### Developers
- **API Integration**: RESTful API for custom tools
- **WebSocket Streaming**: Real-time data integration
- **Custom Dashboards**: Embed CoyoteKey in existing tools
- **Automation**: Programmatic attack configuration

## 🆘 Troubleshooting

### Common Issues

**Dashboard not loading:**
```bash
# Check if web files exist
ls -la web/static/css/dashboard.css
ls -la web/static/js/dashboard.js
ls -la web/templates/dashboard.html
```

**WebSocket connection failed:**
- Check firewall settings
- Verify WebSocket support in browser
- Check for proxy/load balancer issues

**API authentication errors:**
- Verify API key configuration
- Check request headers
- Confirm endpoint permissions

### Debug Mode
```bash
# Enable verbose logging
./coyotekey -web -v

# Check browser developer console
# Network tab for API calls
# Console tab for JavaScript errors
```

## 📚 Examples

### Basic GUI Attack
```bash
./coyotekey -u https://api.example.com -w wordlist.txt -web
```

### Advanced GUI with All Features
```bash
./coyotekey \
  -u https://api.example.com -w wordlist.txt \
  -web -real-time -notifications -web-api \
  -db -ml -success-prediction \
  -web-auth -web-user admin -web-password secret123
```

### Production GUI Setup
```bash
./coyotekey \
  -targets production_targets.txt -w production_wordlist.txt \
  -web -web-port 443 -web-ssl -web-auth \
  -real-time -notifications -websocket -cors \
  -db -db-type postgres -persistent-storage -attack-analytics \
  -ml -success-prediction -adaptive-learning -pattern-recognition
```

---

## 🎉 Conclusion

CoyoteKey GUI transforms command-line API security testing into an intuitive, visual experience. With real-time monitoring, interactive configuration, and comprehensive analytics, it provides enterprise-grade capabilities through a modern web interface.

Perfect for security teams, penetration testers, and developers who need powerful API testing capabilities with an easy-to-use interface.
