// PhishShield Configuration
const PHISHSHIELD_CONFIG = {
  // Backend API URL - Change this to your production server
  API_URL: "http://localhost:8000",
  
  // API Endpoints
  ENDPOINTS: {
    CHECK_URL: "/api/check-url",
    REPORT_URL: "/api/report-url",
    WHITELIST: "/api/whitelist",
    BLACKLIST: "/api/blacklist",
    HEALTH: "/"
  },
  
  // Risk thresholds
  THRESHOLDS: {
    MALICIOUS: 0.8,
    SUSPICIOUS: 0.5
  },
  
  // Auto-scan settings
  AUTO_SCAN: {
    ENABLED: true,
    SCAN_LINKS: true,
    SHOW_NOTIFICATIONS: true
  },
  
  // Cache settings (in milliseconds)
  CACHE: {
    TTL: 5 * 60 * 1000, // 5 minutes
    MAX_SIZE: 1000
  }
};

// Make config available globally
if (typeof window !== 'undefined') {
  window.PHISHSHIELD_CONFIG = PHISHSHIELD_CONFIG;
}

