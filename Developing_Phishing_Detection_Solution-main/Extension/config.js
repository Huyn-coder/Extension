const PHISHSHIELD_CONFIG = {
  API_URL: "http://localhost:8000",
  ENDPOINTS: {
    CHECK_URL: "/api/check-url",
    REPORT_URL: "/api/report-url",
    WHITELIST: "/api/whitelist",
    BLACKLIST: "/api/blacklist",
    HEALTH: "/"
  },
  THRESHOLDS: {
    MALICIOUS: 0.6,
    SUSPICIOUS: 0.4
  },
  TRUSTED_PLATFORMS: [
    'facebook.com', 'm.facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'tiktok.com', 'pinterest.com', 'reddit.com',
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
    'sourceforge.net', 'npm.com', 'pypi.org', 'docker.com',
    'maps.google.com', 'openstreetmap.org', 'mapbox.com', 'waze.com',
    'earth.google.com', 'here.com',
    'dropbox.com', 'drive.google.com', 'onedrive.live.com', 'mediafire.com',
    'mega.nz', 'icloud.com', 'box.com',
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'researchgate.net', 'academia.edu', 'wikipedia.org',
    'paypal.com', 'stripe.com', 'visa.com', 'mastercard.com',
    'binance.com', 'coinbase.com'
  ],
  AUTO_SCAN: {
    ENABLED: true,
    SCAN_LINKS: true,
    SHOW_NOTIFICATIONS: true
  },
  CACHE: {
    TTL: 5 * 60 * 1000,
    MAX_SIZE: 1000
  }
};

if (typeof window !== 'undefined') {
  window.PHISHSHIELD_CONFIG = PHISHSHIELD_CONFIG;
}