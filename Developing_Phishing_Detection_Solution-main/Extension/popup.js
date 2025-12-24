// PhishShield Popup Script
// Connects with the FastAPI backend for phishing detection

class PhishShieldPopup {
  constructor() {
    this.config = PHISHSHIELD_CONFIG;
    this.currentUrl = '';
    this.currentTabId = null;
    this.init();
  }

  async init() {
    // Get current tab info
    await this.getCurrentTab();
    
    // Check API connection
    await this.checkApiConnection();
    
    // Scan current URL
    await this.scanCurrentUrl();
    
    // Setup event listeners
    this.setupEventListeners();
    
    // Load page links stats
    this.loadPageLinksStats();
  }

  async getCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        this.currentUrl = tab.url;
        this.currentTabId = tab.id;
        document.getElementById('currentUrl').textContent = this.truncateUrl(tab.url, 80);
      }
    } catch (error) {
      console.error('Error getting current tab:', error);
      document.getElementById('currentUrl').textContent = 'Unable to get URL';
    }
  }

  truncateUrl(url, maxLength) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  }

  async checkApiConnection() {
    const statusEl = document.getElementById('apiStatus');
    try {
      const response = await fetch(`${this.config.API_URL}${this.config.ENDPOINTS.HEALTH}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (response.ok) {
        statusEl.innerHTML = '<div class="status-dot"></div><span>Connected</span>';
        statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
        statusEl.style.borderColor = 'rgba(16, 185, 129, 0.3)';
        statusEl.style.color = '#10b981';
        return true;
      }
    } catch (error) {
      console.error('API connection error:', error);
    }
    
    statusEl.innerHTML = '<span>⚠️</span><span>Offline</span>';
    statusEl.style.background = 'rgba(239, 68, 68, 0.15)';
    statusEl.style.borderColor = 'rgba(239, 68, 68, 0.3)';
    statusEl.style.color = '#ef4444';
    return false;
  }

  async scanCurrentUrl() {
    const container = document.getElementById('riskCardContainer');
    const loadingState = document.getElementById('loadingState');
    const actionButtons = document.getElementById('actionButtons');
    
    // Skip non-http URLs
    if (!this.currentUrl || !this.currentUrl.startsWith('http')) {
      container.innerHTML = this.renderInfoCard('Internal Page', 'This is a browser internal page and cannot be scanned.');
      actionButtons.style.display = 'none';
      return;
    }

    // Show loading
    loadingState.style.display = 'block';
    actionButtons.style.display = 'none';

    try {
      const response = await fetch(`${this.config.API_URL}${this.config.ENDPOINTS.CHECK_URL}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: this.currentUrl })
      });

      const data = await response.json();
      
      if (data.error) {
        throw new Error(data.error);
      }

      // Render risk card
      container.innerHTML = this.renderRiskCard(data);
      actionButtons.style.display = 'grid';
      
      // Store result for badge update
      chrome.runtime.sendMessage({
        action: 'updateBadge',
        risk: data.risk,
        tabId: this.currentTabId
      });

    } catch (error) {
      console.error('Scan error:', error);
      container.innerHTML = this.renderErrorCard('Connection Error', 'Unable to connect to PhishShield server. Please make sure the backend is running.');
      actionButtons.style.display = 'none';
    }
  }

  renderRiskCard(data) {
    const icons = {
      safe: '✅',
      suspicious: '⚠️',
      malicious: '🚨'
    };

    const titles = {
      safe: 'Safe Website',
      suspicious: 'Suspicious URL',
      malicious: 'Phishing Detected!'
    };

    const descriptions = {
      safe: 'This website appears to be legitimate and safe to use.',
      suspicious: 'This URL shows some suspicious patterns. Proceed with caution.',
      malicious: 'WARNING: This website is likely a phishing attempt. Do not enter any personal information!'
    };

    const score = (data.score * 100).toFixed(1);
    const reasons = data.reasons || [];

    return `
      <div class="risk-card ${data.risk}">
        <div class="risk-icon">${icons[data.risk]}</div>
        <div class="risk-title">${titles[data.risk]}</div>
        <div class="risk-description">${descriptions[data.risk]}</div>
        <div class="risk-score">
          <span>Risk Score:</span>
          <span style="color: ${this.getScoreColor(data.score)}">${score}%</span>
        </div>
        ${reasons.length > 0 ? `
          <div class="reason-tags">
            ${reasons.map(r => `<span class="reason-tag">${this.formatReason(r)}</span>`).join('')}
          </div>
        ` : ''}
      </div>
    `;
  }

  renderInfoCard(title, description) {
    return `
      <div class="risk-card safe">
        <div class="risk-icon">ℹ️</div>
        <div class="risk-title">${title}</div>
        <div class="risk-description">${description}</div>
      </div>
    `;
  }

  renderErrorCard(title, description) {
    return `
      <div class="error-state">
        <div class="error-icon">🔌</div>
        <div class="error-title">${title}</div>
        <div class="error-desc">${description}</div>
      </div>
    `;
  }

  getScoreColor(score) {
    if (score >= 0.8) return '#ef4444';
    if (score >= 0.5) return '#f59e0b';
    return '#10b981';
  }

formatReason(reason) {
    const reasonMap = {
        // Basic statuses
        'whitelist': '✅ Whitelisted',
        'blacklist': '🚫 Blacklisted',
        
        // AI & Model
        'model_probability': '🤖 AI Analysis', 
        'ML Analysis': '🤖 AI Analysis', 

        // Specific Features (The ones you saw)
        'has_https': '🔒 Secured with HTTPS',
        'no_https': '⚠️ Missing HTTPS',
        'personal_domain_pattern': '⚠️ Suspicious Domain Pattern',
        'ip_address_url': '⚠️ IP Address URL',
        'no_suspicious_keywords': '✅ No Suspicious Keywords',
        'sus_keyword': '🚫 Suspicious Keywords Found',
        'long_url': '📏 URL Too Long',
        'short_url': '🔗 Shortened URL',
        'trusted_pattern': '🛡️ Trusted Pattern',
        
        // Score adjustments
        'score_adjusted_for_https': '🔒 HTTPS Bonus',
        'score_adjusted_for_known_tld': '🌐 Known TLD',
        'score_adjusted_for_short_url': '🔗 Short URL Penalty'
    };

    // If the reason exists in the map, use it. 
    // If not, replace underscores (_) with spaces to make it readable (fallback).
    return reasonMap[reason] || reason.replace(/_/g, ' ');
}

  setupEventListeners() {
    // Re-scan button
    document.getElementById('scanBtn').addEventListener('click', () => {
      this.scanCurrentUrl();
    });

    // Whitelist button
    document.getElementById('whitelistBtn').addEventListener('click', () => {
      this.addToList('whitelist');
    });

    // Blacklist button
    document.getElementById('blacklistBtn').addEventListener('click', () => {
      this.addToList('blacklist');
    });

    // Report button
    document.getElementById('reportBtn').addEventListener('click', () => {
      this.reportUrl();
    });

    // Scan all links button
    document.getElementById('scanLinksBtn').addEventListener('click', () => {
      this.scanPageLinks();
    });
  }

  async addToList(listType) {
    if (!this.currentUrl.startsWith('http')) {
      this.showToast('Cannot add internal pages to lists', 'error');
      return;
    }

    const endpoint = listType === 'whitelist' 
      ? this.config.ENDPOINTS.WHITELIST 
      : this.config.ENDPOINTS.BLACKLIST;

    try {
      const response = await fetch(`${this.config.API_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: this.currentUrl })
      });

      const data = await response.json();

      if (data.ok) {
        this.showToast(`Added to ${listType} successfully!`, 'success');
        // Re-scan to update the UI
        setTimeout(() => this.scanCurrentUrl(), 500);
      } else {
        throw new Error(data.error || 'Unknown error');
      }
    } catch (error) {
      console.error(`Error adding to ${listType}:`, error);
      this.showToast(`Failed to add to ${listType}`, 'error');
    }
  }

  async reportUrl() {
    if (!this.currentUrl.startsWith('http')) {
      this.showToast('Cannot report internal pages', 'error');
      return;
    }

    try {
      const response = await fetch(`${this.config.API_URL}${this.config.ENDPOINTS.REPORT_URL}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: this.currentUrl })
      });

      const data = await response.json();

      if (data.ok) {
        this.showToast('URL reported for review. Thank you!', 'success');
      } else {
        throw new Error(data.error || 'Unknown error');
      }
    } catch (error) {
      console.error('Error reporting URL:', error);
      this.showToast('Failed to report URL', 'error');
    }
  }

  async loadPageLinksStats() {
    try {
      const data = await chrome.storage.local.get(['pageLinksStats']);
      if (data.pageLinksStats && data.pageLinksStats[this.currentUrl]) {
        const stats = data.pageLinksStats[this.currentUrl];
        this.updateLinksStats(stats);
      }
    } catch (error) {
      console.error('Error loading page links stats:', error);
    }
  }

  updateLinksStats(stats) {
    document.getElementById('linksCount').textContent = `${stats.total || 0} links`;
    document.getElementById('safeCount').textContent = stats.safe || 0;
    document.getElementById('suspiciousCount').textContent = stats.suspicious || 0;
    document.getElementById('maliciousCount').textContent = stats.malicious || 0;
  }

  async scanPageLinks() {
    const btn = document.getElementById('scanLinksBtn');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Scanning...';

    try {
      // Get links from content script
      const response = await chrome.tabs.sendMessage(this.currentTabId, { action: 'getLinks' });
      
      if (!response || !response.links) {
        throw new Error('No links found');
      }

      const links = [...new Set(response.links)]; // Remove duplicates
      document.getElementById('linksCount').textContent = `${links.length} links`;

      // Scan each link
      const stats = { total: links.length, safe: 0, suspicious: 0, malicious: 0 };
      const results = [];

      for (const link of links.slice(0, 50)) { // Limit to 50 links
        try {
          const checkResponse = await fetch(`${this.config.API_URL}${this.config.ENDPOINTS.CHECK_URL}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: link })
          });

          const data = await checkResponse.json();
          results.push({ url: link, ...data });
          
          if (data.risk === 'safe') stats.safe++;
          else if (data.risk === 'suspicious') stats.suspicious++;
          else if (data.risk === 'malicious') stats.malicious++;

          this.updateLinksStats(stats);
        } catch (error) {
          console.error('Error scanning link:', link, error);
        }
      }

      // Save stats
      const pageLinksStats = (await chrome.storage.local.get(['pageLinksStats'])).pageLinksStats || {};
      pageLinksStats[this.currentUrl] = stats;
      await chrome.storage.local.set({ pageLinksStats });

      // Send results to content script for highlighting
      chrome.tabs.sendMessage(this.currentTabId, {
        action: 'highlightLinks',
        results: results
      });

      this.showToast(`Scanned ${links.length} links!`, 'success');
    } catch (error) {
      console.error('Error scanning page links:', error);
      this.showToast('Failed to scan page links', 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>🔍</span> Scan All Links on Page';
    }
  }

  showToast(message, type) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;

    setTimeout(() => {
      toast.classList.remove('show');
    }, 3000);
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new PhishShieldPopup();
});
