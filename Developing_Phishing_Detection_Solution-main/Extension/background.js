// PhishShield Background Service Worker
// Handles real-time URL scanning and badge updates

// Configuration (duplicated here since service workers can't import)
const API_CONFIG = {
  API_URL: "http://localhost:8000",
  ENDPOINTS: {
    CHECK_URL: "/api/check-url",
    HEALTH: "/"
  }
};

// Cache for URL scan results
const urlCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Badge colors
const BADGE_COLORS = {
  safe: '#10b981',
  suspicious: '#f59e0b',
  malicious: '#ef4444',
  loading: '#3b82f6',
  error: '#6b7280'
};

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishShield extension installed');
  
  // Set default settings
  chrome.storage.local.set({
    autoScan: true,
    showNotifications: true,
    scanLinks: true,
    pageLinksStats: {}
  });

  // Set default badge
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.loading });
});

// Listen for tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url && tab.url.startsWith('http')) {
      await scanUrl(tab.url, tab.id);
    } else {
      // Clear badge for non-http pages
      chrome.action.setBadgeText({ text: '', tabId: tab.id });
    }
  } catch (error) {
    console.error('Error on tab activation:', error);
  }
});

// Listen for tab updates (navigation)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    await scanUrl(tab.url, tabId);
    
    // Inject content script if needed
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ['config.js', 'content.js']
      });
    } catch (error) {
      // Content script might already be injected
      console.log('Content script injection:', error.message);
    }
  }
});

// Listen for web navigation completed
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId === 0 && details.url.startsWith('http')) {
    await scanUrl(details.url, details.tabId);
  }
});

// Scan URL and update badge
async function scanUrl(url, tabId) {
  // Show loading state
  chrome.action.setBadgeText({ text: '...', tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.loading, tabId: tabId });

  // Check cache first
  const cacheKey = url.toLowerCase();
  const cached = urlCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    updateBadge(cached.result.risk, tabId);
    return cached.result;
  }

  try {
    const response = await fetch(`${API_CONFIG.API_URL}${API_CONFIG.ENDPOINTS.CHECK_URL}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });

    const result = await response.json();

    if (result.error) {
      throw new Error(result.error);
    }

    // Cache the result
    urlCache.set(cacheKey, {
      result: result,
      timestamp: Date.now()
    });

    // Clean old cache entries
    cleanCache();

    // Update badge
    updateBadge(result.risk, tabId);

    // Show notification for dangerous sites
    if (result.risk === 'malicious') {
      showNotification(url, result);
    }

    return result;
  } catch (error) {
    console.error('Error scanning URL:', error);
    chrome.action.setBadgeText({ text: '!', tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS.error, tabId: tabId });
    return null;
  }
}

// Update extension badge
function updateBadge(risk, tabId) {
  const badgeConfig = {
    safe: { text: '✓', color: BADGE_COLORS.safe },
    suspicious: { text: '!', color: BADGE_COLORS.suspicious },
    malicious: { text: '✗', color: BADGE_COLORS.malicious }
  };

  const config = badgeConfig[risk] || { text: '?', color: BADGE_COLORS.error };
  
  chrome.action.setBadgeText({ text: config.text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId: tabId });
}

// Show notification for malicious sites
function showNotification(url, result) {
  chrome.storage.local.get(['showNotifications'], (data) => {
    if (data.showNotifications !== false) {
      const hostname = new URL(url).hostname;
      
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon128.png',
        title: '🚨 Phishing Alert!',
        message: `Warning: ${hostname} may be a phishing site. Risk score: ${(result.score * 100).toFixed(0)}%`,
        priority: 2
      });
    }
  });
}

// Clean expired cache entries
function cleanCache() {
  const now = Date.now();
  for (const [key, value] of urlCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      urlCache.delete(key);
    }
  }
  
  // Limit cache size
  if (urlCache.size > 1000) {
    const entries = Array.from(urlCache.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    for (let i = 0; i < entries.length - 500; i++) {
      urlCache.delete(entries[i][0]);
    }
  }
}

// Listen for messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'updateBadge') {
    updateBadge(request.risk, request.tabId);
    sendResponse({ success: true });
  }
  
  else if (request.action === 'scanUrl') {
    scanUrl(request.url, request.tabId || sender.tab?.id)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true; // Keep channel open for async response
  }
  
  else if (request.action === 'checkUrl') {
    // Quick check for content script
    fetch(`${API_CONFIG.API_URL}${API_CONFIG.ENDPOINTS.CHECK_URL}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
    .then(response => response.json())
    .then(data => sendResponse(data))
    .catch(error => sendResponse({ error: error.message }));
    return true;
  }
  
  else if (request.action === 'getStats') {
    chrome.storage.local.get(['pageLinksStats'], (data) => {
      sendResponse(data.pageLinksStats || {});
    });
    return true;
  }
  
  else if (request.action === 'linksExtracted') {
    // Handle links extracted from content script
    if (sender.tab) {
      chrome.storage.local.get(['extractedLinks'], (data) => {
        const links = data.extractedLinks || {};
        links[sender.tab.url] = request.links;
        chrome.storage.local.set({ extractedLinks: links });
      });
    }
  }
});

// Startup check
chrome.runtime.onStartup.addListener(() => {
  console.log('PhishShield service worker started');
  
  // Check API health
  fetch(`${API_CONFIG.API_URL}${API_CONFIG.ENDPOINTS.HEALTH}`)
    .then(response => {
      if (response.ok) {
        console.log('API connection successful');
      }
    })
    .catch(error => {
      console.error('API connection failed:', error);
    });
});
