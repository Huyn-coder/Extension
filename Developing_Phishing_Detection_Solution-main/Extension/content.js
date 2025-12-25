// PhishShield Content Script
// Runs on web pages to extract links and highlight dangerous ones

(function() {
  'use strict';

  // Prevent multiple injections
  if (window.phishShieldInjected) return;
  window.phishShieldInjected = true;

  // Store scan results for links
  const linkResults = new Map();

  // Listen for messages from popup and background
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getLinks') {
      const links = extractAllLinks();
      sendResponse({ links: links });
    }
    
    else if (request.action === 'highlightLinks') {
      highlightLinks(request.results);
      sendResponse({ success: true });
    }
    
    else if (request.action === 'scanPageLinks') {
      const links = extractAllLinks();
      sendResponse({ links: links });
    }

    // --- PHẦN MỚI THÊM VÀO ---
    // Nhận lệnh hiển thị cảnh báo từ background.js
    else if (request.action === 'showWarning') {
      // Kiểm tra xem người dùng đã từng chọn "Continue" cho trang này chưa
      const dismissed = sessionStorage.getItem('phishshield-dismissed-' + window.location.hostname);
      if (!dismissed) {
        showPageWarning(request.result);
      }
    }
    // -------------------------
    
    return true;
  });

  // Extract all links from the page
  function extractAllLinks() {
    const links = [];
    const anchorElements = document.querySelectorAll('a[href]');
    
    anchorElements.forEach((anchor) => {
      const href = anchor.href;
      
      // Filter out non-http links
      if (href && 
          (href.startsWith('http://') || href.startsWith('https://')) &&
          !href.startsWith('javascript:') && 
          !href.startsWith('mailto:') && 
          !href.startsWith('tel:')) {
        links.push(href);
      }
    });
    
    return [...new Set(links)]; // Remove duplicates
  }

  // Highlight links based on scan results
  function highlightLinks(results) {
    if (!results || !Array.isArray(results)) return;

    // Store results
    results.forEach(result => {
      linkResults.set(result.url.toLowerCase(), result);
    });

    // Find and highlight all links
    const anchors = document.querySelectorAll('a[href]');
    
    anchors.forEach((anchor) => {
      const href = anchor.href?.toLowerCase();
      if (!href) return;

      const result = linkResults.get(href);
      if (!result) return;

      // Remove existing indicators
      anchor.classList.remove('phishshield-safe', 'phishshield-suspicious', 'phishshield-malicious');
      
      // Remove old tooltips
      const oldTooltip = anchor.querySelector('.phishshield-tooltip');
      if (oldTooltip) oldTooltip.remove();

      // Add risk class
      anchor.classList.add(`phishshield-${result.risk}`);
      anchor.dataset.phishshieldRisk = result.risk;
      anchor.dataset.phishshieldScore = result.score;

      // Add tooltip for suspicious and malicious links
      if (result.risk === 'suspicious' || result.risk === 'malicious') {
        addTooltip(anchor, result);
      }
    });
  }

  // Add tooltip to dangerous links
  function addTooltip(anchor, result) {
    const tooltip = document.createElement('div');
    tooltip.className = 'phishshield-tooltip';
    
    const icon = result.risk === 'malicious' ? '🚨' : '⚠️';
    const title = result.risk === 'malicious' ? 'Phishing Alert!' : 'Suspicious Link';
    const score = (result.score * 100).toFixed(0);
    
    tooltip.innerHTML = `
      <div class="phishshield-tooltip-header">
        <span class="phishshield-tooltip-icon">${icon}</span>
        <span class="phishshield-tooltip-title">${title}</span>
      </div>
      <div class="phishshield-tooltip-score">Risk Score: ${score}%</div>
      <div class="phishshield-tooltip-hint">Click with caution!</div>
    `;

    // Position tooltip
    anchor.style.position = 'relative';
    anchor.appendChild(tooltip);
  }

  // Add warning overlay for malicious pages
  function showPageWarning(result) {
    // Check if warning already exists
    if (document.getElementById('phishshield-page-warning')) return;

    const overlay = document.createElement('div');
    overlay.id = 'phishshield-page-warning';
    overlay.innerHTML = `
      <div class="phishshield-warning-content">
        <div class="phishshield-warning-icon">🚨</div>
        <h1>PhishShield Warning</h1>
        <p class="phishshield-warning-main">This website may be a phishing attempt!</p>
        <p class="phishshield-warning-detail">
          Our AI detected suspicious patterns on this page.<br>
          Risk Score: <strong>${(result.score * 100).toFixed(0)}%</strong>
        </p>
        <div class="phishshield-warning-reasons">
          ${result.reasons?.map(r => `<span class="phishshield-reason-tag">${r}</span>`).join('') || ''}
        </div>
        <div class="phishshield-warning-buttons">
          <button class="phishshield-btn-leave" onclick="history.back()">← Go Back (Safe)</button>
          <button class="phishshield-btn-proceed" id="phishshield-proceed">
            Continue anyway (Not recommended)
          </button>
        </div>
        <p class="phishshield-warning-tip">
           Be careful when enter passwords or personal information on suspicious websites.
        </p>
      </div>
    `;

    document.body.appendChild(overlay);

    // Handle proceed button
    document.getElementById('phishshield-proceed').addEventListener('click', () => {
      overlay.remove();
      // Store that user chose to proceed
      sessionStorage.setItem('phishshield-dismissed-' + window.location.hostname, 'true');
    });
  }

  // Check current page on load
  async function checkCurrentPage() {
    const dismissed = sessionStorage.getItem('phishshield-dismissed-' + window.location.hostname);
    if (dismissed) return;

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'checkUrl',
        url: window.location.href
      });

      if (response && response.risk === 'malicious') {
        showPageWarning(response);
      }
    } catch (error) {
      console.log('PhishShield: Could not check page', error);
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(checkCurrentPage, 500);
    });
  } else {
    setTimeout(checkCurrentPage, 500);
  }

  // Auto-extract links and send to background
  setTimeout(() => {
    const links = extractAllLinks();
    if (links.length > 0) {
      chrome.runtime.sendMessage({
        action: 'linksExtracted',
        links: links
      });
    }
  }, 2000);

})();