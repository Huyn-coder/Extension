#!/usr/bin/env python3
"""
Smart whitelist patterns to reduce false positives.
"""
import re
from typing import List, Tuple

# Trusted domain patterns
TRUSTED_PATTERNS = [
    # Developer platforms
    (r'.*\.(github\.io|gitlab\.io|gitbook\.io)$', 'developer_platform'),
    (r'.*\.(netlify\.app|vercel\.app|herokuapp\.com)$', 'hosting_platform'),
    (r'.*\.(azurewebsites\.net|amazonaws\.com|cloudfront\.net)$', 'cloud_provider'),
    (r'.*\.(firebaseapp\.com|web\.app|appspot\.com)$', 'google_cloud'),
    
    # Educational institutions
    (r'.*\.(edu|edu\.vn|edu\.au|edu\.uk|ac\.uk|ac\.jp)$', 'educational'),
    
    # Government
    (r'.*\.(gov|gov\.uk|gov\.au|gov\.vn|mil)$', 'government'),
    
    # Well-known tech companies & platforms
    (r'.*(google|microsoft|apple|amazon|facebook|twitter|meta)\.com$', 'tech_giant'),
    (r'.*(youtube|youtu\.be).*$', 'google_platform'),
    (r'.*(instagram|whatsapp|messenger)\.com$', 'meta_platform'),
    (r'.*(linkedin|github|gitlab|bitbucket)\.com$', 'professional_platform'),
    (r'.*(netflix|spotify|twitch|discord|slack|zoom)\.com$', 'popular_service'),
    (r'.*(reddit|quora|medium)\.com$', 'social_platform'),
    (r'.*(paypal|stripe|visa|mastercard)\.com$', 'payment_service'),
    (r'.*(dropbox|onedrive|icloud)\.com$', 'cloud_storage'),
    (r'.*(adobe|canva|figma)\.com$', 'creative_tools'),
    (r'.*(notion|trello|asana|monday)\.com$', 'productivity_tools'),
    (r'.*(chatgpt|openai|anthropic|claude)\.com$', 'ai_platform'),
    
    # Open source & community
    (r'.*\.(mozilla\.org|wikipedia\.org|wikimedia\.org)$', 'open_source'),
    (r'.*\.(stackoverflow\.com|stackexchange\.com)$', 'developer_community'),
    
    # Security & research
    (r'.*\.(virustotal\.com|hybrid-analysis\.com|urlscan\.io)$', 'security_research'),
    (r'.*\.(shodan\.io|securitytrails\.com)$', 'security_tools'),
]

# Suspicious TLDs (higher false positive risk but commonly used legitimately)
LEGITIMATE_NEW_TLDS = [
    '.tech',  # Often used by developers
    '.io',    # Popular with startups
    '.dev',   # Google-owned, developer-focused
    '.app',   # Google-owned
    '.ai',    # AI companies
    '.xyz',   # Popular but risky
    '.co',    # Colombia but used globally
]

# Keywords that might be legitimate in context
CONTEXT_KEYWORDS = {
    'lab': ['laboratory', 'research', 'test environment'],
    'dev': ['developer', 'development'],
    'test': ['testing', 'qa'],
    'staging': ['staging environment'],
    'demo': ['demonstration'],
}


def check_trusted_pattern(url: str) -> Tuple[bool, str]:
    """
    Check if URL matches any trusted pattern.
    
    Args:
        url: URL to check
        
    Returns:
        (is_trusted, reason)
    """
    url_lower = url.lower()
    
    for pattern, category in TRUSTED_PATTERNS:
        if re.match(pattern, url_lower, re.IGNORECASE):
            return True, f"trusted_pattern:{category}"
    
    return False, ""


def adjust_score_for_context(url: str, base_score: float) -> Tuple[float, List[str]]:
    """
    Adjust ML score based on contextual factors.
    Reduces false positives for legitimate-looking URLs.
    
    Args:
        url: URL to analyze
        base_score: ML model score (0-1, higher = more dangerous)
        
    Returns:
        (adjusted_score, reasons)
    """
    adjustments = []
    adjusted_score = base_score
    
    # Check for trusted patterns first
    is_trusted, reason = check_trusted_pattern(url)
    if is_trusted:
        # Heavily discount score for trusted patterns
        adjusted_score *= 0.3
        adjustments.append(reason)
        return adjusted_score, adjustments
    
    # Parse URL components
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    
    # Check for HTTPS (slight bonus)
    if parsed.scheme == 'https':
        adjusted_score *= 0.95
        adjustments.append("has_https")
    
    # Check for subdomain context
    parts = hostname.split('.')
    if len(parts) > 2:
        subdomain = parts[0]
        if subdomain in CONTEXT_KEYWORDS:
            # Subdomain might be legitimate (lab, dev, test, etc.)
            adjusted_score *= 0.85
            adjustments.append(f"legitimate_subdomain:{subdomain}")
    
    # Check if using new TLD that's commonly legitimate
    for tld in LEGITIMATE_NEW_TLDS:
        if hostname.endswith(tld):
            # Slightly reduce suspicion for these TLDs
            adjusted_score *= 0.9
            adjustments.append(f"legitimate_tld:{tld}")
            break
    
    # Check for personal domains (name + surname patterns)
    name_pattern = r'^[a-z]+[a-z]+\.'  # firstname+lastname pattern
    if re.match(name_pattern, hostname):
        # Might be personal website
        adjusted_score *= 0.85
        adjustments.append("personal_domain_pattern")
    
    # If URL has no suspicious keywords
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 
                          'confirm', 'password', 'signin', 'banking']
    has_suspicious = any(kw in url.lower() for kw in suspicious_keywords)
    if not has_suspicious:
        adjusted_score *= 0.9
        adjustments.append("no_suspicious_keywords")
    
    # Ensure score stays in valid range
    adjusted_score = max(0.0, min(1.0, adjusted_score))
    
    return adjusted_score, adjustments


def should_whitelist_automatically(url: str) -> Tuple[bool, str]:
    """
    Determine if URL should be automatically whitelisted.
    
    Args:
        url: URL to check
        
    Returns:
        (should_whitelist, reason)
    """
    is_trusted, reason = check_trusted_pattern(url)
    if is_trusted:
        return True, reason
    
    return False, ""


# Example usage
if __name__ == "__main__":
    test_urls = [
        "https://lab.dylantran.tech/",
        "https://example.github.io/",
        "https://my-app.netlify.app/",
        "https://secure-login-paypal.com/",
        "https://harvard.edu/",
        "https://gov.uk/",
    ]
    
    print("Testing Smart Whitelist:\n")
    for url in test_urls:
        is_trusted, reason = check_trusted_pattern(url)
        print(f"URL: {url}")
        print(f"  Trusted: {is_trusted}")
        print(f"  Reason: {reason}\n")
        
        # Test score adjustment
        base_score = 0.85
        adjusted, adjustments = adjust_score_for_context(url, base_score)
        print(f"  Score: {base_score} → {adjusted:.3f}")
        print(f"  Adjustments: {adjustments}\n")
        print("-" * 60)

