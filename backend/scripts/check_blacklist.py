#!/usr/bin/env python3
"""Quick script to check if a URL/host is in blacklist."""
import os
import sys
from urllib.parse import urlparse
from pymongo import MongoClient

mongo_uri = os.getenv("MONGO_URI", "")
if not mongo_uri:
    print("❌ MONGO_URI not set. Set it first:")
    print("   export MONGO_URI='mongodb://localhost:27017/phishshield'")
    sys.exit(1)

try:
    client = MongoClient(mongo_uri)
    db = client.get_default_database() if "/" in mongo_uri.split("?")[0] else client["phishshield"]
    blacklist = db["blacklist"]
    
    # Test URLs
    test_urls = [
        "http://metamaskkkkkk-wallet.webflow.io/",
        "https://metamaskkkkkk-wallet.webflow.io",
        "memtaskelogiyn.webflow.io",
        "chaingpt-pad.net/pools/aster-giveaway"
    ]
    
    print(f"📊 Blacklist size: {blacklist.count_documents({})}")
    print("\n🔍 Testing URLs:\n")
    
    for url in test_urls:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        
        found = blacklist.find_one({"host": host})
        if found:
            print(f"✅ {url}")
            print(f"   Host: {host} → FOUND in blacklist")
            print(f"   Source: {found.get('source', 'unknown')}\n")
        else:
            print(f"❌ {url}")
            print(f"   Host: {host} → NOT FOUND in blacklist\n")
    
    # Show sample entries
    print("\n📋 Sample blacklist entries (first 5):")
    for doc in blacklist.find().limit(5):
        print(f"   - {doc.get('host')} ({doc.get('source', 'unknown')})")
        
except Exception as e:
    print(f"❌ Error: {e}")
    print("\n💡 Make sure:")
    print("   1. MongoDB is running")
    print("   2. Blacklist has been imported:")
    print("      python3 backend/scripts/import_blacklist_txt.py --txt Machine-Learning-main/blacklist.txt")

