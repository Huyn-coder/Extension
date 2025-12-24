#!/usr/bin/env python3
"""
Import whitelist from text file to MongoDB.
Usage: python3 import_whitelist.py --txt <file.txt>
"""
import os
import sys
import argparse
from urllib.parse import urlparse
from datetime import datetime
from pymongo import MongoClient

def main():
    parser = argparse.ArgumentParser(description='Import whitelist from TXT file')
    parser.add_argument('--txt', required=True, help='Path to whitelist TXT file')
    args = parser.parse_args()
    
    mongo_uri = os.getenv("MONGO_URI", "")
    if not mongo_uri:
        print("❌ MONGO_URI not set. Set it first:")
        print("   export MONGO_URI='mongodb://localhost:27017/phishshield'")
        sys.exit(1)
    
    if not os.path.exists(args.txt):
        print(f"❌ File not found: {args.txt}")
        sys.exit(1)
    
    try:
        client = MongoClient(mongo_uri)
        db = client.get_default_database() if "/" in mongo_uri.split("?")[0] else client["phishshield"]
        whitelist = db["whitelist"]
        
        print(f"📂 Reading whitelist from: {args.txt}")
        
        with open(args.txt, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"📊 Found {len(urls)} URLs")
        
        added = 0
        skipped = 0
        now = datetime.utcnow()
        
        for url in urls:
            try:
                # Parse URL to get host
                if not url.startswith('http'):
                    url = 'https://' + url
                
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                
                if not host:
                    print(f"⚠️  Invalid URL: {url}")
                    skipped += 1
                    continue
                
                # Check if already exists
                existing = whitelist.find_one({"host": host})
                if existing:
                    print(f"⏭️  Already exists: {host}")
                    skipped += 1
                    continue
                
                # Insert new entry
                doc = {
                    "url": url,
                    "host": host,
                    "source": "manual",
                    "imported_at": now,
                }
                
                whitelist.insert_one(doc)
                print(f"✅ Added: {host}")
                added += 1
                
            except Exception as e:
                print(f"❌ Error processing {url}: {e}")
                skipped += 1
        
        print("\n" + "="*60)
        print(f"✅ Import complete!")
        print(f"   Added: {added}")
        print(f"   Skipped: {skipped}")
        print(f"   Total in whitelist: {whitelist.count_documents({})}")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

