#!/usr/bin/env python3
"""Review all database collections and their contents."""
import os
import sys
from pymongo import MongoClient
from datetime import datetime

mongo_uri = os.getenv("MONGO_URI", "")
if not mongo_uri:
    print("❌ MONGO_URI not set. Set it first:")
    print("   export MONGO_URI='mongodb://localhost:27017/phishshield'")
    sys.exit(1)

try:
    client = MongoClient(mongo_uri)
    db = client.get_default_database() if "/" in mongo_uri.split("?")[0] else client["phishshield"]
    
    print("="*60)
    print("📊 PHISHSHIELD DATABASE REVIEW")
    print("="*60)
    print(f"Database: {db.name}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Get all collections
    collections = db.list_collection_names()
    print(f"📁 Collections: {collections}\n")
    
    # Review each collection
    for coll_name in collections:
        coll = db[coll_name]
        count = coll.count_documents({})
        
        print("─"*60)
        print(f"📋 Collection: {coll_name}")
        print(f"   Total documents: {count}")
        
        if count > 0:
            # Show sample documents
            print(f"   Sample entries (first 3):")
            for i, doc in enumerate(coll.find().limit(3), 1):
                doc_id = doc.get("_id", "N/A")
                if coll_name == "blacklist":
                    host = doc.get("host", "N/A")
                    url = doc.get("url", "N/A")
                    source = doc.get("source", "unknown")
                    print(f"      {i}. Host: {host}")
                    print(f"         URL: {url}")
                    print(f"         Source: {source}")
                elif coll_name == "whitelist":
                    host = doc.get("host", "N/A")
                    url = doc.get("url", "N/A")
                    print(f"      {i}. Host: {host}")
                    print(f"         URL: {url}")
                elif coll_name == "reports":
                    url = doc.get("url", "N/A")
                    host = doc.get("host", "N/A")
                    reason = doc.get("reason", "N/A")
                    created = doc.get("createdAt", "N/A")
                    print(f"      {i}. URL: {url}")
                    print(f"         Host: {host}")
                    print(f"         Reason: {reason}")
                    print(f"         Created: {created}")
            
            # Show statistics
            if coll_name == "blacklist":
                sources = coll.distinct("source")
                print(f"   Sources: {sources}")
                for source in sources:
                    src_count = coll.count_documents({"source": source})
                    print(f"      - {source}: {src_count}")
            
            print()
    
    print("="*60)
    print("✅ Database review complete!")
    print("="*60)
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("\n💡 Make sure MongoDB is running.")

