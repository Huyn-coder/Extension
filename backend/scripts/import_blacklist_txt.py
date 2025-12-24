#!/usr/bin/env python3
"""
Import blacklist from TXT file (one URL per line) into MongoDB blacklist collection.

Usage:
  MONGO_URI="mongodb://localhost:27017/phishshield" \
  python backend/scripts/import_blacklist_txt.py --txt /path/to/blacklist.txt
"""

import argparse
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

from pymongo import MongoClient


def main():
    parser = argparse.ArgumentParser(description="Import blacklist from TXT file")
    parser.add_argument("--txt", required=True, help="Path to TXT file (one URL per line)")
    parser.add_argument("--limit", type=int, default=0, help="Limit rows for quick test")
    parser.add_argument("--source", default="manual", help="Source label (default: manual)")
    args = parser.parse_args()

    mongo_uri = os.getenv("MONGO_URI", "")
    if not mongo_uri:
        raise SystemExit("MONGO_URI is required, e.g. mongodb://localhost:27017/phishshield")

    if not os.path.exists(args.txt):
        raise SystemExit(f"File not found: {args.txt}")

    client = MongoClient(mongo_uri)
    db = client.get_default_database() if "/" in mongo_uri.split("?")[0] else client["phishshield"]
    blacklist = db["blacklist"]
    blacklist.create_index("host", background=True)
    blacklist.create_index("url", background=True)

    total = 0
    upserts = 0
    errors = 0
    now = datetime.utcnow()

    with open(args.txt, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    continue
                host = (parsed.hostname or "").lower()  # Normalize to lowercase
                
                doc = {
                    "url": url,
                    "host": host,
                    "source": args.source,
                    "imported_at": now,
                }
                blacklist.update_one(
                    {"host": host},  # Use host as unique key (more reliable)
                    {"$set": doc},
                    upsert=True,
                )
                upserts += 1
            except Exception as e:
                errors += 1
                print(f"Error processing {url}: {e}", file=sys.stderr)
            
            total += 1
            if args.limit and total >= args.limit:
                break

    print(f"Processed {total} lines, imported/updated {upserts} entries, {errors} errors")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

