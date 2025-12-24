# PhishShield Backend API

## Run

```bash
cd backend
pip install -r requirements.txt

# (Optional) Set MongoDB URI
export MONGO_URI="mongodb://localhost:27017/phishshield"

# Start server (từ thư mục backend)
uvicorn app:app --host 0.0.0.0 --port 8000

# Hoặc từ project root
uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Server chạy tại: `http://localhost:8000`

## Endpoints

### POST /api/check-url
Request
```json
{ "url": "https://example.com" }
```
Response
```json
{ "risk": "safe|suspicious|malicious", "score": 0.73, "reasons": ["model_probability"], "model_version": "rf-pipeline" }
```

Checks order: whitelist → blacklist → model.

### POST /api/report-url
Request
```json
{ "url": "https://bad.example" }
```
Response with MongoDB
```json
{ "ok": true, "id": "..." }
```
Response without MongoDB (file fallback)
```json
{ "ok": true, "file": "reports.json" }
```

### POST /api/whitelist
Add a URL/host to whitelist.
```json
{ "url": "https://example.com" }
```
Response: `{ "ok": true }` or `{ "ok": false, "error": "..." }`

### POST /api/blacklist
Add a URL/host to blacklist.
```json
{ "url": "https://bad.example" }
```
Response: `{ "ok": true }` or `{ "ok": false, "error": "..." }`

## Notes
- Model features are generated from URL only to match Team 5's `feature_names.json`.
- CORS origins controlled by `ALLOW_ORIGINS`.
- If `MONGO_URI` is unset, reports are appended to `backend/reports.json`.

## Import Blacklist

### Import from TXT file (one URL per line)

```bash
cd /Users/nguyen/Downloads/PhishShield_Extension-main-3
export MONGO_URI="mongodb://localhost:27017/phishshield"
python3 backend/scripts/import_blacklist_txt.py --txt Machine-Learning-main/blacklist.txt
# or with custom source label
python3 backend/scripts/import_blacklist_txt.py --txt Machine-Learning-main/blacklist.txt --source "team5_blacklist"
# test with limit (first 100 lines)
python3 backend/scripts/import_blacklist_txt.py --txt Machine-Learning-main/blacklist.txt --limit 100
```

### Import PhishTank CSV

```bash
cd /Users/nguyen/Downloads/PhishShield_Extension-main-3
export MONGO_URI="mongodb://localhost:27017/phishshield"
python backend/scripts/import_phishtank.py --csv /path/to/phishtank.csv
# or
python backend/scripts/import_phishtank.py --url https://example.com/phishtank.csv
```

Both scripts upsert `url` and `host` into the `blacklist` collection.

