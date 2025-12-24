from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
import joblib
import json
import os
import re
from urllib.parse import urlparse
import pandas as pd
from pymongo import MongoClient
from pymongo.errors import PyMongoError

# Import config in both module and script contexts
try:
    from . import config as cfg  # type: ignore
except Exception:
    try:
        from backend import config as cfg  # type: ignore
    except Exception:
        import config as cfg  # type: ignore


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.ALLOW_ORIGINS if hasattr(cfg, "ALLOW_ORIGINS") else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Load Team 5 model artifacts
ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Machine-Learning-main"))
MODEL_PATH = os.path.join(ML_DIR, "phishing_detector_model.pkl")
FEATURES_PATH = os.path.join(ML_DIR, "feature_names.json")

pipeline = joblib.load(MODEL_PATH)
with open(FEATURES_PATH, "r") as f:
    FEATURE_NAMES: List[str] = json.load(f).get("feature_names", [])


class URLInput(BaseModel):
    url: str


def _count(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text))


def _is_ip(host: str) -> int:
    return 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host or "") else 0


def build_ml_features(url: str, feature_names: List[str]) -> Dict[str, float]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    suffix = (host.split(".")[-1] if "." in host else "")
    subdomains = host.split(".")[:-2] if host.count(".") >= 2 else []

    text = url or ""

    feature_values: Dict[str, float] = {
        "feat_url_length": float(len(text)),
        "feat_hostname_length": float(len(host)),
        "feat_path_length": float(len(path)),
        "feat_count_hyphen": float(text.count("-")),
        "feat_count_at": float(text.count("@")),
        "feat_count_dot": float(text.count(".")),
        "feat_count_slash": float(text.count("/")),
        "feat_count_percent": float(text.count("%")),
        "feat_count_digits": float(_count(r"\d", text)),
        "feat_count_letters": float(_count(r"[A-Za-z]", text)),
        "feat_has_login": 1.0 if re.search(r"login", text, re.I) else 0.0,
        "feat_has_secure": 1.0 if re.search(r"secure", text, re.I) else 0.0,
        "feat_has_bank": 1.0 if re.search(r"bank", text, re.I) else 0.0,
        "feat_has_account": 1.0 if re.search(r"account", text, re.I) else 0.0,
        "feat_has_verify": 1.0 if re.search(r"verify", text, re.I) else 0.0,
        "feat_has_password": 1.0 if re.search(r"password|passwd|pwd", text, re.I) else 0.0,
        "feat_has_signin": 1.0 if re.search(r"sign\s*in|signin", text, re.I) else 0.0,
        "feat_total_keywords": 0.0,  # computed below
        "feat_subdomain_count": float(len([s for s in subdomains if s])),
        "feat_domain_length": float(len(host.split(".")[0])) if host else 0.0,
        "feat_suffix_length": float(len(suffix)),
        "feat_use_https": 1.0 if parsed.scheme == "https" else 0.0,
        "feat_use_ip": float(_is_ip(host)),
    }

    keyword_flags = [
        feature_values["feat_has_login"],
        feature_values["feat_has_secure"],
        feature_values["feat_has_bank"],
        feature_values["feat_has_account"],
        feature_values["feat_has_verify"],
        feature_values["feat_has_password"],
        feature_values["feat_has_signin"],
    ]
    feature_values["feat_total_keywords"] = float(sum(1 for v in keyword_flags if v == 1.0))

    # Only return the requested features in the exact order the model expects
    return {name: feature_values.get(name, 0.0) for name in feature_names}


@app.post("/api/check-url")
def check_url(input_data: URLInput):
    try:
        # Check whitelist/blacklist before model
        parsed_for_lists = urlparse(input_data.url)
        host = (parsed_for_lists.hostname or "").lower()
        # Normalize URL for comparison (remove scheme, trailing slash, lowercase)
        url_normalized = input_data.url.lower().rstrip("/")
        if url_normalized.startswith("http://"):
            url_normalized = url_normalized[7:]
        elif url_normalized.startswith("https://"):
            url_normalized = url_normalized[8:]
        url_normalized = url_normalized.rstrip("/")
        
        wl = _get_whitelist_collection()
        if wl is not None:
            # Check by host or normalized URL
            wl_doc = wl.find_one({"$or": [
                {"host": host},
                {"url": {"$regex": f"^{re.escape(host)}", "$options": "i"}}
            ]})
            if wl_doc:
                return {"risk": "safe", "score": 0.0, "reasons": ["whitelist"], "model_version": "rf-pipeline"}
        
        bl = _get_blacklist_collection()
        if bl is not None:
            # Check by host (most reliable) - exact match
            bl_doc = bl.find_one({"host": host})
            if bl_doc:
                return {"risk": "malicious", "score": 1.0, "reasons": ["blacklist"], "model_version": "rf-pipeline"}
            # Also check if URL contains the host
            bl_doc2 = bl.find_one({"url": {"$regex": re.escape(host), "$options": "i"}})
            if bl_doc2:
                return {"risk": "malicious", "score": 1.0, "reasons": ["blacklist"], "model_version": "rf-pipeline"}

        features = build_ml_features(input_data.url, FEATURE_NAMES)
        df = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

        # Predict probability for class 1 (phishing). If predict_proba missing, fallback to label
        try:
            proba = float(pipeline.predict_proba(df)[0][1])
        except Exception:
            label = int(pipeline.predict(df)[0])
            proba = 1.0 if label == 1 else 0.0

        # Apply smart whitelist adjustments to reduce false positives
        try:
            from smart_whitelist import adjust_score_for_context, check_trusted_pattern
            
            # Check if URL matches trusted pattern
            is_trusted, trust_reason = check_trusted_pattern(input_data.url)
            if is_trusted:
                return {
                    "risk": "safe",
                    "score": 0.0,
                    "reasons": [trust_reason],
                    "model_version": "rf-pipeline",
                }
            
            # Adjust score based on context
            adjusted_score, adjustments = adjust_score_for_context(input_data.url, proba)
            proba = adjusted_score
            
        except ImportError:
            # If smart_whitelist not available, use original score
            adjustments = []

        # Check for HTTP (no SSL) - security warning
        is_http_no_ssl = input_data.url.lower().startswith("http://")
        if is_http_no_ssl:
            # Increase risk score for HTTP sites (no encryption)
            proba = min(1.0, proba + 0.25)  # Add 25% to risk score
            if "adjustments" not in dir():
                adjustments = []
            adjustments.append("http_no_ssl_warning")

        # Map to risk levels
        if proba >= 0.8:
            risk = "malicious"
        elif proba >= 0.5:
            risk = "suspicious"
        elif is_http_no_ssl:
            # HTTP sites are at least suspicious even with low ML score
            risk = "suspicious"
            proba = max(proba, 0.5)
        else:
            risk = "safe"

        reasons = ["model_probability"]
        if adjustments:
            reasons.extend(adjustments)
        

        return {
            "risk": risk,
            "score": proba,
            "reasons": reasons,
            "model_version": "rf-pipeline",
        }
    except Exception as e:
        return {"error": str(e)}


_mongo_client = None
_reports_coll = None
_blacklist_coll = None
_whitelist_coll = None


def _ensure_db():
    global _mongo_client, _reports_coll, _blacklist_coll, _whitelist_coll
    if _reports_coll is not None:
        return
    mongo_uri = getattr(cfg, "MONGO_URI", "")
    if mongo_uri:
        _mongo_client = MongoClient(mongo_uri)
        db = _mongo_client.get_default_database() if "/" in mongo_uri.split("?")[0] else _mongo_client["phishshield"]
        _reports_coll = db["reports"]
        _blacklist_coll = db["blacklist"]
        _whitelist_coll = db["whitelist"]


def _get_reports_collection():
    _ensure_db()
    return _reports_coll


def _get_blacklist_collection():
    _ensure_db()
    return _blacklist_coll


def _get_whitelist_collection():
    _ensure_db()
    return _whitelist_coll


@app.post("/api/report-url")
def report_url(input_data: URLInput):
    payload = {"url": input_data.url}
    coll = _get_reports_collection()
    if coll is not None:
        try:
            p = urlparse(input_data.url)
            res = coll.insert_one({"url": input_data.url, "host": p.hostname or ""})
            return {"ok": True, "id": str(res.inserted_id)}
        except PyMongoError as e:
            return {"ok": False, "error": str(e)}
    # Fallback to file if no Mongo configured
    try:
        reports_path = os.path.join(os.path.dirname(__file__), "reports.json")
        data = []
        if os.path.exists(reports_path):
            with open(reports_path, "r") as f:
                data = json.load(f)
        data.append(payload)
        with open(reports_path, "w") as f:
            json.dump(data, f, indent=2)
        return {"ok": True, "file": "reports.json"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


class ListInput(BaseModel):
    url: str


@app.post("/api/whitelist")
def add_whitelist(item: ListInput):
    coll = _get_whitelist_collection()
    if coll is None:
        return {"ok": False, "error": "No database configured"}
    p = urlparse(item.url)
    try:
        coll.update_one({"$or": [{"url": item.url}, {"host": p.hostname or ""}]}, {"$set": {"url": item.url, "host": p.hostname or ""}}, upsert=True)
        return {"ok": True}
    except PyMongoError as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/blacklist")
def add_blacklist(item: ListInput):
    coll = _get_blacklist_collection()
    if coll is None:
        return {"ok": False, "error": "No database configured"}
    p = urlparse(item.url)
    try:
        coll.update_one({"$or": [{"url": item.url}, {"host": p.hostname or ""}]}, {"$set": {"url": item.url, "host": p.hostname or ""}}, upsert=True)
        return {"ok": True}
    except PyMongoError as e:
        return {"ok": False, "error": str(e)}


@app.get("/")
def read_root():
    return {"message": "PhishShield API is running 🚀"}
