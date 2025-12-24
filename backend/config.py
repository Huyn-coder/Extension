import os


ALLOW_ORIGINS = os.getenv("ALLOW_ORIGINS", "*").split(",")
# Default to local MongoDB if no env var set
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/phishshield")
PORT = int(os.getenv("PORT", "8000"))

