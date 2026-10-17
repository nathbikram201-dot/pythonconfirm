import os, json, secrets, hashlib, sqlite3
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, send_from_directory, abort

# FLIENT-PAPA: token-gated configuration server for Render.
# Set ADMIN_KEY and FIREBASE_SERVICE_ACCOUNT_JSON in Render Environment.
# The requested login key defaults to BIKRAM; change it before production.
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# The admin.html may be hosted on a different static host, so allow cross-origin
# requests. Authentication remains server-side via X-Admin-Key.
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Max-Age"] = "600"
    return response

@app.route("/api/<path:_path>", methods=["OPTIONS"])
def api_preflight(_path):
    return ("", 204)
ADMIN_KEY = os.environ.get("ADMIN_KEY", "BIKRAM")
PORT = int(os.environ.get("PORT", "8080"))
FIREBASE_SERVICE_ACCOUNT_JSON = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()

# Original configuration is embedded server-side; it is never served as a public file.
CONFIG = json.loads(r'''{"remarks":"FLIENT-VIP","inbounds":[{"tag":"socks","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false},{"tag":"http","listen":"127.0.0.1","port":10809,"protocol":"http","sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false}],"outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"address":"wraith-bom2.aimhack.shop","port":443,"version":2},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"wraith-bom2.aimhack.shop","alpn":["h3"]},"hysteriaSettings":{"version":2,"auth":"AMHK-05AF-AB2E-A78E"}},{"tag":"direct","protocol":"freedom"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","domain":["full:clientbp.ggpolarbear.com","full:loginbp.ggpolarbear.com","full:core-bs.ggpolarbear.com","full:core-bs.freefiremobile.com","full:core-tata.freefireind.in","full:core-gmc.freefiremobile.com","full:client.ind.freefiremobile.com","full:client.us.freefiremobile.com","full:sgnetwork.ggblueshark.com","full:menetwork.ggblueshark.com","full:bdnetwork.ggpolarbear.com","full:100067.connect.garena.com","full:100067.msdk.garena.com","full:clientbp.ppmainecoonghj.com","full:loginbp.ppmainecoonghj.com","full:ffmconnect.ppmainecoonghj.com","full:ffmmsdk.ppmainecoonghj.com","regexp:^(clientbp|loginbp|core-[a-z0-9]+|[a-z]+network|ffmconnect|ffmmsdk)\\."],"outboundTag":"proxy"},{"type":"field","ip":["0.0.0.0/24","101.32.114.0/23","101.33.44.0/22","102.204.191.0/24","102.217.238.0/24","103.103.244.0/24","103.108.100.0/22","103.117.4.0/22","103.123.54.0/23","103.127.228.0/22","103.16.32.0/22","103.215.127.0/24","103.219.200.0/22","103.237.102.0/23","103.247.204.0/22","103.248.57.0/24","103.248.58.0/23","103.52.145.0/24","103.60.16.0/22","103.62.54.0/24","103.69.179.0/24","104.166.132.0/23","104.166.144.0/22","104.166.148.0/22","104.166.175.0/24","104.166.185.0/24","104.166.191.0/24","107.151.141.0/24","107.151.192.0/24","107.151.193.0/24","107.151.240.0/24","107.151.241.0/24","107.151.242.0/24","124.108.136.0/22","124.108.140.0/23","124.108.149.0/24","124.108.150.0/23","124.108.152.0/21","124.108.160.0/21","124.108.172.0/22","124.108.191.0/24","124.156.200.0/22","124.156.204.0/22","124.158.133.0/24","124.158.134.0/23","124.158.142.0/23","128.1.113.0/24","128.1.189.0/24","128.1.200.0/24","128.1.63.0/24","128.14.102.0/23","128.14.136.0/23","128.14.206.0/24","128.14.38.0/24","128.14.63.0/24","128.14.89.0/24","129.226.144.0/24","129.226.200.0/22","129.226.220.0/22","134.168.233.0/24","134.168.234.0/24","139.180.158.0/24","143.92.112.0/23","143.92.116.0/23","143.92.118.0/24","143.92.120.0/21","148.153.101.0/24","148.153.11.0/24","148.153.112.0/23","148.153.116.0/23","148.153.143.0/24","148.153.168.0/22","148.153.206.0/23","148.153.222.0/24","148.153.246.0/24","148.153.248.0/23","148.153.67.0/24","148.153.84.0/23","148.153.92.0/23","148.222.64.0/20","148.222.80.0/22","148.222.84.0/23","148.222.88.0/21","149.28.55.0/24","15.235.220.0/24","15.235.231.0/24","15.235.233.0/24","150.109.24.0/22","150.129.42.0/24","152.233.63.0/24","154.203.154.0/23","154.206.73.0/24","154.223.134.0/23","154.93.32.0/24","154.93.46.0/24","154.93.86.0/24","154.95.68.0/24","154.95.81.0/24","156.227.242.0/24","156.59.144.0/23","156.59.154.0/24","156.59.194.0/23","156.59.242.0/23","156.59.251.0/24","156.59.64.0/22","156.59.70.0/23","162.128.241.0/24","162.128.242.0/24","162.128.249.0/24","162.128.32.0/24","162.128.54.0/24","162.128.61.0/24","162.128.80.0/24","162.128.82.0/24","163.227.196.0/24","163.53.247.0/24","169.197.96.0/22","185.23.183.0/24","192.169.117.0/24","192.169.124.0/23","193.118.34.0/23","194.26.72.0/24","198.44.169.0/24","199.182.238.0/24","202.181.64.0/23","202.181.67.0/24","202.181.68.0/24","202.181.70.0/23","202.181.72.0/21","202.181.80.0/21","202.73.16.0/21","202.81.100.0/23","202.81.104.0/21","202.81.112.0/20","202.81.96.0/22","204.3.212.0/24","207.148.69.0/24","210.17.80.0/24","23.236.112.0/23","23.251.37.0/24","23.251.41.0/24","23.251.51.0/24","23.251.61.0/24","23.90.133.0/24","23.90.134.0/24","23.90.141.0/24","34.126.122.0/24","34.126.175.0/24","34.126.239.0/24","34.126.81.0/24","34.87.109.0/24","34.87.170.0/24","34.87.24.0/24","35.185.188.0/24","35.187.246.0/24","35.198.211.0/24","35.198.221.0/24","38.54.120.0/24","38.54.21.0/24","38.54.44.0/23","38.54.70.0/24","38.54.78.0/23","43.128.121.0/24","43.129.35.0/24","43.129.43.0/24","43.133.146.0/24","43.133.150.0/24","43.133.153.0/24","43.133.154.0/24","43.133.40.0/24","43.133.41.0/24","43.134.101.0/24","43.134.103.0/24","43.134.118.0/24","43.134.168.0/24","43.134.170.0/24","43.134.182.0/24","43.134.232.0/24","43.134.233.0/24","43.134.241.0/24","43.134.28.0/24","43.134.45.0/24","43.134.64.0/24","43.134.90.0/24","43.134.94.0/24","43.152.104.0/24","43.152.105.0/24","43.153.208.0/24","43.153.209.0/24","43.153.215.0/24","43.156.134.0/24","43.156.14.0/24","43.156.141.0/24","43.156.151.0/24","43.156.167.0/24","43.156.177.0/24","43.156.199.0/24","43.156.200.0/24","43.156.203.0/24","43.156.205.0/24","43.156.209.0/24","43.156.26.0/24","43.156.31.0/24","43.156.40.0/24","43.156.7.0/24","43.157.195.0/24","43.157.197.0/24","43.157.200.0/24","43.157.204.0/24","43.157.206.0/24","43.157.208.0/24","43.157.209.0/24","43.157.210.0/24","43.157.211.0/24","43.157.224.0/24","43.157.227.0/24","43.157.228.0/24","43.157.230.0/24","43.157.242.0/24","43.157.250.0/24","43.157.251.0/24","43.163.105.0/24","43.163.108.0/24","43.163.119.0/24","43.163.126.0/24","43.163.88.0/24","43.163.96.0/24","43.173.0.0/23","43.173.170.0/24","43.173.171.0/24","43.173.2.0/23","43.173.29.0/24","43.252.184.0/22","43.252.210.0/24","45.119.216.0/22","45.119.240.0/22","45.121.212.0/24","45.251.28.0/22","59.153.158.0/24","60.199.50.0/24","66.253.15.0/24","82.200.131.0/24","98.96.251.0/24","98.98.12.0/22","98.98.140.0/23","98.98.162.0/24","98.98.189.0/24","98.98.220.0/23","98.98.29.0/24","98.98.32.0/24","98.98.33.0/24","98.98.34.0/24"],"outboundTag":"proxy"},{"type":"field","network":"tcp","port":"39000-39999","outboundTag":"proxy"},{"type":"field","network":"udp","port":"10000-10999","outboundTag":"proxy"},{"type":"field","domain":["full:event-vodka.freefireind.in","full:indevent.ggblueshark.com","full:sgevent.ggblueshark.com","full:meevent.ggblueshark.com","full:thevent.ggblueshark.com","full:sacevent.ggblueshark.com","full:idevent.ggblueshark.com","full:bdevent.ggpolarbear.com","regexp:event\\.gg(blueshark|polarbear)\\.com$","full:gin.freefireind.in","full:gin.freefiremobile.com","full:vodka.freefireind.in","full:dl.castle.freefiremobile.com","full:dl.cdn.freefiremobile.com","full:dl-core.cdn.freefiremobile.com","full:dl.gmc.freefiremobile.com","full:dl.aw.freefiremobile.com","full:dl.dir.freefiremobile.com","full:dl.bs.freefiremobile.com","full:dl.ak.freefiremobile.com","full:dl-sg-production.freefiremobile.com","full:dl-tata.freefireind.in","full:dl-bs.ggpolarbear.com","domain:freefiremobile-a.akamaihd.net","full:client.nulldash.store","full:client.aimhack.shop","full:client.xreg.store","full:client.trollmodz.store","full:client.silentx.store","full:client.zentnityx.store","full:client.ruizenteam.store"],"outboundTag":"direct"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]}''')

_db = None
_firestore = None

def init_store():
    global _db, _firestore
    if FIREBASE_SERVICE_ACCOUNT_JSON:
        try:
            import firebase_admin
            from firebase_admin import credentials, firestore
            if not firebase_admin._apps:
                cred_data = json.loads(FIREBASE_SERVICE_ACCOUNT_JSON)
                firebase_admin.initialize_app(credentials.Certificate(cred_data))
            _firestore = firestore.client()
            app.logger.info("Token storage: Firebase Firestore")
            return
        except Exception as e:
            app.logger.exception("Firebase initialization failed")
            raise RuntimeError("Firebase setup failed. Check FIREBASE_SERVICE_ACCOUNT_JSON in Render.") from e
    # Local-only fallback for testing; Render ephemeral disk can reset this database.
    _db = sqlite3.connect(os.environ.get("LOCAL_DB_PATH", "tokens.sqlite3"), check_same_thread=False)
    _db.execute("CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, label TEXT NOT NULL DEFAULT '')")
    _db.commit()
    app.logger.warning("Firebase not configured; using local SQLite fallback (not durable on Render).")

init_store()

def utcnow(): return datetime.now(timezone.utc)
def iso(dt): return dt.astimezone(timezone.utc).isoformat()
def require_admin():
    key = request.headers.get("X-Admin-Key", "")
    if not key or not secrets.compare_digest(key, ADMIN_KEY):
        abort(401)

def save_token(token, expires_at, label):
    created = utcnow()
    row = {"token": token, "expires_at": iso(expires_at), "created_at": iso(created), "label": label[:80]}
    if _firestore is not None:
        _firestore.collection("access_tokens").document(hashlib.sha256(token.encode()).hexdigest()).set(row)
    else:
        _db.execute("INSERT INTO tokens(token,expires_at,created_at,label) VALUES(?,?,?,?)", (token,row["expires_at"],row["created_at"],row["label"]))
        _db.commit()
    return row

def get_token(token):
    if _firestore is not None:
        doc = _firestore.collection("access_tokens").document(hashlib.sha256(token.encode()).hexdigest()).get()
        return doc.to_dict() if doc.exists else None
    row = _db.execute("SELECT token,expires_at,created_at,label FROM tokens WHERE token=?", (token,)).fetchone()
    return dict(zip(("token","expires_at","created_at","label"),row)) if row else None

def list_tokens():
    if _firestore is not None:
        rows = [d.to_dict() for d in _firestore.collection("access_tokens").stream()]
    else:
        rows = [dict(zip(("token","expires_at","created_at","label"),r)) for r in _db.execute("SELECT token,expires_at,created_at,label FROM tokens ORDER BY created_at DESC").fetchall()]
    # Expired tokens are shown as expired, but raw tokens are only shown in admin panel.
    return sorted(rows, key=lambda r:r.get("created_at", ""), reverse=True)

@app.get("/")
def home():
    return jsonify({"service":"FLIENT-PAPA","status":"online","admin":"/admin.html","note":"Configuration endpoints require a valid access token."})

@app.get("/health")
def health(): return jsonify({"ok":True})

@app.get("/admin.html")
def admin_page(): return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "admin.html")

@app.post("/api/admin/login")
def login():
    # The key is verified server-side; never put it in the page source.
    key = (request.get_json(silent=True) or {}).get("key", "")
    if not key or not secrets.compare_digest(str(key), ADMIN_KEY): return jsonify({"error":"Invalid admin key"}), 401
    return jsonify({"ok":True})

@app.post("/api/admin/tokens")
def create_token():
    require_admin()
    data = request.get_json(silent=True) or {}
    try: minutes = int(data.get("validity_minutes", 60))
    except (TypeError, ValueError): return jsonify({"error":"validity_minutes must be an integer"}), 400
    if minutes < 1 or minutes > 525600: return jsonify({"error":"Validity must be 1 minute to 365 days"}), 400
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(minutes=minutes)
    row = save_token(token, expires, str(data.get("label", "")))
    row["url"] = request.host_url.rstrip("/") + "/access/" + token
    return jsonify(row), 201

@app.get("/api/admin/tokens")
def admin_tokens():
    require_admin()
    now = utcnow()
    out=[]
    for row in list_tokens():
        item = dict(row)
        item["active"] = datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00")) > now
        item["url"] = request.host_url.rstrip("/") + "/access/" + item["token"]
        out.append(item)
    return jsonify({"tokens":out})

@app.delete("/api/admin/tokens/<token>")
def revoke_token(token):
    require_admin()
    if _firestore is not None:
        _firestore.collection("access_tokens").document(hashlib.sha256(token.encode()).hexdigest()).delete()
    else:
        _db.execute("DELETE FROM tokens WHERE token=?", (token,)); _db.commit()
    return jsonify({"ok":True})

@app.get("/access/<token>")
def access_config(token):
    # Only a valid, unexpired token can retrieve the client configuration.
    row = get_token(token)
    if not row: return jsonify({"error":"Invalid access token"}), 403
    try: expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    except Exception: return jsonify({"error":"Invalid token record"}), 403
    if expiry <= utcnow(): return jsonify({"error":"Access token expired"}), 403
    response = jsonify(CONFIG)
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.errorhandler(401)
def unauthorized(_): return jsonify({"error":"Unauthorized"}), 401
@app.errorhandler(404)
def not_found(_): return jsonify({"error":"Not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
