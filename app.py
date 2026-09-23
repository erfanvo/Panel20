"""پنل مدیریت Bridge

این فایل فقط لایهٔ مدیریت و رابط وب است. قراردادهای Redis عمداً با Bridge/bx.py
هماهنگ نگه داشته شده‌اند تا موتور ثبت‌نام بدون تغییر کار کند.
"""
import csv
import io
import json
import os
import secrets
import threading
import time
from datetime import datetime
from functools import wraps

import redis
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"))
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(24))

REDIS_URL = os.environ.get(
    "REDIS_URL",
    "redis://default:fuHrGqESMbVVRciLtcxCzsKaeUdGnrOU@interchange.proxy.rlwy.net:58097",
)
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "https://your-domain.com").rstrip("/")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
APP_SECRET_HEADER = "JetApp-Secure-Client"

try:
    db = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    db.ping()
except Exception:
    db = None


# ================= Token Worker =================
# این worker همان رفتار قبلی را حفظ می‌کند: حساب جدید را از صف می‌خواند،
# session را می‌سازد و رکورد مدیریتی را در hash قرار می‌دهد.
def token_worker():
    while True:
        if db:
            try:
                raw_data = db.lpop("bot:new_accounts")
                if raw_data:
                    acc = json.loads(raw_data)
                    token = secrets.token_urlsafe(14)
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    db.setex(
                        f"jet_session:{token}",
                        30 * 24 * 3600,
                        json.dumps(acc.get("data", {}), ensure_ascii=False),
                    )

                    record = {
                        "phone": acc.get("phone", ""),
                        "name": acc.get("name", ""),
                        "token": token,
                        "created_at": now_str,
                        "total_orders": 0,
                    }
                    db.hset(
                        "jet:bulk_accounts",
                        acc.get("phone", ""),
                        json.dumps(record, ensure_ascii=False),
                    )
            except Exception:
                pass
        time.sleep(1)


threading.Thread(target=token_worker, daemon=True).start()


# ================= Login =================
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ورود به پنل</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root { color-scheme: light; font-family: Vazirmatn, Tahoma, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
      background: #f4f7fb; color: #142033; }
    .login { width: min(100%, 420px); background: #fff; border: 1px solid #e3e9f2;
      border-radius: 22px; padding: 34px; box-shadow: 0 22px 60px rgba(20,32,51,.09); }
    .mark { width: 48px; height: 48px; display: grid; place-items: center; border-radius: 14px;
      background: #1d4ed8; color: white; font-weight: 800; font-size: 20px; margin-bottom: 22px; }
    h1 { font-size: 22px; margin: 0 0 8px; } p { color: #66748a; font-size: 13px; margin: 0 0 26px; }
    label { display: block; font-size: 13px; font-weight: 700; margin-bottom: 8px; }
    input { direction: ltr; width: 100%; border: 1px solid #d6dfeb; border-radius: 11px;
      padding: 13px 14px; font: inherit; outline: none; }
    input:focus { border-color: #2563eb; box-shadow: 0 0 0 4px #dbeafe; }
    button { width: 100%; border: 0; border-radius: 11px; padding: 13px; margin-top: 16px;
      background: #1d4ed8; color: white; font: inherit; font-weight: 700; cursor: pointer; }
    button:hover { background: #1e40af; }
    .error { color: #b42318; background: #fff1f0; border: 1px solid #ffd5d2; border-radius: 10px;
      padding: 10px 12px; font-size: 12px; margin-bottom: 18px; }
  </style>
</head>
<body>
  <main class="login">
    <div class="mark">B</div>
    <h1>ورود به پنل مدیریت</h1>
    <p>مدیریت حساب‌ها، لینک‌ها و وضعیت سرویس</p>
    {{ERROR}}
    <form method="POST" action="/login">
      <label for="password">رمز عبور</label>
      <input id="password" type="password" name="password" autocomplete="current-password" required autofocus>
      <button type="submit">ورود به پنل</button>
    </form>
  </main>
</body>
</html>
"""


def login_page(error=""):
    message = f'<div class="error">{error}</div>' if error else ""
    return render_template_string(LOGIN_HTML.replace("{{ERROR}}", message))


def protected(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapped


def db_or_empty():
    return db


def parse_account(raw, fallback_phone=""):
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            return None
        return value
    except (TypeError, ValueError):
        return {"phone": fallback_phone, "name": "", "created_at": "", "total_orders": 0}


def account_rows(acc_type, query=""):
    if not db_or_empty():
        return []

    hash_key = "jet:ordered_accounts" if acc_type == "ordered" else "jet:bulk_accounts"
    records = db.hgetall(hash_key)

    def created_at(item):
        account = parse_account(item[1], item[0]) or {}
        return account.get("created_at", "")

    sorted_records = sorted(records.items(), key=created_at, reverse=True)
    query = (query or "").strip().lower()
    rows = []

    # One pipeline avoids one Redis round-trip per account when checking links.
    pipe = db.pipeline(transaction=False)
    usable = []
    for phone, raw in sorted_records:
        account = parse_account(raw, phone)
        if not account:
            continue
        haystack = f"{phone} {account.get('name', '')}".lower()
        if query and query not in haystack:
            continue
        usable.append((phone, account))
        token = account.get("token", "")
        pipe.exists(f"jet_session:{token}")
        pipe.ttl(f"jet_session:{token}")

    link_info = pipe.execute() if usable else []
    for index, ((phone, account), values) in enumerate(zip(usable, zip(link_info[::2], link_info[1::2])), 1):
        exists, ttl = values
        rows.append(
            {
                "index": index,
                "phone": account.get("phone") or phone,
                "name": account.get("name", ""),
                "created_at": account.get("created_at", ""),
                "total_orders": account.get("total_orders", 0),
                "link": f"{WEBHOOK_URL}/auth/{account.get('token', '')}",
                "link_active": bool(exists),
                "link_ttl": ttl if exists else 0,
            }
        )
    return rows


def db_type_and_size(key):
    try:
        kind = db.type(key)
        if kind == "hash":
            return kind, db.hlen(key)
        if kind == "list":
            return kind, db.llen(key)
        if kind == "set":
            return kind, db.scard(key)
        if kind == "zset":
            return kind, db.zcard(key)
        if kind == "string":
            return kind, 1
        return kind, 0
    except Exception:
        return "unknown", 0


def database_snapshot():
    keys = [
        ("jet:bulk_accounts", "حساب‌های پایه"),
        ("jet:ordered_accounts", "حساب‌های دارای سفارش"),
        ("jet:processed_phones", "شماره‌های پردازش‌شده"),
        ("bot:new_accounts", "صف حساب‌های جدید"),
        ("bot:admin_commands", "صف فرمان‌ها"),
        ("bot:admin_alerts", "گزارش‌های موتور"),
        ("nexus:checker_logs", "گزارش‌های بررسی"),
    ]
    items = []
    for key, label in keys:
        kind, size = db_type_and_size(key)
        items.append({"key": key, "label": label, "type": kind, "size": size})

    session_count = sum(1 for _ in db.scan_iter(match="jet_session:*", count=500))
    return {
        "items": items,
        "sessions": session_count,
        "connected": True,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/")
def index():
    if not session.get("logged_in"):
        return login_page()
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    if request.form.get("password") == ADMIN_PASS:
        session["logged_in"] = True
        session.permanent = True
        return redirect(url_for("index"))
    return login_page("رمز عبور واردشده درست نیست."), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ================= Dashboard API =================
@app.route("/api/stats")
@protected
def get_stats():
    if not db:
        return jsonify(
            {
                "total_accounts": 0,
                "ordered_accounts": 0,
                "active_proxies": 0,
                "system_status": "Offline",
                "checker_running": False,
                "new_accounts_queue": 0,
                "command_queue": 0,
                "database_connected": False,
            }
        )

    total_normal = db.hlen("jet:bulk_accounts")
    total_ordered = db.hlen("jet:ordered_accounts")
    active_proxies = db.get("nexus:active_proxies")
    is_checking = db.get("nexus:checker_running") == "1"
    last_cmd = db.lindex("bot:admin_commands", -1)

    engine_alive = False
    try:
        engine_alive = any(client.get("cmd") == "blpop" for client in db.client_list())
    except Exception:
        pass

    if not engine_alive and not is_checking:
        status = "Offline"
    elif is_checking:
        status = "Checking"
    elif last_cmd and "START_BULK" in last_cmd:
        status = "Registering"
    else:
        status = "Standby"

    return jsonify(
        {
            "total_accounts": total_normal,
            "ordered_accounts": total_ordered,
            "active_proxies": int(active_proxies) if active_proxies else 0,
            "system_status": status,
            "checker_running": is_checking,
            "new_accounts_queue": db.llen("bot:new_accounts"),
            "command_queue": db.llen("bot:admin_commands"),
            "database_connected": True,
        }
    )


@app.route("/api/logs")
@protected
def get_logs():
    if not db:
        return jsonify({"logs": []})
    raw_logs = db.lrange("bot:admin_alerts", -60, -1)
    logs = [
        {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "message": str(log).replace("\n", " - "),
        }
        for log in raw_logs
    ]
    return jsonify({"logs": logs})


@app.route("/api/accounts/<acc_type>")
@protected
def get_accounts(acc_type):
    if acc_type not in {"normal", "ordered"}:
        return jsonify({"data": []}), 404
    return jsonify({"data": account_rows(acc_type, request.args.get("q", ""))})


@app.route("/api/database/overview")
@protected
def database_overview():
    if not db:
        return jsonify({"connected": False, "items": [], "sessions": 0})
    return jsonify(database_snapshot())


@app.route("/api/export/<acc_type>/<file_format>")
@protected
def export_accounts(acc_type, file_format):
    if acc_type not in {"normal", "ordered"} or file_format not in {"csv", "json"}:
        return jsonify({"error": "فرمت خروجی نامعتبر است."}), 400

    rows = account_rows(acc_type, request.args.get("q", ""))
    if file_format == "json":
        payload = json.dumps(rows, ensure_ascii=False, indent=2)
        return Response(
            payload,
            mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=accounts-{acc_type}.json"},
        )

    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=["index", "phone", "name", "created_at", "total_orders", "link", "link_active"],
    )
    writer.writeheader()
    writer.writerows(
        {key: row.get(key, "") for key in writer.fieldnames}
        for row in rows
    )
    return Response(
        "\ufeff" + stream.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=accounts-{acc_type}.csv"},
    )


# ================= Engine actions =================
@app.route("/api/checker/start", methods=["POST"])
@protected
def start_checker():
    if not db:
        return jsonify({"error": "اتصال دیتابیس برقرار نیست."}), 503
    req = request.json or {}
    start_idx = max(1, int(req.get("start_idx", 1)))
    end_idx = max(start_idx, int(req.get("end_idx", 200)))
    db.delete("bot:admin_commands")
    db.rpush("bot:admin_commands", f"START_CHECKER:{start_idx}:{end_idx}")
    return jsonify({"status": "ok", "message": f"بررسی ردیف‌های {start_idx} تا {end_idx} در صف قرار گرفت."})


@app.route("/api/checker/stop", methods=["POST"])
@protected
def stop_checker():
    if not db:
        return jsonify({"error": "اتصال دیتابیس برقرار نیست."}), 503
    db.set("nexus:checker_stop", "1")
    return jsonify({"status": "ok", "message": "درخواست توقف برای موتور ارسال شد."})


@app.route("/api/action/clear_logs", methods=["POST"])
@protected
def clear_logs():
    if not db:
        return jsonify({"error": "اتصال دیتابیس برقرار نیست."}), 503
    db.delete("bot:admin_alerts", "nexus:checker_logs")
    return jsonify({"status": "ok", "message": "گزارش‌های سیستم پاک شد."})


@app.route("/api/action/<cmd>", methods=["POST"])
@protected
def handle_action(cmd):
    if not db:
        return jsonify({"error": "اتصال دیتابیس برقرار نیست."}), 503
    if cmd == "start":
        db.delete("bot:admin_commands")
        db.rpush("bot:admin_commands", "START_BULK")
        return jsonify({"status": "ok", "message": "فرمان ثبت‌نام در صف قرار گرفت."})
    if cmd == "clean":
        req = request.json or {}
        if req.get("code") != "NEXUS-WIPE-ALL":
            return jsonify({"status": "error", "message": "کد تأیید اشتباه است."})
        db.delete(
            "jet:processed_phones",
            "jet:bulk_accounts",
            "jet:ordered_accounts",
            "bot:admin_alerts",
            "bot:new_accounts",
            "nexus:checker_logs",
        )
        for key in db.scan_iter(match="jet_session:*", count=500):
            db.delete(key)
        return jsonify({"status": "ok", "message": "داده‌های مدیریتی و نشست‌ها پاک شدند."})
    return jsonify({"status": "error", "message": "فرمان ناشناخته است."}), 404


@app.route("/api/action/delete_account", methods=["POST"])
@protected
def delete_account():
    if not db:
        return jsonify({"status": "error", "message": "اتصال دیتابیس برقرار نیست."}), 503
    payload = request.json or {}
    phone = str(payload.get("phone", "")).strip()
    if not phone:
        return jsonify({"status": "error", "message": "شماره حساب مشخص نیست."}), 400

    deleted = False
    for hash_key in ["jet:bulk_accounts", "jet:ordered_accounts"]:
        rec = db.hget(hash_key, phone)
        if rec:
            acc = parse_account(rec, phone) or {}
            if acc.get("token"):
                db.delete(f"jet_session:{acc['token']}")
            db.hdel(hash_key, phone)
            db.srem("jet:processed_phones", phone)
            deleted = True
    return jsonify(
        {
            "status": "ok" if deleted else "not_found",
            "message": "حساب حذف شد." if deleted else "حسابی با این شماره پیدا نشد.",
        }
    )


@app.route("/api/action/revoke_link", methods=["POST"])
@protected
def revoke_link():
    if not db:
        return jsonify({"status": "error", "message": "اتصال دیتابیس برقرار نیست."}), 503
    phone = str((request.json or {}).get("phone", "")).strip()
    for hash_key in ["jet:bulk_accounts", "jet:ordered_accounts"]:
        raw = db.hget(hash_key, phone)
        if raw:
            account = parse_account(raw, phone) or {}
            token = account.get("token")
            if token:
                db.delete(f"jet_session:{token}")
                return jsonify({"status": "ok", "message": "لینک ورود این حساب باطل شد."})
    return jsonify({"status": "not_found", "message": "حسابی با این شماره پیدا نشد."}), 404


# ================= Client gateway =================
@app.route("/auth/<token>")
def secure_gateway(token):
    if not db:
        return "Server Error", 500
    session_str = db.get(f"jet_session:{token}")
    if not session_str:
        return (
            '<html dir="rtl"><body style="background:#f8fafc;color:#e11d48;font-family:Tahoma;text-align:center;padding:50px;">'
            "<h2>نشست کاربری نامعتبر یا منقضی شده است.</h2></body></html>",
            404,
        )
    user_agent = request.headers.get("User-Agent", "")
    app_header = request.headers.get("X-Client-App", "")
    if app_header == APP_SECRET_HEADER or "JetAppClient" in user_agent:
        return jsonify({"status": "success", "session": json.loads(session_str)})
    return (
        '<html dir="rtl"><body style="background:#f8fafc;color:#e11d48;font-family:Tahoma;text-align:center;padding:50px;">'
        "<h2>دسترسی از این درگاه غیرمجاز است.</h2></body></html>"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
