"""
Nexus Command Center - Core Panel
"""
import os, json, secrets, threading, time
from datetime import datetime
from flask import Flask, render_template_string, render_template, jsonify, request, session, redirect, url_for
import redis

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(24))

REDIS_URL = os.environ.get("REDIS_URL", "redis://default:fuHrGqESMbVVRciLtcxCzsKaeUdGnrOU@interchange.proxy.rlwy.net:58097")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "https://your-domain.com").rstrip('/')
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
APP_SECRET_HEADER = "JetApp-Secure-Client"

try:
    db = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    db.ping()
except Exception:
    db = None

# ================= Token Worker =================
def token_worker():
    while True:
        if db:
            try:
                raw_data = db.lpop("bot:new_accounts")
                if raw_data:
                    acc = json.loads(raw_data)
                    token = secrets.token_urlsafe(14)
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    db.setex(f"jet_session:{token}", 30 * 24 * 3600, json.dumps(acc.get("data", {}), ensure_ascii=False))
                    
                    record = {
                        "phone": acc.get("phone", ""),
                        "name": acc.get("name", ""),
                        "token": token,
                        "created_at": now_str,
                        "total_orders": 0
                    }
                    db.hset("jet:bulk_accounts", acc.get("phone", ""), json.dumps(record, ensure_ascii=False))
            except Exception:
                pass
        time.sleep(1)

threading.Thread(target=token_worker, daemon=True).start()

# ================= Modern Login UI =================
LOGIN_HTML = """
<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>ورود | پنل مدیریت نکسوس</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.0.0/Vazirmatn-font-face.css" rel="stylesheet" />
<style>body { font-family: 'Vazirmatn', sans-serif; }</style></head>
<body class="min-h-screen bg-slate-900 flex items-center justify-center p-4">
<div class="bg-slate-800 p-8 rounded-2xl border border-slate-700 shadow-2xl w-full max-w-sm">
<div class="flex items-center justify-center mb-6 text-blue-500">
<svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"></path></svg>
</div>
<h2 class="text-xl font-bold text-white text-center mb-6">سیستم جامع نکسوس</h2>
<form method="POST" action="/login" class="flex flex-col gap-4">
<input type="password" name="password" placeholder="رمز عبور ادمین..." required class="bg-slate-900 border border-slate-600 text-white rounded-xl p-3 text-center outline-none focus:border-blue-500 transition-colors">
<button type="submit" class="bg-blue-600 text-white font-bold py-3 rounded-xl hover:bg-blue-700 transition-colors">احراز هویت</button>
</form></div></body></html>
"""

@app.route('/')
def index():
    if not session.get('logged_in'): return render_template_string(LOGIN_HTML)
    # Load index.html from templates folder
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    if request.form.get('password') == ADMIN_PASS:
        session['logged_in'] = True
        return redirect(url_for('index'))
    return "رمز عبور نادرست است.", 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/stats')
def get_stats():
    if not session.get('logged_in') or not db:
        return jsonify({"total_accounts":0, "ordered_accounts":0, "active_proxies": None, "system_status":"Offline", "checker_running": False})
    
    total_normal = db.hlen("jet:bulk_accounts")
    total_ordered = db.hlen("jet:ordered_accounts")
    active_proxies = db.get("nexus:active_proxies")
    is_checking = db.get("nexus:checker_running") == "1"
    last_cmd = db.lindex("bot:admin_commands", -1)
    
    # هوش تشخیص اجرای موتور لوکال از طریق بررسی کانکشن‌های ردیس
    engine_alive = False
    try:
        clients = db.client_list()
        for c in clients:
            if c.get('cmd') == 'blpop': 
                engine_alive = True
                break
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
    
    return jsonify({
        "total_accounts": total_normal,
        "ordered_accounts": total_ordered,
        "active_proxies": int(active_proxies) if active_proxies and status != "Offline" else 0,
        "system_status": status,
        "checker_running": is_checking
    })

@app.route('/api/logs')
def get_logs():
    if not session.get('logged_in') or not db: return jsonify({"logs": []})
    raw_logs = db.lrange("bot:admin_alerts", -40, -1)
    logs_fmt = [{"timestamp": datetime.now().strftime("%H:%M:%S"), "message": l.replace('\n', ' - ')} for l in raw_logs]
    return jsonify({"logs": logs_fmt})

@app.route('/api/accounts/<acc_type>')
def get_accounts(acc_type):
    if not session.get('logged_in') or not db: return jsonify({"data": []})
    hash_key = "jet:ordered_accounts" if acc_type == 'ordered' else "jet:bulk_accounts"
    records = db.hgetall(hash_key)
    
    def get_created(item):
        try: return json.loads(item[1]).get("created_at", "")
        except: return ""
    sorted_recs = sorted(records.items(), key=get_created, reverse=True)
    
    data = []
    for idx, (phone, val) in enumerate(sorted_recs, start=1):
        acc = json.loads(val)
        data.append({
            "index": idx,
            "phone": acc.get("phone", phone),
            "name": acc.get("name", ""),
            "created_at": acc.get("created_at", ""),
            "total_orders": acc.get("total_orders", 0),
            "link": f"{WEBHOOK_URL}/auth/{acc.get('token', '')}"
        })
    return jsonify({"data": data})

@app.route('/api/checker/start', methods=['POST'])
def start_checker():
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    req = request.json or {}
    start_idx = req.get("start_idx", 1)
    end_idx = req.get("end_idx", 200)
    db.delete("bot:admin_commands")
    db.rpush("bot:admin_commands", f"START_CHECKER:{start_idx}:{end_idx}")
    return jsonify({"status": "ok", "message": f"فرمان بررسی برای بازه {start_idx} تا {end_idx} با موفقیت در صف قرار گرفت."})

@app.route('/api/checker/stop', methods=['POST'])
def stop_checker():
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    db.set("nexus:checker_stop", "1")
    return jsonify({"status": "ok", "message": "سیگنال توقف برای موتور ارسال شد."})

@app.route('/api/action/clear_logs', methods=['POST'])
def clear_logs():
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    db.delete("bot:admin_alerts", "nexus:checker_logs")
    return jsonify({"status": "ok", "message": "لاگ‌های سیستم پاکسازی شد."})

@app.route('/api/action/<cmd>', methods=['POST'])
def handle_action(cmd):
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    if cmd == 'start':
        db.delete("bot:admin_commands")
        db.rpush("bot:admin_commands", "START_BULK")
        return jsonify({"status": "ok", "message": "موتور استخراج در حالت آماده‌باش قرار گرفت."})
    elif cmd == 'clean':
        req = request.json or {}
        if req.get('code') != 'NEXUS-WIPE-ALL': return jsonify({"status": "error", "message": "کد امنیتی نامعتبر است."})
        db.delete("jet:processed_phones", "jet:bulk_accounts", "jet:ordered_accounts", "bot:admin_alerts", "bot:new_accounts", "nexus:checker_logs")
        for key in db.keys("jet_session:*"): db.delete(key)
        return jsonify({"status": "ok", "message": "عملیات فلش دیتابیس با موفقیت انجام شد."})
    return jsonify({"status": "error"})

@app.route('/api/action/delete_account', methods=['POST'])
def delete_account():
    if not session.get('logged_in') or not db: return jsonify({"status": "error"})
    phone = request.json.get('phone')
    for hash_key in ["jet:bulk_accounts", "jet:ordered_accounts"]:
        rec = db.hget(hash_key, phone)
        if rec:
            acc = json.loads(rec)
            db.delete(f"jet_session:{acc.get('token')}")
            db.hdel(hash_key, phone)
            db.srem("jet:processed_phones", phone)
    return jsonify({"status": "ok"})

@app.route('/auth/<token>')
def secure_gateway(token):
    if not db: return "Server Error", 500
    session_str = db.get(f"jet_session:{token}")
    if not session_str: return '<html dir="rtl"><body style="background:#f8fafc;color:#e11d48;font-family:Tahoma;text-align:center;padding:50px;"><h2>نشست کاربری نامعتبر یا منقضی شده است.</h2></body></html>', 404
    u_agent, app_hdr = request.headers.get("User-Agent", ""), request.headers.get("X-Client-App", "")
    if app_hdr == APP_SECRET_HEADER or "JetAppClient" in u_agent:
        return jsonify({"status": "success", "session": json.loads(session_str)})
    return '<html dir="rtl"><body style="background:#f8fafc;color:#e11d48;font-family:Tahoma;text-align:center;padding:50px;"><h2>دسترسی از این درگاه غیرمجاز است.</h2></body></html>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
