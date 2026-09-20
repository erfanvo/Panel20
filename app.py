"""
Nexus Extractor Engine - Advanced Cloud Panel with Detailed Diagnostic Logs
"""
import os, json, secrets, threading, time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template_string, render_template, jsonify, request, session, redirect, url_for, Response
import requests
import redis

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(24))

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "https://your-domain.com").rstrip('/')
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
APP_SECRET_HEADER = "JetApp-Secure-Client"

try:
    db = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    db.ping()
except Exception:
    db = None

def log_checker_event(msg):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now_str}] {msg}"
    if db:
        try:
            db.rpush("nexus:checker_logs", line)
            db.ltrim("nexus:checker_logs", -3000, -1)  # نگه‌داری ۳۰۰۰ لاگ آخر
        except Exception:
            pass

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

# ================= Custom Proxy Cloud Checker =================
def format_proxy(raw_p):
    raw_p = raw_p.strip()
    if not raw_p: return None
    if raw_p.startswith("http://") or raw_p.startswith("https://"):
        return raw_p
    parts = raw_p.split(":")
    if len(parts) == 4:
        ip, port, user, pwd = parts
        return f"http://{user}:{pwd}@{ip}:{port}"
    elif len(parts) == 2:
        return f"http://{raw_p}"
    return None

def check_account_with_proxy(phone, acc_data, proxy_url):
    try:
        nexus_token = acc_data.get("token")
        if not nexus_token:
            log_checker_event(f"❌ شماره {phone} | خطا: توکن نکسوس در دیتابیس یافت نشد.")
            return False, 0

        session_raw = db.get(f"jet_session:{nexus_token}")
        if not session_raw:
            log_checker_event(f"❌ شماره {phone} | خطا: سشن jet_session:{nexus_token} در ردیس یافت نشد (احتمالاً منقضی شده).")
            return False, 0
        
        session_data = json.loads(session_raw)
        cookies = session_data.get("cookies", [])
        dk_token = ""
        for c in cookies:
            if c.get("name") == "token":
                dk_token = c.get("value")
                break
        
        if not dk_token:
            log_checker_event(f"❌ شماره {phone} | خطا: کوکی توکن اصلی دیجی‌کالا در نشست وجود ندارد.")
            return False, 0

        headers = {
            "authority": "api.digikalajet.ir",
            "accept": "application/json, text/plain, */*",
            "app-id": "8b62e987-34bf-48bd-bc62-347f38309a36",
            "authorization": dk_token,
            "client": "mobile",
            "clientos": "Android"
        }
        proxies = {"http": proxy_url, "https": proxy_url}
        
        res = requests.get("https://api.digikalajet.ir/order-shipments/?ch=jj", headers=headers, proxies=proxies, timeout=12)
        
        if res.status_code == 200:
            orders = res.json().get("data", {}).get("pager", {}).get("total_items", 0)
            if orders > 0:
                acc_data["total_orders"] = orders
                db.hset("jet:ordered_accounts", phone, json.dumps(acc_data, ensure_ascii=False))
                db.hdel("jet:bulk_accounts", phone)
                log_checker_event(f"✅ شماره {phone} | وضعیت: خریددار ({orders} سفارش) | انتقال یافت.")
                return True, orders
            else:
                log_checker_event(f"⚪ شماره {phone} | وضعیت: بدون خرید (0 سفارش)")
                return False, 0
        else:
            log_checker_event(f"⚠️ شماره {phone} | خطای سرور دیجی‌کالا (کد {res.status_code}) | پاسخ: {res.text[:90]} | پروکسی: {proxy_url}")
            return False, 0

    except requests.exceptions.ProxyError:
        log_checker_event(f"🚫 شماره {phone} | خطای پروکسی (ProxyError): اتصال برقرار نشد یا نام کاربری/رمز پروکسی اشتباه است | پروکسی: {proxy_url}")
        return False, 0
    except requests.exceptions.Timeout:
        log_checker_event(f"⏱️ شماره {phone} | تایم‌اوت پروکسی (Timeout): پروکسی پاسخ نداد | پروکسی: {proxy_url}")
        return False, 0
    except Exception as e:
        log_checker_event(f"❌ شماره {phone} | خطای غیرمنتظره: {str(e)} | پروکسی: {proxy_url}")
        return False, 0

def run_cloud_checker_thread(proxy_list):
    valid_proxies = [p for p in [format_proxy(x) for x in proxy_list] if p]
    if not valid_proxies:
        msg = "❌ خطای چکر: هیچ پروکسی معتبری فرمت نشد. لطفاً فرمت ip:port:user:pass را رعایت کنید."
        db.rpush("bot:admin_alerts", msg)
        log_checker_event(msg)
        return

    accounts = db.hgetall("jet:bulk_accounts")
    if not accounts:
        msg = "⚠️ چکر: لیست خام خالی است و اکانتی برای بررسی وجود ندارد."
        db.rpush("bot:admin_alerts", msg)
        log_checker_event(msg)
        return

    start_msg = f"🔎 شروع چکر با پروکسی شخصی | پروکسی‌ها: {len(valid_proxies)} | اکانت‌ها: {len(accounts)}"
    db.rpush("bot:admin_alerts", start_msg)
    log_checker_event(start_msg)
    
    ordered_count = 0
    p_idx = 0
    p_len = len(valid_proxies)

    with ThreadPoolExecutor(max_workers=min(p_len * 2, 30)) as executor:
        futures = []
        for phone, acc_raw in accounts.items():
            acc_data = json.loads(acc_raw)
            chosen_proxy = valid_proxies[p_idx % p_len]
            p_idx += 1
            futures.append(executor.submit(check_account_with_proxy, phone, acc_data, chosen_proxy))

        for f in as_completed(futures):
            is_ordered, count = f.result()
            if is_ordered:
                ordered_count += 1

    finish_msg = f"🎯 پایان چکر | تعداد {ordered_count} اکانت دارای خرید شناسایی و جدا شدند."
    db.rpush("bot:admin_alerts", finish_msg)
    log_checker_event(finish_msg)

LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>ورود | Nexus</title><script src="https://cdn.tailwindcss.com"></script><style>body{background-color:#f8fafc;}</style></head><body class="min-h-screen flex items-center justify-center p-4"><div class="bg-white p-8 rounded-2xl border border-slate-200 shadow-xl w-full max-w-sm"><h2 class="text-2xl font-bold text-slate-800 text-center mb-6">NEXUS PANEL</h2><form method="POST" action="/login" class="flex flex-col gap-4"><input type="password" name="password" placeholder="رمز عبور..." required class="bg-slate-50 border border-slate-300 rounded-xl p-3 text-center outline-none focus:border-blue-500" dir="ltr"><button type="submit" class="bg-blue-600 text-white font-bold py-3 rounded-xl hover:bg-blue-700">ورود</button></form></div></body></html>"""

@app.route('/')
def index():
    if not session.get('logged_in'): return render_template_string(LOGIN_HTML)
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    if request.form.get('password') == ADMIN_PASS:
        session['logged_in'] = True
        return redirect(url_for('index'))
    return "پسورد اشتباه است.", 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/stats')
def get_stats():
    if not session.get('logged_in') or not db: return jsonify({"total_accounts":0, "ordered_accounts":0, "active_proxies": None, "system_status":"Offline"})
    total_normal = db.hlen("jet:bulk_accounts")
    total_ordered = db.hlen("jet:ordered_accounts")
    active_proxies = db.get("nexus:active_proxies")
    last_cmd = db.lindex("bot:admin_commands", -1)
    status = "Registering" if last_cmd == "START_BULK" else "Standby"
    
    return jsonify({
        "total_accounts": total_normal,
        "ordered_accounts": total_ordered,
        "active_proxies": int(active_proxies) if active_proxies else None,
        "system_status": status
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
    data = []
    for phone, val in records.items():
        acc = json.loads(val)
        data.append({
            "phone": acc.get("phone", phone),
            "name": acc.get("name", ""),
            "created_at": acc.get("created_at", ""),
            "total_orders": acc.get("total_orders", 0),
            "link": f"{WEBHOOK_URL}/auth/{acc.get('token', '')}"
        })
    return jsonify({"data": data})

@app.route('/api/custom_checker', methods=['POST'])
def start_custom_checker():
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    proxies_text = request.json.get("proxies", "")
    proxy_list = [p.strip() for p in proxies_text.strip().split("\n") if p.strip()]
    if not proxy_list:
        return jsonify({"status": "error", "message": "لیست پروکسی خالی است."})
    
    threading.Thread(target=run_cloud_checker_thread, args=(proxy_list,), daemon=True).start()
    return jsonify({"status": "ok", "message": f"چکر ابری با {len(proxy_list)} پروکسی شروع به کار کرد."})

# ایندپوینت جدید برای دانلود فایل متنی لاگ‌های چکر
@app.route('/api/download_checker_logs')
def download_checker_logs():
    if not session.get('logged_in') or not db:
        return "دسترسی غیرمجاز", 401
    
    raw_logs = db.lrange("nexus:checker_logs", 0, -1)
    if not raw_logs:
        content = "هنوز هیچ لاگی از چکر ثبت نشده است. ابتدا عملیات بررسی را اجرا کنید."
    else:
        content = "\n".join(raw_logs)
    
    filename = f"Nexus_Checker_Logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    return Response(
        content,
        mimetype="text/plain;charset=utf-8",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route('/api/action/<cmd>', methods=['POST'])
def handle_action(cmd):
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    if cmd == 'start':
        db.delete("bot:admin_commands")
        db.rpush("bot:admin_commands", "START_BULK")
        return jsonify({"status": "ok", "message": "فرمان ثبت‌نام ارسال شد."})
    elif cmd == 'stop':
        db.rpush("bot:admin_commands", "STOP_EMERGENCY")
        return jsonify({"status": "ok", "message": "فرمان توقف صادر شد."})
    elif cmd == 'clean':
        req = request.json or {}
        if req.get('code') != 'NEXUS-WIPE-ALL': return jsonify({"status": "error", "message": "کد اشتباه است."})
        db.delete("jet:processed_phones", "jet:bulk_accounts", "jet:ordered_accounts", "bot:admin_alerts", "bot:new_accounts", "nexus:checker_logs")
        for key in db.keys("jet_session:*"): db.delete(key)
        return jsonify({"status": "ok", "message": "دیتابیس و لاگ‌ها به طور کامل پاک شدند."})
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
    if not session_str: return '<html dir="rtl"><body style="background:#f8fafc;color:#e11d48;font-family:Tahoma;text-align:center;padding:50px;"><h2>منقضی شده است.</h2></body></html>', 404
    u_agent, app_hdr = request.headers.get("User-Agent", ""), request.headers.get("X-Client-App", "")
    if app_hdr == APP_SECRET_HEADER or "JetAppClient" in u_agent:
        return jsonify({"status": "success", "session": json.loads(session_str)})
    return '<html dir="rtl"><body style="background:#f8fafc;color:#e11d48;font-family:Tahoma;text-align:center;padding:50px;"><h2>دسترسی مسدود است</h2></body></html>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
