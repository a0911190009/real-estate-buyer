# -*- coding: utf-8 -*-
"""
房仲工具 — 買方管理（real-estate-buyer）
管理買方需求、戰況版（斡旋中物件）、帶看紀錄。
Firestore 集合：
  buyers/       買方資料
  war_records/  戰況版（個人斡旋紀錄）
  showings/     帶看紀錄（buyer_id × prop_id 橋接）
"""

import os
import json
import uuid
from datetime import datetime, timezone, timedelta

from flask import Flask, request, session, redirect, jsonify
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# ── 讀取 .env ──
try:
    from dotenv import load_dotenv
    _dir = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(_dir, ".env"), os.path.join(_dir, "..", ".env")):
        if os.path.isfile(p):
            load_dotenv(p, override=False)
            break
except Exception:
    pass

# ── Firestore ──
try:
    from google.cloud import firestore as _firestore
    _db = None
except ImportError:
    _firestore = None
    _db = None


def _get_db():
    """取得 Firestore client（延遲初始化）。"""
    global _db
    if _db is not None:
        return _db
    if _firestore is None:
        return None
    try:
        _db = _firestore.Client(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT")
        )
        return _db
    except Exception as e:
        import logging
        logging.warning("Buyer: Firestore 初始化失敗: %s", e)
        return None


# ── Flask ──
app = Flask(__name__)
_secret = os.environ.get("FLASK_SECRET_KEY", "")
if not _secret:
    # 允許啟動，但 session 功能不安全（部署後立即補環境變數即可）
    import logging
    logging.warning("FLASK_SECRET_KEY 未設定，使用預設 dev key，請盡快補上環境變數。")
app.secret_key = _secret or "dev-only-insecure-key"
# SameSite=None：Portal 跨站跳轉後瀏覽器才能正確帶 session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

PORTAL_URL      = (os.environ.get("PORTAL_URL") or "").strip()
LIBRARY_URL     = (os.environ.get("LIBRARY_URL") or "").strip()
ADMIN_EMAILS    = [e.strip() for e in (os.environ.get("ADMIN_EMAILS") or "").split(",") if e.strip()]
SERVICE_API_KEY = (os.environ.get("SERVICE_API_KEY") or "").strip()
TOKEN_SERIALIZER = URLSafeTimedSerializer(app.secret_key)
TOKEN_MAX_AGE   = 300  # 5 分鐘，容忍 Cloud Run cold start


def _verify_service_key():
    """驗證 X-Service-Key header 與 SERVICE_API_KEY 一致。"""
    import hmac as _hmac
    if not SERVICE_API_KEY:
        return False
    key = request.headers.get("X-Service-Key", "")
    return _hmac.compare_digest(key, SERVICE_API_KEY)


def _is_admin(email):
    return email in ADMIN_EMAILS


def _require_user():
    email = session.get("user_email")
    if not email:
        return None, ("請先登入", 401)
    return email, None


def _now_str():
    """UTC+8 現在時間字串。"""
    return (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M")


# ══════════════════════════════════════════
#  Auth
# ══════════════════════════════════════════


VALID_THEME_STYLES = ["navy", "forest", "amber", "minimal", "rose", "oled"]

@app.route("/api/theme", methods=["GET"])
def api_theme_get():
    db = _get_db()
    style, mode = "navy", None
    if db:
        try:
            doc = db.collection("system_settings").document("theme").get()
            if doc.exists:
                d = doc.to_dict()
                style = d.get("style", "navy")
                mode = d.get("mode")
        except Exception:
            pass
    return jsonify({"style": style, "mode": mode})

@app.route("/api/theme", methods=["POST"])
def api_theme_set():
    email = session.get("user_email", "")
    if not email:
        return jsonify({"error": "請先登入"}), 401
    data = request.get_json(silent=True) or {}
    update = {}
    if "style" in data:
        if not _is_admin(email):
            return jsonify({"error": "無管理權限"}), 403
        style = data["style"]
        if style not in VALID_THEME_STYLES:
            return jsonify({"error": "無效風格"}), 400
        update["style"] = style
    if "mode" in data:
        mode = data["mode"]
        if mode in ("dark", "light", "system"):
            update["mode"] = mode
    if update:
        db = _get_db()
        if db:
            try:
                db.collection("system_settings").document("theme").set(update, merge=True)
            except Exception as e:
                return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})

@app.route("/health")
def health():
    return {"service": "real-estate-buyer", "status": "ok"}, 200


@app.route("/api/prop-suggest", methods=["GET"])
def api_prop_suggest_proxy():
    """
    代理 Library 的物件搜尋 API，避免瀏覽器跨域（CORS）問題。
    前端呼叫本服務的 /api/prop-suggest，由後端轉發至 Library。
    """
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"items": []})
    if not LIBRARY_URL:
        return jsonify({"items": [], "error": "LIBRARY_URL 未設定"})
    import urllib.request as _req
    import urllib.parse as _parse
    try:
        url = LIBRARY_URL.rstrip("/") + "/api/prop-suggest?q=" + _parse.quote(q)
        with _req.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return jsonify(data)
    except Exception as e:
        return jsonify({"items": [], "error": str(e)})


@app.route("/auth/portal-login", methods=["GET", "POST"])
def auth_portal_login():
    """Portal 跳轉過來時，驗證 token 建立 session。"""
    token = request.form.get("token") or request.args.get("token", "")
    if not token:
        return redirect(PORTAL_URL or "/")
    try:
        payload = TOKEN_SERIALIZER.loads(token, salt="portal-sso", max_age=TOKEN_MAX_AGE)
    except (SignatureExpired, BadSignature, Exception):
        return redirect(PORTAL_URL or "/")
    email = payload.get("email", "")
    if not email:
        return redirect(PORTAL_URL or "/")
    session["user_email"] = email
    session["user_name"]  = payload.get("name", "")
    session["user_picture"] = payload.get("picture", "")
    session.modified = True
    # 直接 render 首頁（不做任何 redirect），Set-Cookie 與 HTML 在同一個 response
    # 避免 Chrome SameSite 問題：跨站 redirect 後瀏覽器帶不到剛設的 cookie
    return _render_index(email)


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"redirect": PORTAL_URL or "/"})


@app.route("/api/me")
def api_me():
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    return jsonify({
        "email": email,
        "name":  session.get("user_name", ""),
        "picture": session.get("user_picture", ""),
        "is_admin": _is_admin(email),
    })


# ══════════════════════════════════════════
#  買方（buyers 集合）
# ══════════════════════════════════════════

@app.route("/api/buyers", methods=["GET"])
def api_buyers_list():
    """列出買方清單。管理員可看全部，一般用戶只看自己建立的。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        col = db.collection("buyers")
        if not _is_admin(email):
            # 只看自己建立的
            docs = col.where("created_by", "==", email).stream()
        else:
            docs = col.stream()
        items = []
        for d in docs:
            item = d.to_dict()
            item["id"] = d.id
            items.append(item)
        # 依建立時間排序（新→舊）
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify({"items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buyer-suggest", methods=["GET"])
def api_buyer_suggest():
    """
    公開 API（不需登入）：依關鍵字搜尋買方姓名，供其他工具（如行事曆）自動完成使用。
    查詢參數：q=關鍵字
    回傳格式：{"items": [{id, name, phone}]}
    """
    kw = (request.args.get("q") or "").strip().lower()
    if not kw:
        return jsonify({"items": []})

    db = _get_db()
    if db is None:
        return jsonify({"items": []})

    try:
        # 拉全部買方，在 Python 端過濾（Firestore 不支援 like 查詢）
        docs = db.collection("buyers").stream()
        items = []
        for d in docs:
            b = d.to_dict()
            name = b.get("name", "")
            # 姓名包含關鍵字才回傳
            if kw in name.lower():
                items.append({
                    "id":    d.id,
                    "name":  name,
                    "phone": b.get("phone", ""),
                })
            if len(items) >= 10:
                break
        return jsonify({"items": items})
    except Exception as e:
        import logging
        logging.warning("buyer-suggest error: %s", e)
        return jsonify({"items": []})


@app.route("/api/buyers", methods=["POST"])
def api_buyers_create():
    """新增買方。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        data = request.get_json(force=True) or {}
        doc = {
            "name":        str(data.get("name", "")).strip(),
            "phone":       str(data.get("phone", "")).strip(),
            "budget_min":  data.get("budget_min"),   # 萬
            "budget_max":  data.get("budget_max"),   # 萬
            "area":        str(data.get("area", "")).strip(),       # 地區需求
            "types":       data.get("types", []),                   # 物件類型（可複選）
            "size_min":    data.get("size_min"),      # 坪數下限
            "size_max":    data.get("size_max"),      # 坪數上限
            "note":        str(data.get("note", "")).strip(),       # 備註
            "status":      data.get("status", "洽談中"),            # 洽談中/成交/流失
            "created_by":  email,
            "created_at":  _now_str(),
            "updated_at":  _now_str(),
        }
        if not doc["name"]:
            return jsonify({"error": "請填寫買方姓名"}), 400
        ref = db.collection("buyers").document()
        ref.set(doc)
        return jsonify({"ok": True, "id": ref.id, **doc})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buyers/<buyer_id>", methods=["GET"])
def api_buyer_get(buyer_id):
    """取得單筆買方資料。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        doc = db.collection("buyers").document(buyer_id).get()
        if not doc.exists:
            return jsonify({"error": "找不到此買方"}), 404
        item = doc.to_dict()
        item["id"] = doc.id
        # 權限：自己建立的或管理員
        if not _is_admin(email) and item.get("created_by") != email:
            return jsonify({"error": "無權限"}), 403
        return jsonify(item)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buyers/<buyer_id>", methods=["PUT"])
def api_buyer_update(buyer_id):
    """更新買方資料。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        ref = db.collection("buyers").document(buyer_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "找不到此買方"}), 404
        item = doc.to_dict()
        if not _is_admin(email) and item.get("created_by") != email:
            return jsonify({"error": "無權限"}), 403
        data = request.get_json(force=True) or {}
        update = {
            "name":       str(data.get("name", item.get("name", ""))).strip(),
            "phone":      str(data.get("phone", item.get("phone", ""))).strip(),
            "budget_min": data.get("budget_min", item.get("budget_min")),
            "budget_max": data.get("budget_max", item.get("budget_max")),
            "area":       str(data.get("area", item.get("area", ""))).strip(),
            "types":      data.get("types", item.get("types", [])),
            "size_min":   data.get("size_min", item.get("size_min")),
            "size_max":   data.get("size_max", item.get("size_max")),
            "note":       str(data.get("note", item.get("note", ""))).strip(),
            "status":     data.get("status", item.get("status", "洽談中")),
            "updated_at": _now_str(),
        }
        ref.update(update)
        return jsonify({"ok": True, "id": buyer_id, **update})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buyers/<buyer_id>", methods=["DELETE"])
def api_buyer_delete(buyer_id):
    """刪除買方（同時刪除其帶看紀錄）。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        ref = db.collection("buyers").document(buyer_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "找不到此買方"}), 404
        item = doc.to_dict()
        if not _is_admin(email) and item.get("created_by") != email:
            return jsonify({"error": "無權限"}), 403
        # 同步刪除帶看紀錄
        showings = db.collection("showings").where("buyer_id", "==", buyer_id).stream()
        for s in showings:
            s.reference.delete()
        ref.delete()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════
#  帶看紀錄（showings 集合）
# ══════════════════════════════════════════

@app.route("/api/showings/by-prop", methods=["GET"])
def api_showings_by_prop():
    """
    公開 API（不需登入）：依 prop_id 查詢帶看紀錄。
    供物件庫跨服務呼叫，顯示「曾帶看買方」。
    回傳欄位：buyer_name, date, reaction, note（不回傳敏感電話/價格）。
    """
    prop_id = request.args.get("prop_id", "").strip()
    if not prop_id:
        return jsonify({"error": "缺少 prop_id"}), 400
    db = _get_db()
    if db is None:
        return jsonify({"items": []})
    try:
        docs = db.collection("showings").where("prop_id", "==", prop_id).stream()
        items = []
        for d in docs:
            r = d.to_dict()
            items.append({
                "id":          d.id,
                "buyer_name":  r.get("buyer_name", ""),
                "date":        r.get("date", ""),
                "reaction":    r.get("reaction", ""),
                "note":        r.get("note", ""),
            })
        items.sort(key=lambda x: x.get("date", ""), reverse=True)
        return jsonify({"items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/buyers/list-for-agent", methods=["GET"])
def api_buyers_list_for_agent():
    """Agent 專用：以 X-Service-Key 列出指定用戶的買方清單（簡化版）。
    Query: email=xxx（必填）"""
    if not _verify_service_key():
        return jsonify({"error": "需要有效的 X-Service-Key"}), 401
    email = (request.args.get("email") or "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "缺少有效的 email"}), 400
    db = _get_db()
    if db is None:
        return jsonify({"items": []})
    try:
        docs = db.collection("buyers").where("created_by", "==", email).stream()
        items = []
        for d in docs:
            item = d.to_dict()
            items.append({
                "id": d.id,
                "name": item.get("name", ""),
                "phone": item.get("phone", ""),
                "budget_min": item.get("budget_min", ""),
                "budget_max": item.get("budget_max", ""),
                "area_pref": item.get("area_pref", ""),
                "notes": item.get("notes", ""),
                "created_at": item.get("created_at", ""),
            })
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify({"items": items[:20]})  # 最多回傳 20 筆
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/showings/from-calendar", methods=["POST"])
def api_showings_from_calendar():
    """
    服務間 API：行事曆儲存帶看行程後呼叫，自動新增帶看紀錄。
    用共享 secret（FLASK_SECRET_KEY）驗證，不需 session。
    body: {
      secret, buyer_id, buyer_name,
      prop_id, prop_name, prop_address,
      date,          # YYYY-MM-DD
      calendar_event_id,  # 行事曆行程 ID，方便反查
      note
    }
    """
    _secret_key = os.environ.get("FLASK_SECRET_KEY", "")
    data = request.get_json(force=True) or {}

    # 驗證共享 secret
    if not _secret_key or data.get("secret") != _secret_key:
        return jsonify({"error": "未授權"}), 401

    buyer_id = str(data.get("buyer_id", "")).strip()
    if not buyer_id:
        return jsonify({"error": "缺少 buyer_id"}), 400

    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        doc = {
            "buyer_id":          buyer_id,
            "buyer_name":        str(data.get("buyer_name", "")).strip(),
            "prop_id":           str(data.get("prop_id", "")).strip(),
            "prop_name":         str(data.get("prop_name", "")).strip(),
            "prop_address":      str(data.get("prop_address", "")).strip(),
            "date":              str(data.get("date", _now_str()[:10])).strip(),
            "reaction":          "",        # 帶看反應待事後填寫
            "note":              str(data.get("note", "")).strip(),
            "calendar_event_id": str(data.get("calendar_event_id", "")).strip(),
            "created_by":        "calendar-service",   # 標記來源
            "created_at":        _now_str(),
        }
        ref = db.collection("showings").document()
        ref.set(doc)
        return jsonify({"ok": True, "id": ref.id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/showings", methods=["GET"])
def api_showings_list():
    """列出帶看紀錄。可依 buyer_id 或 prop_id 篩選。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        buyer_id = request.args.get("buyer_id", "").strip()
        prop_id  = request.args.get("prop_id", "").strip()
        col = db.collection("showings")
        if buyer_id:
            docs = col.where("buyer_id", "==", buyer_id).stream()
        elif prop_id:
            docs = col.where("prop_id", "==", prop_id).stream()
        else:
            # 只列自己建立的
            docs = col.where("created_by", "==", email).stream()
        items = []
        for d in docs:
            item = d.to_dict()
            item["id"] = d.id
            items.append(item)
        items.sort(key=lambda x: x.get("date", ""), reverse=True)
        return jsonify({"items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/showings", methods=["POST"])
def api_showings_create():
    """新增帶看紀錄。body: {buyer_id, prop_id, prop_name, prop_address, date, reaction, note}"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        data = request.get_json(force=True) or {}
        buyer_id = str(data.get("buyer_id", "")).strip()
        prop_id  = str(data.get("prop_id", "")).strip()
        if not buyer_id:
            return jsonify({"error": "請指定買方"}), 400
        doc = {
            "buyer_id":     buyer_id,
            "buyer_name":   str(data.get("buyer_name", "")).strip(),   # 冗餘存姓名，方便顯示
            "prop_id":      prop_id,
            "prop_name":    str(data.get("prop_name", "")).strip(),    # 冗餘存案名，序號改了仍能對應
            "prop_address": str(data.get("prop_address", "")).strip(),
            "date":         str(data.get("date", _now_str()[:10])).strip(),  # YYYY-MM-DD
            "reaction":     str(data.get("reaction", "")).strip(),     # 買方反應（有興趣/普通/不喜歡）
            "note":         str(data.get("note", "")).strip(),
            "created_by":   email,
            "created_at":   _now_str(),
        }
        ref = db.collection("showings").document()
        ref.set(doc)
        return jsonify({"ok": True, "id": ref.id, **doc})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/showings/<showing_id>", methods=["PUT"])
def api_showing_update(showing_id):
    """更新帶看紀錄（反應、備註）。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        ref = db.collection("showings").document(showing_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "找不到此紀錄"}), 404
        old = doc.to_dict()
        if not _is_admin(email) and old.get("created_by") != email:
            return jsonify({"error": "無權限"}), 403
        data = request.get_json(force=True) or {}
        update = {
            "date":     str(data.get("date", old.get("date", ""))).strip(),
            "reaction": str(data.get("reaction", old.get("reaction", ""))).strip(),
            "note":     str(data.get("note", old.get("note", ""))).strip(),
        }
        ref.update(update)
        return jsonify({"ok": True, "id": showing_id, **update})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/showings/<showing_id>", methods=["DELETE"])
def api_showing_delete(showing_id):
    """刪除帶看紀錄。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        ref = db.collection("showings").document(showing_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "找不到此紀錄"}), 404
        old = doc.to_dict()
        if not _is_admin(email) and old.get("created_by") != email:
            return jsonify({"error": "無權限"}), 403
        ref.delete()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════
#  戰況版（war_records 集合）
# ══════════════════════════════════════════

@app.route("/api/war", methods=["GET"])
def api_war_list():
    """列出戰況版（個人）。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        docs = db.collection("war_records").where("owner", "==", email).stream()
        items = []
        for d in docs:
            item = d.to_dict()
            item["id"] = d.id
            items.append(item)
        items.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
        return jsonify({"items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/war", methods=["POST"])
def api_war_create():
    """新增戰況物件。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        data = request.get_json(force=True) or {}
        def _s(key, default=""): return str(data.get(key, default) or "").strip()
        def _n(key): return data.get(key)  # 數字欄位，可為 None
        doc = {
            # ── 物件資訊 ──
            "prop_id":      _s("prop_id"),
            "prop_name":    _s("prop_name"),
            "prop_address": _s("prop_address"),
            "prop_price":   _n("prop_price"),         # 公告售價（萬）
            "my_offer":     _n("my_offer"),           # 我方出價/承購總價（萬）
            "floor_price":  _n("floor_price"),        # 屋主底價（私密）
            # ── 關聯紀錄 ──
            "buyer_id":     _s("buyer_id"),
            "buyer_name":   _s("buyer_name"),
            "showing_id":   _s("showing_id"),
            "status":       _s("status", "斡旋中"),   # 斡旋中/談判中/放棄/成交
            "note":         _s("note"),
            # ── 斡旋書編號 ──
            "war_no":       _s("war_no"),              # 斡旋書編號
            # ── 斡旋期間 ──
            "review_date":  _s("review_date"),         # 審閱日
            "war_date":     _s("war_date"),             # 斡旋日期
            "expire_date":  _s("expire_date"),          # 到期日
            # ── 契約變更（契變）──
            "contract_change_no":     _s("contract_change_no"),      # 契變編號
            "contract_change_expire": _s("contract_change_expire"),  # 變更後到期日
            "contract_change_amount": _n("contract_change_amount"),  # 變更後金額（萬）
            # ── 斡旋金 ──
            "deposit_amount":  _n("deposit_amount"),  # 斡旋金金額（萬）
            "deposit_type":    _s("deposit_type"),    # 現金/匯款/票據
            # ── 承購總價款與付款方式 ──
            "purchase_price":  _n("purchase_price"),  # 承購總價款（萬）
            "sign_amount":     _n("sign_amount"),      # 簽約款（萬）
            "sign_ratio":      _n("sign_ratio"),       # 簽約款比例（%）
            "tax_amount":      _n("tax_amount"),       # 完稅款（萬）
            "tax_ratio":       _n("tax_ratio"),        # 完稅款比例（%）
            "handover_amount": _n("handover_amount"),  # 交屋款（萬）
            "handover_ratio":  _n("handover_ratio"),   # 交屋款比例（%）
            "loan_amount":     _n("loan_amount"),      # 貸款金額（萬）
            # ── 服務報酬 ──
            "service_fee_ratio": _n("service_fee_ratio") if _n("service_fee_ratio") is not None else 2.0,  # 買方服務費（%，預設2%）
            "service_fee_amount": _n("service_fee_amount"),  # 服務費金額（萬）
            # ── 買方個人資料 ──
            "buyer_id_no":   _s("buyer_id_no"),       # 身分證字號
            "buyer_birthday": _s("buyer_birthday"),   # 出生年月日
            "buyer_address": _s("buyer_address"),     # 戶籍地址
            "buyer_phone":   _s("buyer_phone"),       # 電話
            # ── 系統欄位 ──
            "owner":        email,
            "created_at":   _now_str(),
            "updated_at":   _now_str(),
        }
        if not doc["prop_name"]:
            return jsonify({"error": "請填寫物件名稱"}), 400
        ref = db.collection("war_records").document()
        ref.set(doc)
        return jsonify({"ok": True, "id": ref.id, **doc})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/war/<war_id>", methods=["PUT"])
def api_war_update(war_id):
    """更新戰況紀錄。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        ref = db.collection("war_records").document(war_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "找不到此紀錄"}), 404
        old = doc.to_dict()
        if old.get("owner") != email and not _is_admin(email):
            return jsonify({"error": "無權限"}), 403
        data = request.get_json(force=True) or {}
        fields = [
            # 物件資訊
            "prop_name", "prop_address", "prop_price", "my_offer", "floor_price",
            # 關聯紀錄
            "buyer_id", "buyer_name", "showing_id", "status", "note",
            # 斡旋書編號
            "war_no",
            # 斡旋期間
            "review_date", "war_date", "expire_date",
            # 契約變更
            "contract_change_no", "contract_change_expire", "contract_change_amount",
            # 斡旋金
            "deposit_amount", "deposit_type",
            # 承購總價款與付款方式
            "purchase_price", "sign_amount", "sign_ratio",
            "tax_amount", "tax_ratio", "handover_amount", "handover_ratio", "loan_amount",
            # 服務報酬
            "service_fee_ratio", "service_fee_amount",
            # 買方個人資料
            "buyer_id_no", "buyer_birthday", "buyer_address", "buyer_phone",
        ]
        update = {"updated_at": _now_str()}
        for f in fields:
            if f in data:
                update[f] = data[f]
        ref.update(update)
        return jsonify({"ok": True, "id": war_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/war/<war_id>", methods=["DELETE"])
def api_war_delete(war_id):
    """刪除戰況紀錄。"""
    email, err = _require_user()
    if err:
        return jsonify({"error": err[0]}), err[1]
    db = _get_db()
    if db is None:
        return jsonify({"error": "Firestore 未連線"}), 503
    try:
        ref = db.collection("war_records").document(war_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "找不到此紀錄"}), 404
        if doc.to_dict().get("owner") != email and not _is_admin(email):
            return jsonify({"error": "無權限"}), 403
        ref.delete()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════
#  主頁（回傳 HTML）
# ══════════════════════════════════════════

def _render_index(email):
    """產生並回傳買方管理首頁 HTML（供 index 和 auth_portal_login 共用）。"""
    is_admin     = _is_admin(email)
    user_name    = session.get("user_name", email)
    user_picture = session.get("user_picture", "")
    portal_url   = PORTAL_URL or "/"
    library_url  = LIBRARY_URL or ""
    IS_ADMIN_JSON = json.dumps(is_admin)
    role_label   = "管理員" if is_admin else "業務"
    badge_class  = "admin" if is_admin else "points"
    initial      = (user_name or user_picture or "?")[0].upper()
    html = (HTML_TEMPLATE
        .replace('__AVATAR__',      user_picture)
        .replace('__INITIAL__',     initial)
        .replace('__USER_NAME__',   user_name)
        .replace('__PORTAL_URL__',  portal_url)
        .replace('__LIBRARY_URL__', json.dumps(library_url))
        .replace('__ROLE_LABEL__',  role_label)
        .replace('__BADGE_CLASS__', badge_class)
        .replace('__IS_ADMIN__',    IS_ADMIN_JSON)
    )
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.route("/")
def index():
    email, err = _require_user()
    if err:
        return redirect(PORTAL_URL or "/auth/portal-login")
    return _render_index(email)


# ══════════════════════════════════════════
#  HTML 模板
# ══════════════════════════════════════════

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <link rel="icon" type="image/png" href="data:image/png;base64,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">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>買方管理</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
/* ══ 6 套主題 CSS 變數 ══ */
[data-theme="navy-dark"]{--bg-p:#0f172a;--bg-s:#1e293b;--bg-t:#293548;--bg-h:#334155;--bd:#334155;--bdl:#475569;--tx:#f1f5f9;--txs:#94a3b8;--txm:#64748b;--ac:#3b82f6;--ach:#2563eb;--act:#fff;--acs:rgba(59,130,246,0.15);--dg:#f87171;--dgb:rgba(239,68,68,0.15);--ok:#34d399;--warn:#fbbf24;--tg:#1d4ed8;--tgt:#bfdbfe;--sh:0 8px 32px rgba(0,0,0,0.5);}
[data-theme="navy-light"]{--bg-p:#f0f4f8;--bg-s:#fff;--bg-t:#f8fafc;--bg-h:#e2e8f0;--bd:#cbd5e1;--bdl:#e2e8f0;--tx:#0f172a;--txs:#475569;--txm:#94a3b8;--ac:#2563eb;--ach:#1d4ed8;--act:#fff;--acs:rgba(37,99,235,0.1);--dg:#dc2626;--dgb:rgba(220,38,38,0.08);--ok:#16a34a;--warn:#d97706;--tg:#dbeafe;--tgt:#1e40af;--sh:0 4px 16px rgba(0,0,0,0.1);}
[data-theme="forest-dark"]{--bg-p:#0a1a12;--bg-s:#132218;--bg-t:#1a3024;--bg-h:#1e3d2a;--bd:#1e3d2a;--bdl:#2d5a3e;--tx:#ecfdf5;--txs:#86efac;--txm:#4ade80;--ac:#22c55e;--ach:#16a34a;--act:#fff;--acs:rgba(34,197,94,0.15);--dg:#f87171;--dgb:rgba(239,68,68,0.15);--ok:#34d399;--warn:#fbbf24;--tg:#14532d;--tgt:#86efac;--sh:0 8px 32px rgba(0,0,0,0.6);}
[data-theme="forest-light"]{--bg-p:#f0fdf4;--bg-s:#fff;--bg-t:#f7fef9;--bg-h:#dcfce7;--bd:#bbf7d0;--bdl:#dcfce7;--tx:#14532d;--txs:#166534;--txm:#4ade80;--ac:#16a34a;--ach:#15803d;--act:#fff;--acs:rgba(22,163,74,0.1);--dg:#dc2626;--dgb:rgba(220,38,38,0.08);--ok:#16a34a;--warn:#d97706;--tg:#dcfce7;--tgt:#14532d;--sh:0 4px 16px rgba(0,80,40,0.1);}
[data-theme="amber-dark"]{--bg-p:#1a1208;--bg-s:#261a0c;--bg-t:#332210;--bg-h:#3d2b14;--bd:#3d2b14;--bdl:#5c3d1e;--tx:#fef3c7;--txs:#fcd34d;--txm:#d97706;--ac:#f59e0b;--ach:#d97706;--act:#1a1208;--acs:rgba(245,158,11,0.15);--dg:#f87171;--dgb:rgba(239,68,68,0.15);--ok:#34d399;--warn:#fbbf24;--tg:#78350f;--tgt:#fde68a;--sh:0 8px 32px rgba(0,0,0,0.6);}
[data-theme="amber-light"]{--bg-p:#fffbeb;--bg-s:#fff;--bg-t:#fefce8;--bg-h:#fef3c7;--bd:#fde68a;--bdl:#fef3c7;--tx:#451a03;--txs:#92400e;--txm:#b45309;--ac:#d97706;--ach:#b45309;--act:#fff;--acs:rgba(217,119,6,0.1);--dg:#dc2626;--dgb:rgba(220,38,38,0.08);--ok:#16a34a;--warn:#d97706;--tg:#fef3c7;--tgt:#78350f;--sh:0 4px 16px rgba(180,100,0,0.1);}
[data-theme="minimal-light"]{--bg-p:#f9fafb;--bg-s:#fff;--bg-t:#f3f4f6;--bg-h:#f3f4f6;--bd:#e5e7eb;--bdl:#f3f4f6;--tx:#111827;--txs:#6b7280;--txm:#9ca3af;--ac:#4f46e5;--ach:#4338ca;--act:#fff;--acs:rgba(79,70,229,0.08);--dg:#ef4444;--dgb:rgba(239,68,68,0.08);--ok:#10b981;--warn:#f59e0b;--tg:#ede9fe;--tgt:#4c1d95;--sh:0 1px 8px rgba(0,0,0,0.08);}
[data-theme="minimal-dark"]{--bg-p:#18181b;--bg-s:#27272a;--bg-t:#3f3f46;--bg-h:#3f3f46;--bd:#3f3f46;--bdl:#52525b;--tx:#fafafa;--txs:#a1a1aa;--txm:#71717a;--ac:#6366f1;--ach:#4f46e5;--act:#fff;--acs:rgba(99,102,241,0.15);--dg:#f87171;--dgb:rgba(239,68,68,0.15);--ok:#34d399;--warn:#fbbf24;--tg:#312e81;--tgt:#c7d2fe;--sh:0 8px 32px rgba(0,0,0,0.5);}
[data-theme="rose-light"]{--bg-p:#fff1f2;--bg-s:#fff;--bg-t:#fff1f2;--bg-h:#ffe4e6;--bd:#fecdd3;--bdl:#ffe4e6;--tx:#4c0519;--txs:#9f1239;--txm:#e11d48;--ac:#e11d48;--ach:#be123c;--act:#fff;--acs:rgba(225,29,72,0.08);--dg:#be123c;--dgb:rgba(190,18,60,0.08);--ok:#16a34a;--warn:#d97706;--tg:#ffe4e6;--tgt:#9f1239;--sh:0 4px 16px rgba(200,0,50,0.1);}
[data-theme="rose-dark"]{--bg-p:#1a0810;--bg-s:#2a0f1c;--bg-t:#3a1528;--bg-h:#4a1a32;--bd:#4a1a32;--bdl:#6b2545;--tx:#fff1f2;--txs:#fda4af;--txm:#fb7185;--ac:#fb7185;--ach:#f43f5e;--act:#fff;--acs:rgba(251,113,133,0.15);--dg:#f87171;--dgb:rgba(239,68,68,0.15);--ok:#34d399;--warn:#fbbf24;--tg:#881337;--tgt:#fda4af;--sh:0 8px 32px rgba(0,0,0,0.6);}
[data-theme="oled-dark"]{--bg-p:#000;--bg-s:#0a0a0a;--bg-t:#141414;--bg-h:#1f1f1f;--bd:#1f1f1f;--bdl:#2d2d2d;--tx:#fff;--txs:#a3a3a3;--txm:#525252;--ac:#fff;--ach:#e5e5e5;--act:#000;--acs:rgba(255,255,255,0.08);--dg:#f87171;--dgb:rgba(239,68,68,0.15);--ok:#34d399;--warn:#fbbf24;--tg:#1f1f1f;--tgt:#a3a3a3;--sh:0 8px 32px rgba(0,0,0,0.8);}

/* ══ 通用樣式（全用 CSS 變數）══ */
*,*::before,*::after{box-sizing:border-box;}
body{background:var(--bg-p);color:var(--tx);font-family:'Noto Sans TC','Segoe UI',sans-serif;min-height:100vh;transition:background 0.3s,color 0.3s;}
.tab-btn{transition:color .15s,border-color .15s;}
.tab-btn.active{color:var(--ac);border-bottom:2px solid var(--ac);font-weight:600;}
.card{background:var(--bg-s);border:1px solid var(--bd);border-radius:1rem;padding:1rem;transition:background 0.3s,border-color 0.3s;}
.badge{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:.7rem;font-weight:600;}
.badge-blue{background:#1d4ed8;color:#bfdbfe;}
.badge-green{background:#166534;color:#bbf7d0;}
.badge-red{background:#991b1b;color:#fecaca;}
.badge-gray{background:#374151;color:#9ca3af;}
.badge-amber{background:#92400e;color:#fde68a;}
.badge-role{background:var(--tg);color:var(--tgt);}
.points-pill{display:inline-flex;align-items:center;padding:0.2rem 0.6rem;border-radius:9999px;font-size:0.72rem;font-weight:600;white-space:nowrap;}
.points-pill.admin{background:rgba(139,92,246,0.2);color:rgb(196,167,255);}
.points-pill.sub{background:rgba(34,197,94,0.2);color:rgb(134,239,172);}
.points-pill.points{background:var(--acs);color:var(--ac);}
.btn-primary{background:var(--ac);color:var(--act);border-radius:.5rem;padding:.4rem 1rem;font-size:.85rem;font-weight:600;transition:background .15s;border:none;cursor:pointer;}
.btn-primary:hover{background:var(--ach);}
.btn-ghost{background:transparent;color:var(--txs);border:1px solid var(--bdl);border-radius:.5rem;padding:.4rem 1rem;font-size:.85rem;transition:all .15s;cursor:pointer;}
.btn-ghost:hover{color:var(--tx);border-color:var(--txs);}
.btn-danger{background:var(--dg);color:#fff;border-radius:.5rem;padding:.4rem 1rem;font-size:.85rem;font-weight:600;transition:background .15s;border:none;cursor:pointer;}
.btn-danger:hover{opacity:0.85;}
input,textarea,select{background:var(--bg-s);border:1px solid var(--bdl);color:var(--tx);border-radius:.5rem;padding:.45rem .75rem;font-size:.875rem;width:100%;outline:none;}
input:focus,textarea:focus,select:focus{border-color:var(--ac);}
input::placeholder,textarea::placeholder{color:var(--txm);}
label{font-size:.8rem;color:var(--txs);display:block;margin-bottom:.25rem;}
.modal-bg{position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.65);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:1rem;}
.modal-box{background:var(--bg-s);border:1px solid var(--bdl);border-radius:1.25rem;width:100%;max-width:520px;max-height:92vh;overflow-y:auto;box-shadow:var(--sh);}
.modal-box::-webkit-scrollbar{width:6px;}
.modal-box::-webkit-scrollbar-thumb{background:var(--bdl);border-radius:3px;}
#toast-container{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;}
.toast-item{padding:.6rem 1.2rem;border-radius:.75rem;font-size:.875rem;font-weight:500;box-shadow:var(--sh);animation:slideIn .2s ease;}
.toast-info{background:#1e40af;color:#bfdbfe;}
.toast-success{background:#166534;color:#bbf7d0;}
.toast-error{background:#991b1b;color:#fecaca;}
.toast-out{opacity:0;transition:opacity .3s;}
@keyframes slideIn{from{transform:translateX(2rem);opacity:0}to{transform:none;opacity:1}}
.reaction-好{color:var(--ok);}
.reaction-普通{color:var(--warn);}
.reaction-差{color:var(--dg);}
/* ── 統一 Sidebar ── */
#app-sidebar{position:fixed;top:0;left:0;height:100%;width:224px;background:var(--bg-s);border-right:1px solid var(--bd);display:flex;flex-direction:column;z-index:300;transition:background 0.3s,border-color 0.3s;}
#app-sidebar .sb-logo{display:flex;align-items:center;gap:8px;padding:14px 16px;border-bottom:1px solid var(--bd);font-weight:600;color:var(--tx);font-size:0.85rem;}
#app-sidebar nav{flex:1;padding:16px 8px;display:flex;flex-direction:column;gap:2px;}
#app-sidebar nav a{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;color:var(--txs);font-size:0.875rem;font-weight:500;text-decoration:none;transition:background 0.15s,color 0.15s;}
#app-sidebar nav a:hover,#app-sidebar nav a.active{background:var(--acs);color:var(--ac);}
#app-sidebar .sb-user{padding:12px 8px;border-top:1px solid var(--bd);}
#app-sidebar .sb-user button{width:100%;display:flex;align-items:center;gap:12px;padding:8px 10px;border-radius:10px;border:none;background:none;cursor:pointer;color:var(--txs);font-size:0.875rem;text-align:left;transition:background 0.15s;}
#app-sidebar .sb-user button:hover{background:var(--bg-h);}
#app-header{display:none;position:sticky;top:0;z-index:250;background:var(--bg-s);border-bottom:1px solid var(--bd);padding:10px 16px;align-items:center;justify-content:space-between;transition:background 0.3s;}
#app-header .hd-logo{font-weight:600;color:var(--tx);font-size:0.85rem;}
/* 通用頭像容器 */
.av-wrap{position:relative;flex-shrink:0;border-radius:50%;overflow:hidden;border:2px solid var(--bdl);}
.av-wrap img{position:absolute;inset:0;width:100%;height:100%;border-radius:50%;object-fit:cover;}
.av-wrap .av-fb{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:0.9rem;background:linear-gradient(135deg,var(--ac),var(--ach));}
/* Dropdown */
#user-dropdown{position:fixed;z-index:500;width:220px;background:var(--bg-s);border:1px solid var(--bd);border-radius:14px;box-shadow:var(--sh);overflow:hidden;display:none;}
#user-dropdown .dd-header{padding:12px 16px;border-bottom:1px solid var(--bd);background:var(--bg-p);}
#user-dropdown .dd-header p{margin:0;font-size:0.85rem;font-weight:600;color:var(--tx);}
#user-dropdown a,#user-dropdown button{display:flex;align-items:center;gap:10px;width:100%;padding:10px 16px;border:none;background:none;color:var(--txs);font-size:0.85rem;text-decoration:none;cursor:pointer;text-align:left;transition:background 0.15s;}
#user-dropdown a:hover,#user-dropdown button:hover{background:var(--bg-h);color:var(--tx);}
#user-dropdown .dd-danger{color:var(--dg);}
#user-dropdown .dd-danger:hover{background:var(--dgb);}
#user-dropdown .dd-divider{height:1px;background:var(--bd);margin:4px 0;}
@media(min-width:768px){body{padding-left:calc(224px + 1.5rem);padding-right:1.5rem;}}
@media(max-width:767px){#app-sidebar{display:none;}#app-header{display:flex;}body{padding-left:1rem;padding-right:1rem;padding-bottom:72px;}}
/* 手機底部 Tab Bar */
#buyer-tab-bar{position:fixed;bottom:0;left:0;right:0;z-index:250;background:var(--bg-s);backdrop-filter:blur(8px);border-top:1px solid var(--bd);display:none;transition:background 0.3s;}
@media(max-width:767px){#buyer-tab-bar{display:flex;}}
.buyer-tb-item{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;padding:8px 4px;color:var(--txm);font-size:0.65rem;text-decoration:none;transition:color 0.15s;position:relative;border-top:2px solid transparent;}
.buyer-tb-item:hover{color:var(--tx)!important;}
.buyer-tb-active{color:var(--ac)!important;border-top-color:var(--ac)!important;}
/* 外觀切換按鈕 */
#theme-toggle-btn{width:100%;display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:10px;border:none;background:none;cursor:pointer;color:var(--txs);font-size:0.82rem;text-align:left;transition:background 0.15s;}
#theme-toggle-btn:hover{background:var(--bg-h);color:var(--tx);}
/* 外觀設定面板 */
#theme-panel{position:fixed;top:0;right:0;bottom:0;width:288px;background:var(--bg-s);border-left:1px solid var(--bd);z-index:800;padding:20px;overflow-y:auto;box-shadow:var(--sh);transition:background 0.3s,border-color 0.3s;}
.tp-style-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;}
.tp-style-card{border:2px solid var(--bd);border-radius:10px;padding:8px;cursor:pointer;transition:border-color 0.2s,transform 0.15s;position:relative;overflow:hidden;}
.tp-style-card:hover{transform:scale(1.02);}
.tp-style-card.selected{border-color:var(--ac);}
.tp-style-card .preview{height:44px;border-radius:6px;margin-bottom:6px;display:flex;overflow:hidden;}
.tp-style-card .preview .sb-strip{width:28%;height:100%;}
.tp-style-card .preview .ct-strip{flex:1;height:100%;padding:3px;display:flex;flex-direction:column;gap:2px;}
.tp-style-card .preview .ln{border-radius:2px;height:5px;}
.tp-check{position:absolute;top:5px;right:5px;width:16px;height:16px;border-radius:50%;background:var(--ac);color:var(--act);font-size:9px;display:none;align-items:center;justify-content:center;}
.tp-style-card.selected .tp-check{display:flex;}
.tp-style-name{font-size:0.72rem;font-weight:600;color:var(--tx);margin-bottom:1px;}
.tp-style-desc{font-size:0.62rem;color:var(--txm);}
.tp-mode-row{display:flex;gap:5px;margin-bottom:14px;}
.tp-mode-btn{flex:1;padding:7px 4px;border-radius:7px;border:1px solid var(--bd);background:none;color:var(--txs);font-size:0.74rem;cursor:pointer;transition:all 0.15s;}
.tp-mode-btn.active{background:var(--ac);color:var(--act);border-color:var(--ac);}
.tp-section{font-size:0.68rem;font-weight:600;color:var(--txm);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px;margin-top:14px;}
</style>
</head>
<body data-theme="navy-dark">

<!-- ── 外觀設定面板 ── -->
<div id="theme-panel" style="display:none;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
    <div style="font-size:0.95rem;font-weight:700;color:var(--tx);">🎨 外觀設定</div>
    <button onclick="document.getElementById('theme-panel').style.display='none'" style="background:none;border:none;color:var(--txm);cursor:pointer;font-size:1.2rem;line-height:1;">✕</button>
  </div>
  <div style="font-size:0.75rem;color:var(--txm);margin-bottom:14px;">管理員設定的風格，所有成員同步套用</div>
  <div class="tp-section">明暗模式（個人）</div>
  <div class="tp-mode-row" id="tp-mode-row">
    <button class="tp-mode-btn" id="tp-btn-dark" onclick="window._tpSetMode('dark')">🌙 深色</button>
    <button class="tp-mode-btn" id="tp-btn-light" onclick="window._tpSetMode('light')">☀️ 淺色</button>
    <button class="tp-mode-btn" id="tp-btn-system" onclick="window._tpSetMode('system')">🖥️ 系統</button>
  </div>
  <div id="tp-admin-only" style="display:none;">
    <div class="tp-section">色系風格（後台統一）</div>
    <div class="tp-style-grid" id="tp-style-grid">
      <div class="tp-style-card" id="tp-card-navy" onclick="window._tpAdminSetStyle('navy')">
        <div class="preview"><div class="sb-strip" style="background:#1e293b;"></div><div class="ct-strip" style="background:#0f172a;"><div class="ln" style="background:#334155;width:80%;"></div><div class="ln" style="background:#3b82f6;width:50%;"></div><div class="ln" style="background:#334155;width:65%;"></div></div></div>
        <div class="tp-check">✓</div><div class="tp-style-name">🌙 深夜藍</div><div class="tp-style-desc">穩重專業</div>
      </div>
      <div class="tp-style-card" id="tp-card-forest" onclick="window._tpAdminSetStyle('forest')">
        <div class="preview"><div class="sb-strip" style="background:#132218;"></div><div class="ct-strip" style="background:#0a1a12;"><div class="ln" style="background:#1e3d2a;width:80%;"></div><div class="ln" style="background:#22c55e;width:50%;"></div><div class="ln" style="background:#1e3d2a;width:65%;"></div></div></div>
        <div class="tp-check">✓</div><div class="tp-style-name">🌿 森林綠</div><div class="tp-style-desc">清新活力</div>
      </div>
      <div class="tp-style-card" id="tp-card-amber" onclick="window._tpAdminSetStyle('amber')">
        <div class="preview"><div class="sb-strip" style="background:#261a0c;"></div><div class="ct-strip" style="background:#1a1208;"><div class="ln" style="background:#3d2b14;width:80%;"></div><div class="ln" style="background:#f59e0b;width:50%;"></div><div class="ln" style="background:#3d2b14;width:65%;"></div></div></div>
        <div class="tp-check">✓</div><div class="tp-style-name">🌅 暖棕商務</div><div class="tp-style-desc">低調奢華</div>
      </div>
      <div class="tp-style-card" id="tp-card-minimal" onclick="window._tpAdminSetStyle('minimal')">
        <div class="preview"><div class="sb-strip" style="background:#fff;border-right:1px solid #e5e7eb;"></div><div class="ct-strip" style="background:#f9fafb;"><div class="ln" style="background:#e5e7eb;width:80%;"></div><div class="ln" style="background:#4f46e5;width:50%;"></div><div class="ln" style="background:#e5e7eb;width:65%;"></div></div></div>
        <div class="tp-check">✓</div><div class="tp-style-name">⬜ 純白簡約</div><div class="tp-style-desc">清晰易讀</div>
      </div>
      <div class="tp-style-card" id="tp-card-rose" onclick="window._tpAdminSetStyle('rose')">
        <div class="preview"><div class="sb-strip" style="background:#2a0f1c;"></div><div class="ct-strip" style="background:#1a0810;"><div class="ln" style="background:#4a1a32;width:80%;"></div><div class="ln" style="background:#fb7185;width:50%;"></div><div class="ln" style="background:#4a1a32;width:65%;"></div></div></div>
        <div class="tp-check">✓</div><div class="tp-style-name">🌸 玫瑰粉</div><div class="tp-style-desc">優雅浪漫</div>
      </div>
      <div class="tp-style-card" id="tp-card-oled" onclick="window._tpAdminSetStyle('oled')">
        <div class="preview"><div class="sb-strip" style="background:#0a0a0a;"></div><div class="ct-strip" style="background:#000;"><div class="ln" style="background:#1f1f1f;width:80%;"></div><div class="ln" style="background:#fff;width:50%;"></div><div class="ln" style="background:#1f1f1f;width:65%;"></div></div></div>
        <div class="tp-check">✓</div><div class="tp-style-name">🖤 OLED 黑</div><div class="tp-style-desc">省電護眼</div>
      </div>
    </div>
    <button onclick="window._tpSaveStyle()" style="width:100%;padding:9px;border-radius:8px;background:var(--ac);color:var(--act);border:none;cursor:pointer;font-size:0.85rem;font-weight:600;">💾 套用到所有工具</button>
    <div id="tp-save-msg" style="text-align:center;font-size:0.75rem;color:var(--ok);margin-top:6px;display:none;">✓ 已儲存！所有工具同步套用</div>
  </div>
  <div style="margin-top:14px;padding:10px;border-radius:8px;background:var(--bg-t);border:1px solid var(--bd);font-size:0.7rem;color:var(--txm);line-height:1.6;">
    💡 風格由管理員統一設定，明暗模式依個人裝置偏好儲存。
  </div>
</div>

<!-- ── 桌機左側 Sidebar ── -->
<aside id="app-sidebar">
  <div class="sb-logo">
    <span style="font-size:1.3rem;">👥</span>
    <span>買方管理</span>
  </div>
  <nav>
    <a href="__PORTAL_URL__" target="tool-portal" id="sb-portal-home">🏠 工具首頁</a>
    <a href="javascript:void(0)" id="sb-ad" class="hidden">📝 廣告文案</a>
    <a href="javascript:void(0)" id="sb-library" class="hidden">📁 物件庫</a>
    <a href="#" class="active">👥 買方管理</a>
    <a href="javascript:void(0)" id="sb-survey" class="hidden">📍 周邊調查</a>
    <a href="javascript:void(0)" id="sb-calendar" class="hidden">📅 業務行事曆</a>
  </nav>
  <div class="sb-user">
    <button type="button" onclick="buyerToggleDropdown(event)">
      <div id="sb-avatar" class="av-wrap" style="width:36px;height:36px;flex-shrink:0;"><div class="av-fb">__INITIAL__</div></div>
      <div style="min-width:0;flex:1;">
        <div id="sb-name" style="font-size:0.82rem;font-weight:600;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">__USER_NAME__</div>
        <span id="sb-badge" class="points-pill __BADGE_CLASS__" style="margin-top:2px;">__ROLE_LABEL__</span>
      </div>
      <svg style="width:16px;height:16px;color:var(--txm);flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
    </button>
  </div>
</aside>

<!-- ── 手機頂部 Header ── -->
<header id="app-header">
  <div class="hd-logo">👥 買方管理</div>
  <div style="display:flex;align-items:center;gap:8px;cursor:pointer;" onclick="buyerToggleDropdown(event)">
    <span id="hd-badge" class="points-pill __BADGE_CLASS__">__ROLE_LABEL__</span>
    <div id="hd-avatar" class="av-wrap" style="width:34px;height:34px;cursor:pointer;"><div class="av-fb">__INITIAL__</div></div>
  </div>
</header>

<!-- ── 使用者 Dropdown ── -->
<div id="user-dropdown">
  <div class="dd-header">
    <p id="dd-name">__USER_NAME__</p>
    <span id="dd-badge" class="points-pill __BADGE_CLASS__" style="margin-top:4px;">__ROLE_LABEL__</span>
  </div>
  <div style="padding:4px 0;">
    <a id="dd-plans" href="javascript:void(0)" class="hidden">⬆️ 升級方案</a>
    <a id="dd-account" href="javascript:void(0)" class="hidden">👤 帳號管理</a>
    <a id="dd-admin" href="javascript:void(0)" class="hidden">🛡️ 後台管理</a>
    <button onclick="buyerCloseDropdown();document.getElementById('theme-panel').style.display='block';" style="display:flex;align-items:center;gap:10px;width:100%;padding:10px 16px;border:none;background:none;color:var(--txs);font-size:0.85rem;cursor:pointer;text-align:left;transition:background 0.15s;" onmouseover="this.style.background='var(--bg-h)';this.style.color='var(--tx)'" onmouseout="this.style.background='none';this.style.color='var(--txs)'">🎨 外觀設定</button>
  </div>
  <div class="dd-divider"></div>
  <div style="padding:4px 0;">
    <button class="dd-danger" onclick="buyerDoLogout()">🚪 登出</button>
  </div>
</div>
<div id="user-dropdown-backdrop" style="display:none;position:fixed;inset:0;z-index:499;" onclick="buyerCloseDropdown()"></div>

<!-- ── 手機底部 Tab Bar（仿 Portal 固定顯示所有工具） ── -->
<nav id="buyer-tab-bar">
  <a href="__PORTAL_URL__" id="tb-home" class="buyer-tb-item">
    <span style="font-size:1.25rem;">🏠</span>
    <span>首頁</span>
  </a>
  <a href="javascript:void(0)" id="tb-ad" class="buyer-tb-item">
    <span style="font-size:1.25rem;">📝</span>
    <span>廣告</span>
  </a>
  <a href="javascript:void(0)" id="tb-library" class="buyer-tb-item">
    <span style="font-size:1.25rem;">📁</span>
    <span>物件庫</span>
  </a>
  <a href="#" class="buyer-tb-item buyer-tb-active">
    <span style="font-size:1.25rem;">👥</span>
    <span>買方</span>
  </a>
  <a href="javascript:void(0)" id="tb-survey" class="buyer-tb-item">
    <span style="font-size:1.25rem;">📍</span>
    <span>周邊</span>
  </a>
  <a href="javascript:void(0)" id="tb-calendar" class="buyer-tb-item">
    <span style="font-size:1.25rem;">📅</span>
    <span>行事曆</span>
  </a>
</nav>

<!-- ── 頂部分頁列 ── -->
<header class="sticky top-0 z-50" style="background:var(--bg-s);border-bottom:1px solid var(--bd);">
  <!-- 分頁 -->
  <div class="flex max-w-4xl mx-auto" style="border-top:1px solid var(--bd);">
    <button id="tab-buyers"   onclick="switchTab('buyers')"
      class="tab-btn active flex-1 py-2 text-sm font-medium border-b-2" style="color:var(--ac);border-color:var(--ac);">
      👥 買方列表
    </button>
    <button id="tab-war"      onclick="switchTab('war')"
      class="tab-btn flex-1 py-2 text-sm font-medium border-b-2 border-transparent" style="color:var(--txs);">
      ⚔️ 戰況版
    </button>
    <button id="tab-showings" onclick="switchTab('showings')"
      class="tab-btn flex-1 py-2 text-sm font-medium border-b-2 border-transparent" style="color:var(--txs);">
      🗓 帶看紀錄
    </button>
  </div>
</header>

<div id="toast-container"></div>

<!-- ══ 買方列表 ══ -->
<div id="pane-buyers" class="max-w-4xl mx-auto px-4 py-6">
  <div class="flex items-center justify-between mb-4">
    <h2 class="font-bold text-lg" style="color:var(--tx);">👥 買方列表</h2>
    <button class="btn-primary" onclick="buyerOpenNew()">＋ 新增買方</button>
  </div>
  <!-- 搜尋 + 篩選 + 排序 -->
  <div class="flex gap-2 mb-2 flex-wrap">
    <input id="buyer-search" type="text" placeholder="搜尋姓名、地區、類型…" oninput="buyerFilter()" class="flex-1 min-w-40">
    <select id="buyer-status-filter" onchange="buyerFilter()" style="width:auto">
      <option value="">全部狀態</option>
      <option value="洽談中">洽談中</option>
      <option value="成交">成交</option>
      <option value="流失">流失</option>
    </select>
    <select id="buyer-sort" onchange="buyerFilter()" style="width:auto" title="排序方式">
      <option value="war_first">⚔️ 斡旋優先</option>
      <option value="updated_desc">更新日 新→舊</option>
      <option value="updated_asc">更新日 舊→新</option>
      <option value="created_desc">建立日 新→舊</option>
      <option value="created_asc">建立日 舊→新</option>
      <option value="showing_desc">帶看次數 多→少</option>
      <option value="name_asc">姓名 排序</option>
    </select>
  </div>
  <div id="buyer-list" class="space-y-3">
    <p class="text-center py-12" style="color:var(--txs);">載入中…</p>
  </div>
</div>

<!-- ══ 戰況版 ══ -->
<div id="pane-war" style="display:none" class="max-w-4xl mx-auto px-4 py-6">
  <div class="flex items-center justify-between mb-4">
    <div>
      <h2 class="font-bold text-lg" style="color:var(--tx);">⚔️ 斡旋戰況版</h2>
      <p class="text-xs mt-0.5" style="color:var(--txs);">正在斡旋的物件，個人私用，跨裝置同步</p>
    </div>
    <button class="btn-primary" onclick="warOpenNew()">＋ 加入戰況</button>
  </div>
  <div id="war-list" class="space-y-3">
    <p class="text-center py-12" style="color:var(--txs);">載入中…</p>
  </div>
</div>

<!-- ══ 帶看紀錄 ══ -->
<div id="pane-showings" style="display:none" class="max-w-4xl mx-auto px-4 py-6">
  <div class="flex items-center justify-between mb-4">
    <h2 class="font-bold text-lg" style="color:var(--tx);">🗓 帶看紀錄</h2>
    <button class="btn-primary" onclick="showingOpenNew()">＋ 新增帶看</button>
  </div>
  <!-- 篩選 -->
  <div class="flex gap-2 mb-4">
    <select id="showing-buyer-filter" onchange="showingLoad()" class="flex-1">
      <option value="">全部買方</option>
    </select>
  </div>
  <div id="showing-list" class="space-y-3">
    <p class="text-center py-12" style="color:var(--txs);">載入中…</p>
  </div>
</div>

<!-- ════════ 買方 Modal ════════ -->
<div id="buyer-modal" class="modal-bg hidden" onclick="if(event.target===this)buyerCloseModal()">
  <div class="modal-box p-6" onclick="event.stopPropagation()">
    <div class="flex items-center justify-between mb-5">
      <h3 id="buyer-modal-title" class="font-bold text-base" style="color:var(--tx);">新增買方</h3>
      <button onclick="buyerCloseModal()" class="text-xl leading-none" style="color:var(--txs);">×</button>
    </div>
    <div class="grid grid-cols-2 gap-3 mb-3">
      <div>
        <label>姓名 *</label>
        <input id="bm-name" type="text" placeholder="買方姓名">
      </div>
      <div>
        <label>電話</label>
        <input id="bm-phone" type="text" placeholder="0912-345-678">
      </div>
    </div>
    <div class="grid grid-cols-2 gap-3 mb-3">
      <div>
        <label>預算下限（萬）</label>
        <input id="bm-budget-min" type="number" placeholder="0">
      </div>
      <div>
        <label>預算上限（萬）</label>
        <input id="bm-budget-max" type="number" placeholder="500">
      </div>
    </div>
    <div class="mb-3">
      <label>地區需求</label>
      <input id="bm-area" type="text" placeholder="如：台東市、知本、關山">
    </div>
    <div class="mb-3">
      <label>物件類型（可複選，逗號分隔）</label>
      <input id="bm-types" type="text" placeholder="如：農地、建地、店住">
    </div>
    <div class="grid grid-cols-2 gap-3 mb-3">
      <div>
        <label>坪數下限</label>
        <input id="bm-size-min" type="number" placeholder="0">
      </div>
      <div>
        <label>坪數上限</label>
        <input id="bm-size-max" type="number" placeholder="100">
      </div>
    </div>
    <div class="mb-3">
      <label>狀態</label>
      <select id="bm-status">
        <option value="洽談中">洽談中</option>
        <option value="成交">成交</option>
        <option value="流失">流失</option>
      </select>
    </div>
    <div class="mb-5">
      <label>備註</label>
      <textarea id="bm-note" rows="3" placeholder="需求說明、特殊條件…"></textarea>
    </div>
    <input type="hidden" id="bm-id">
    <div class="flex gap-3">
      <button class="btn-primary flex-1" onclick="buyerSave()">儲存</button>
      <button class="btn-ghost" onclick="buyerCloseModal()">取消</button>
    </div>
  </div>
</div>

<!-- ════════ 戰況 Modal ════════ -->
<div id="war-modal" class="modal-bg hidden" onclick="if(event.target===this)warCloseModal()">
  <div class="modal-box overflow-y-auto" style="max-height:92vh;padding:1.5rem" onclick="event.stopPropagation()">
    <div class="flex items-center justify-between mb-4">
      <h3 id="war-modal-title" class="font-bold text-base" style="color:var(--tx);">新增戰況</h3>
      <button onclick="warCloseModal()" class="text-xl leading-none" style="color:var(--txs);">×</button>
    </div>
    <div class="mb-4">
      <label>斡旋書編號</label>
      <input id="wm-war-no" type="text" placeholder="如：114-001">
    </div>

    <!-- ── 區塊：物件資訊 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2 mt-1" style="color:var(--txs);">🏠 物件資訊</p>
    <div class="grid grid-cols-1 gap-3 mb-4">
      <div>
        <label>物件名稱 *</label>
        <input id="wm-prop-name" type="text" placeholder="如：鎮樂海景農地">
      </div>
      <div>
        <label>物件地址</label>
        <input id="wm-prop-address" type="text" placeholder="">
      </div>
      <div class="grid grid-cols-3 gap-2">
        <div><label>公告售價（萬）</label><input id="wm-prop-price" type="number" step="0.01" placeholder=""></div>
        <div><label>我方出價（萬）</label><input id="wm-my-offer" type="number" step="0.01" placeholder=""></div>
        <div><label>屋主底價（萬，私密）</label><input id="wm-floor-price" type="number" step="0.01" placeholder=""></div>
      </div>
    </div>

    <!-- ── 區塊：斡旋期間 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2" style="color:var(--txs);">📅 斡旋期間</p>
    <div class="grid grid-cols-2 gap-3 mb-3">
      <div><label>審閱日</label><input id="wm-review-date" type="date"></div>
      <div><label>斡旋日期</label><input id="wm-war-date" type="date"></div>
      <div><label>到期日</label><input id="wm-expire-date" type="date"></div>
    </div>
    <!-- 契約變更 -->
    <div class="rounded-lg px-3 py-2 mb-4" style="background:var(--bg-t);">
      <p class="text-xs mb-2" style="color:var(--txs);">📄 契約變更（契變）</p>
      <div class="grid grid-cols-1 gap-2">
        <div><label>契變編號</label><input id="wm-contract-change-no" type="text" placeholder="如：契變一"></div>
        <div class="grid grid-cols-2 gap-2">
          <div><label>變更後到期日</label><input id="wm-contract-change-expire" type="date"></div>
          <div><label>變更後金額（萬）</label><input id="wm-contract-change-amount" type="number" step="0.01" placeholder=""></div>
        </div>
      </div>
    </div>

    <!-- ── 區塊：斡旋金 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2" style="color:var(--txs);">💰 斡旋金</p>
    <div class="grid grid-cols-2 gap-3 mb-4">
      <div>
        <label>斡旋金金額（萬）</label>
        <input id="wm-deposit-amount" type="number" step="0.01" placeholder="">
      </div>
      <div>
        <label>支付方式</label>
        <select id="wm-deposit-type">
          <option value="">請選擇</option>
          <option value="現金">現金</option>
          <option value="匯款">匯款</option>
          <option value="票據">票據</option>
        </select>
      </div>
    </div>

    <!-- ── 區塊：承購總價款與付款方式 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2" style="color:var(--txs);">🧾 承購總價款與付款方式</p>
    <div class="mb-3">
      <label>承購總價款（萬）</label>
      <input id="wm-purchase-price" type="number" step="0.01" placeholder="" oninput="warCalcPayment()">
    </div>
    <div class="grid grid-cols-1 gap-2 mb-4">
      <!-- 簽約款 -->
      <div class="rounded-lg px-3 py-2" style="background:var(--bg-t);">
        <p class="text-xs mb-1.5" style="color:var(--txs);">簽約款</p>
        <div class="grid grid-cols-2 gap-2">
          <div><label>金額（萬）</label><input id="wm-sign-amount" type="number" step="0.01" placeholder="" oninput="warSyncRatio('sign')"></div>
          <div><label>比例（%）</label><input id="wm-sign-ratio" type="number" step="0.1" placeholder="" oninput="warSyncAmount('sign')"></div>
        </div>
      </div>
      <!-- 完稅款 -->
      <div class="rounded-lg px-3 py-2" style="background:var(--bg-t);">
        <p class="text-xs mb-1.5" style="color:var(--txs);">完稅款</p>
        <div class="grid grid-cols-2 gap-2">
          <div><label>金額（萬）</label><input id="wm-tax-amount" type="number" step="0.01" placeholder="" oninput="warSyncRatio('tax')"></div>
          <div><label>比例（%）</label><input id="wm-tax-ratio" type="number" step="0.1" placeholder="" oninput="warSyncAmount('tax')"></div>
        </div>
      </div>
      <!-- 交屋款（含貸款） -->
      <div class="rounded-lg px-3 py-2" style="background:var(--bg-t);">
        <p class="text-xs mb-1.5" style="color:var(--txs);">交屋款（含貸款）</p>
        <div class="grid grid-cols-2 gap-2">
          <div><label>金額（萬）</label><input id="wm-handover-amount" type="number" step="0.01" placeholder="" oninput="warSyncRatio('handover')"></div>
          <div><label>比例（%）</label><input id="wm-handover-ratio" type="number" step="0.1" placeholder="" oninput="warSyncAmount('handover')"></div>
        </div>
        <div class="mt-2"><label>其中貸款金額（萬）</label><input id="wm-loan-amount" type="number" step="0.01" placeholder=""></div>
      </div>
    </div>

    <!-- ── 區塊：服務報酬 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2" style="color:var(--txs);">📋 服務報酬（買方）</p>
    <div class="grid grid-cols-2 gap-3 mb-4">
      <div>
        <label>服務費比例（%）</label>
        <input id="wm-service-fee-ratio" type="number" step="0.01" placeholder="預設 2%" oninput="warSyncAmount('fee')">
      </div>
      <div>
        <label>服務費金額（萬）</label>
        <input id="wm-service-fee-amount" type="number" step="0.01" placeholder="" oninput="warSyncRatio('fee')">
      </div>
    </div>

    <!-- ── 區塊：買方個人資料 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2" style="color:var(--txs);">👤 買方個人資料</p>
    <div class="grid grid-cols-1 gap-3 mb-4">
      <div class="grid grid-cols-2 gap-2">
        <div><label>買方姓名</label><input id="wm-buyer-name" type="text" placeholder=""></div>
        <div><label>電話</label><input id="wm-buyer-phone" type="tel" placeholder=""></div>
      </div>
      <div class="grid grid-cols-2 gap-2">
        <div><label>身分證字號</label><input id="wm-buyer-id-no" type="text" placeholder=""></div>
        <div><label>出生年月日</label><input id="wm-buyer-birthday" type="date"></div>
      </div>
      <div><label>戶籍地址</label><input id="wm-buyer-address" type="text" placeholder=""></div>
    </div>

    <!-- ── 區塊：狀態與備註 ── -->
    <p class="text-xs font-semibold uppercase tracking-wide mb-2" style="color:var(--txs);">📝 狀態與備註</p>
    <div class="mb-3">
      <label>狀態</label>
      <select id="wm-status">
        <option value="斡旋中">斡旋中</option>
        <option value="談判中">談判中</option>
        <option value="放棄">放棄</option>
        <option value="成交">成交</option>
      </select>
    </div>
    <div class="mb-5">
      <label>備註</label>
      <textarea id="wm-note" rows="3" placeholder="目前進度、策略…"></textarea>
    </div>

    <input type="hidden" id="wm-id">
    <input type="hidden" id="wm-prop-id">
    <div class="flex gap-3">
      <button class="btn-primary flex-1" onclick="warSave()">儲存</button>
      <button class="btn-ghost" onclick="warCloseModal()">取消</button>
    </div>
  </div>
</div>

<!-- ════════ 帶看 Modal ════════ -->
<div id="showing-modal" class="modal-bg hidden" style="z-index:200" onclick="if(event.target===this)showingCloseModal()">
  <div class="modal-box p-6" onclick="event.stopPropagation()">
    <div class="flex items-center justify-between mb-5">
      <h3 id="showing-modal-title" class="font-bold text-base" style="color:var(--tx);">新增帶看紀錄</h3>
      <button onclick="showingCloseModal()" class="text-xl leading-none" style="color:var(--txs);">×</button>
    </div>
    <div class="mb-3">
      <label>買方 *</label>
      <!-- 從買方卡片開啟時顯示固定買方名稱，否則顯示下拉 -->
      <div id="sm-buyer-locked" class="hidden rounded-lg px-3 py-2 text-sm font-medium" style="background:var(--bg-t);border:1px solid var(--ac);color:var(--ac);"></div>
      <select id="sm-buyer-id" class="">
        <option value="">請選擇買方</option>
      </select>
    </div>
    <div class="mb-3" style="position:relative">
      <label>物件名稱 *</label>
      <input id="sm-prop-name" type="text" placeholder="輸入關鍵字搜尋公司物件…" autocomplete="off"
        oninput="propSuggest(this.value)">
      <!-- 候選清單 -->
      <div id="sm-prop-suggest" class="hidden absolute left-0 right-0 rounded-xl shadow-2xl overflow-hidden" style="background:var(--bg-s);border:1px solid var(--bd);top:calc(100% + 4px);z-index:300;max-height:220px;overflow-y:auto"></div>
    </div>
    <div class="mb-3">
      <label>物件地址／地號</label>
      <!-- 顯示用欄位（土地顯示地號，一般物件顯示地址） -->
      <input id="sm-prop-loc" type="text" placeholder="選取物件後自動帶入">
      <!-- 隱藏：存原始地址供後端 -->
      <input id="sm-prop-address" type="hidden">
    </div>
    <div class="mb-3">
      <label>帶看日期</label>
      <input id="sm-date" type="date">
    </div>
    <div class="mb-3">
      <label>買方反應</label>
      <select id="sm-reaction">
        <option value="有興趣">有興趣</option>
        <option value="普通">普通</option>
        <option value="不喜歡">不喜歡</option>
      </select>
    </div>
    <div class="mb-5">
      <label>備註</label>
      <textarea id="sm-note" rows="3" placeholder="帶看過程、買方意見…"></textarea>
    </div>
    <input type="hidden" id="sm-id">
    <input type="hidden" id="sm-prop-id">
    <div class="flex gap-3">
      <button class="btn-primary flex-1" onclick="showingSave()">儲存</button>
      <button class="btn-ghost" onclick="showingCloseModal()">取消</button>
    </div>
  </div>
</div>

<!-- ════════ 編輯帶看紀錄 Modal ════════ -->
<div id="showing-edit-modal" class="modal-bg hidden" style="z-index:210" onclick="if(event.target===this)showingEditClose()">
  <div class="modal-box p-6" onclick="event.stopPropagation()">
    <div class="flex items-center justify-between mb-5">
      <h3 class="font-bold text-base" style="color:var(--tx);">✏️ 編輯帶看紀錄</h3>
      <button onclick="showingEditClose()" class="text-xl leading-none" style="color:var(--txs);">×</button>
    </div>
    <div class="mb-3">
      <label>帶看日期</label>
      <input id="se-date" type="date">
    </div>
    <div class="mb-3">
      <label>買方反應</label>
      <select id="se-reaction">
        <option value="有興趣">👍 有興趣</option>
        <option value="普通">😐 普通</option>
        <option value="不喜歡">👎 不喜歡</option>
      </select>
    </div>
    <div class="mb-5">
      <label>備註</label>
      <textarea id="se-note" rows="4" placeholder="帶看過程、買方意見、出價意願…"></textarea>
    </div>
    <input type="hidden" id="se-id">
    <input type="hidden" id="se-from-detail">
    <input type="hidden" id="se-buyer-id">
    <div class="flex gap-3">
      <button class="btn-primary flex-1" onclick="showingEditSave()">儲存</button>
      <button class="btn-ghost" onclick="showingEditClose()">取消</button>
    </div>
  </div>
</div>

<!-- ════════ 買方詳情 Modal ════════ -->
<div id="buyer-detail-modal" class="modal-bg hidden" onclick="if(event.target===this)buyerDetailClose()">
  <div class="modal-box p-0" onclick="event.stopPropagation()">
    <div id="buyer-detail-content"></div>
  </div>
</div>

<script>
const isAdmin = __IS_ADMIN__;
const LIBRARY_URL = __LIBRARY_URL__;

// ── 工具函數 ──
function esc(s) {
  if (s == null) return '';
  var d = document.createElement('div'); d.textContent = s; return d.innerHTML.replace(/'/g, '&#39;');
}
function toast(msg, type) {
  type = type || 'info';
  var c = document.getElementById('toast-container');
  var el = document.createElement('div');
  el.className = 'toast-item toast-' + type;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(function() { el.classList.add('toast-out'); setTimeout(function(){ el.remove(); }, 300); }, 2800);
}
function fmtBudget(min, max) {
  if (!min && !max) return '不限';
  if (!min) return '上限 ' + max + '萬';
  if (!max) return min + '萬 以上';
  return min + '～' + max + ' 萬';
}
function fmtSize(min, max) {
  if (!min && !max) return '';
  if (!min) return '上限 ' + max + '坪';
  if (!max) return min + '坪 以上';
  return min + '～' + max + ' 坪';
}
function statusBadge(s) {
  var map = {'洽談中':'badge-blue','成交':'badge-green','流失':'badge-gray'};
  return '<span class="badge ' + (map[s]||'badge-gray') + '">' + esc(s) + '</span>';
}
function warStatusBadge(s) {
  var map = {'斡旋中':'badge-amber','談判中':'badge-blue','成交':'badge-green','放棄':'badge-gray'};
  return '<span class="badge ' + (map[s]||'badge-gray') + '">' + esc(s) + '</span>';
}
function reactionIcon(r) {
  var map = {'有興趣':'👍','普通':'😐','不喜歡':'👎'};
  return map[r] || '';
}

// ══════════════════════════════════════════
//  未儲存變更防護（dirty flag 系統）
// ══════════════════════════════════════════
var _dirtyModal = null;   // 目前哪個 modal 有未儲存變更（'buyer'/'war'/'showing' 或 null）

// 在指定 modal 的所有輸入欄位監聽 input/change，標記為 dirty
function _watchDirty(modalId, name) {
  var modal = document.getElementById(modalId);
  if (!modal) return;
  modal.querySelectorAll('input,select,textarea').forEach(function(el) {
    el.addEventListener('input',  function() { _dirtyModal = name; });
    el.addEventListener('change', function() { _dirtyModal = name; });
  });
}

// 嘗試關閉 modal，若有未儲存變更則詢問
function _safeClose(name, closeFn) {
  if (_dirtyModal === name) {
    if (!confirm('有未儲存的變更，確定要放棄並關閉嗎？')) return;
    _dirtyModal = null;
  }
  closeFn();
}

// 儲存成功後清除 dirty
function _clearDirty() { _dirtyModal = null; }

// ── 分頁切換 ──
function switchTab(tab) {
  ['buyers','war','showings'].forEach(function(t) {
    var p = document.getElementById('pane-' + t);
    var b = document.getElementById('tab-' + t);
    if (p) p.style.display = (t === tab) ? 'block' : 'none';
    if (b) {
      b.classList.toggle('active', t === tab);
      b.style.color = (t === tab) ? 'var(--ac)' : 'var(--txs)';
      b.style.borderBottom = (t === tab) ? '2px solid var(--ac)' : '2px solid transparent';
    }
  });
  if (tab === 'buyers')   buyerLoad();
  if (tab === 'war')      warLoad();
  // 切到帶看 tab 時，先確保斡旋 Map 是最新的，再載入帶看列表
  if (tab === 'showings') {
    showingLoadBuyerFilter();
    // 若斡旋 Map 是空的（第一次進帶看 tab），先拉一次斡旋資料
    if (Object.keys(_warByShowingId).length === 0) {
      fetch('/api/war').then(r => r.json()).then(function(d) {
        var wars = d.items || [];
        _warBuyerIds = new Set(); _warByShowingId = {}; _warByBuyerId = {};
        wars.filter(_isActiveWar).forEach(function(w) {
          if (w.buyer_id)   { _warBuyerIds.add(w.buyer_id); _warByBuyerId[w.buyer_id] = w; }
          if (w.showing_id) { _warByShowingId[w.showing_id] = w; }
        });
        showingLoad();
      }).catch(function() { showingLoad(); });
    } else {
      showingLoad();
    }
  }
}

// ═══════════════════════════
//  買方列表
// ═══════════════════════════
var _buyers = [];
var _warBuyerIds    = new Set();  // 有進行中斡旋的 buyer_id 集合
var _warByShowingId = {};         // showing_id → war 物件（進行中才放）
var _warByBuyerId   = {};         // buyer_id   → war 物件（進行中才放，同買方可能多筆取最新）
var _showingCountByBuyer = {};    // buyer_id → 帶看次數（buyerLoad 時由 /api/showings 統計）

function _isActiveWar(w) {
  return w.status !== '放棄' && w.status !== '成交';
}

function buyerLoad() {
  // 同時拉買方清單、戰況版、帶看紀錄（統計帶看次數）
  Promise.all([
    fetch('/api/buyers').then(r => r.json()),
    fetch('/api/war').then(r => r.json()).catch(() => ({items:[]})),
    fetch('/api/showings').then(r => r.json()).catch(() => ({items:[]})),
  ]).then(function(results) {
    _buyers = results[0].items || [];
    var wars     = results[1].items || [];
    var showings = results[2].items || [];
    // 統計每位買方的帶看次數
    _showingCountByBuyer = {};
    showings.forEach(function(s) {
      if (s.buyer_id) _showingCountByBuyer[s.buyer_id] = (_showingCountByBuyer[s.buyer_id] || 0) + 1;
    });
    // 建立各種快查 Map（只限進行中斡旋）
    _warBuyerIds    = new Set();
    _warByShowingId = {};
    _warByBuyerId   = {};
    wars.filter(_isActiveWar).forEach(function(w) {
      if (w.buyer_id)  { _warBuyerIds.add(w.buyer_id); _warByBuyerId[w.buyer_id] = w; }
      if (w.showing_id){ _warByShowingId[w.showing_id] = w; }
    });
    buyerFilter();
  }).catch(e => toast('載入買方失敗', 'error'));
}

function buyerFilter() {
  var kw   = (document.getElementById('buyer-search').value || '').trim().toLowerCase();
  var st   = (document.getElementById('buyer-status-filter').value || '');
  var sort = (document.getElementById('buyer-sort').value || 'war_first');
  var items = _buyers.filter(function(b) {
    if (st && b.status !== st) return false;
    if (!kw) return true;
    return (b.name||'').toLowerCase().includes(kw)
        || (b.area||'').toLowerCase().includes(kw)
        || ((b.types||[]).join('').toLowerCase()).includes(kw)
        || (b.note||'').toLowerCase().includes(kw);
  });
  // ── 排序 ──
  items.sort(function(a, b) {
    switch (sort) {
      case 'war_first':
        // 斡旋中優先，次排更新日新→舊
        var wa = _warBuyerIds.has(a.id) ? 1 : 0;
        var wb = _warBuyerIds.has(b.id) ? 1 : 0;
        if (wb !== wa) return wb - wa;
        return (b.updated_at || '') > (a.updated_at || '') ? 1 : -1;
      case 'updated_desc':
        return (b.updated_at || '') > (a.updated_at || '') ? 1 : -1;
      case 'updated_asc':
        return (a.updated_at || '') > (b.updated_at || '') ? 1 : -1;
      case 'created_desc':
        return (b.created_at || '') > (a.created_at || '') ? 1 : -1;
      case 'created_asc':
        return (a.created_at || '') > (b.created_at || '') ? 1 : -1;
      case 'showing_desc':
        var sa = _showingCountByBuyer[a.id] || 0;
        var sb = _showingCountByBuyer[b.id] || 0;
        if (sb !== sa) return sb - sa;
        return (b.updated_at || '') > (a.updated_at || '') ? 1 : -1;
      case 'name_asc':
        return (a.name || '').localeCompare(b.name || '', 'zh-TW');
      default:
        return 0;
    }
  });
  var list = document.getElementById('buyer-list');
  if (!items.length) {
    list.innerHTML = '<p class="text-center py-12" style="color:var(--txs);">沒有符合的買方</p>';
    return;
  }
  list.innerHTML = items.map(function(b) {
    var types = (b.types||[]).join('、') || (b.types_str||'');
    var isInWar = _warBuyerIds.has(b.id);
    var warObj  = _warByBuyerId[b.id];
    // 斡旋中：卡片左側加橙色邊條、右上角顯示可點擊按鈕
    var cardBorder = isInWar
      ? 'card hover:border-amber-500 transition cursor-pointer border-l-4 border-l-amber-400'
      : 'card hover:border-slate-500 transition cursor-pointer';
    // 點擊「⚔️ 斡旋中」按鈕直接開啟斡旋編輯 Modal
    var warBadge = isInWar && warObj
      ? '<button style="background:#b45309;color:#fef3c7;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.5px;border:none;cursor:pointer;" onclick="event.stopPropagation();warOpenEdit(\'' + warObj.id + '\')">⚔️ 斡旋中</button>'
      : '';
    return '<div class="' + cardBorder + '" onclick="buyerDetail(\'' + b.id + '\')">'
      + '<div class="flex items-start justify-between">'
      + '<div class="flex-1 min-w-0">'
      + '<div class="flex items-center gap-2 flex-wrap mb-1">'
      + '<span class="font-semibold text-base" style="color:var(--tx);">' + esc(b.name) + '</span>'
      + warBadge
      + statusBadge(b.status)
      + (b.phone ? '<span class="text-xs" style="color:var(--txs);">' + esc(b.phone) + '</span>' : '')
      + '</div>'
      + '<div class="text-sm mb-1" style="color:var(--txs);">💰 ' + fmtBudget(b.budget_min, b.budget_max)
      + (b.area ? '　📍 ' + esc(b.area) : '')
      + (types   ? '　🏷 ' + esc(types) : '')
      + (fmtSize(b.size_min, b.size_max) ? '　📐 ' + fmtSize(b.size_min, b.size_max) : '')
      + '</div>'
      + (b.note ? '<p class="text-xs line-clamp-2" style="color:var(--txs);">' + esc(b.note) + '</p>' : '')
      + (function() {
          // 底部小資訊列：帶看次數 + 更新日期
          var cnt = _showingCountByBuyer[b.id] || 0;
          var upd = (b.updated_at || '').slice(0, 10);
          var parts = [];
          if (cnt > 0) parts.push('👥 帶看 ' + cnt + ' 次');
          if (upd)     parts.push('更新 ' + upd);
          return parts.length ? '<p class="text-xs mt-1" style="color:var(--txm);">' + parts.join('　') + '</p>' : '';
        })()
      + '</div>'
      + '<div class="flex flex-col gap-1 ml-3 flex-shrink-0">'
      + '<button class="btn-ghost text-xs py-1" onclick="event.stopPropagation();buyerOpenEdit(\'' + b.id + '\')">編輯</button>'
      + '<button class="text-xs py-1 px-2 rounded border transition" style="color:var(--dg);border-color:var(--bd);" onclick="event.stopPropagation();buyerDelete(\'' + b.id + '\',\'' + esc(b.name) + '\')">刪除</button>'
      + '</div></div></div>';
  }).join('');
}

function buyerOpenNew() {
  _clearDirty();
  document.getElementById('buyer-modal-title').textContent = '新增買方';
  ['name','phone','area','types','note'].forEach(function(k) {
    document.getElementById('bm-'+k).value = '';
  });
  ['budget-min','budget-max','size-min','size-max'].forEach(function(k) {
    document.getElementById('bm-'+k).value = '';
  });
  document.getElementById('bm-status').value = '洽談中';
  document.getElementById('bm-id').value = '';
  document.getElementById('buyer-modal').classList.remove('hidden');
}

function buyerOpenEdit(id) {
  _clearDirty();
  var b = _buyers.find(function(x){ return x.id === id; });
  if (!b) return;
  document.getElementById('buyer-modal-title').textContent = '編輯買方';
  document.getElementById('bm-name').value  = b.name || '';
  document.getElementById('bm-phone').value = b.phone || '';
  document.getElementById('bm-area').value  = b.area || '';
  document.getElementById('bm-types').value = (b.types||[]).join('、');
  document.getElementById('bm-note').value  = b.note || '';
  document.getElementById('bm-budget-min').value = b.budget_min || '';
  document.getElementById('bm-budget-max').value = b.budget_max || '';
  document.getElementById('bm-size-min').value   = b.size_min || '';
  document.getElementById('bm-size-max').value   = b.size_max || '';
  document.getElementById('bm-status').value = b.status || '洽談中';
  document.getElementById('bm-id').value = b.id;
  document.getElementById('buyer-modal').classList.remove('hidden');
}

function buyerCloseModal() {
  _safeClose('buyer', function() {
    document.getElementById('buyer-modal').classList.add('hidden');
  });
}

function buyerSave() {
  var id   = document.getElementById('bm-id').value.trim();
  var name = document.getElementById('bm-name').value.trim();
  if (!name) { toast('請填寫買方姓名', 'error'); return; }
  var typesRaw = document.getElementById('bm-types').value;
  var types = typesRaw.split(/[、,，\s]+/).map(s => s.trim()).filter(Boolean);
  var body = {
    name:       name,
    phone:      document.getElementById('bm-phone').value.trim(),
    budget_min: parseFloat(document.getElementById('bm-budget-min').value) || null,
    budget_max: parseFloat(document.getElementById('bm-budget-max').value) || null,
    area:       document.getElementById('bm-area').value.trim(),
    types:      types,
    size_min:   parseFloat(document.getElementById('bm-size-min').value) || null,
    size_max:   parseFloat(document.getElementById('bm-size-max').value) || null,
    note:       document.getElementById('bm-note').value.trim(),
    status:     document.getElementById('bm-status').value,
  };
  var url    = id ? '/api/buyers/' + id : '/api/buyers';
  var method = id ? 'PUT' : 'POST';
  fetch(url, {method: method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json()).then(d => {
      if (d.error) { toast(d.error, 'error'); return; }
      _clearDirty();
      toast(id ? '已更新' : '已新增', 'success');
      buyerCloseModal();
      buyerLoad();
    }).catch(e => toast('儲存失敗', 'error'));
}

function buyerDelete(id, name) {
  if (!confirm('確定刪除「' + name + '」？帶看紀錄也會一併刪除。')) return;
  fetch('/api/buyers/' + id, {method:'DELETE'})
    .then(r => r.json()).then(d => {
      if (d.error) { toast(d.error, 'error'); return; }
      toast('已刪除', 'success');
      buyerLoad();
    });
}

// ── 買方詳情（含帶看紀錄） ──
function buyerDetail(id) {
  var b = _buyers.find(function(x){ return x.id === id; });
  if (!b) return;
  var modal = document.getElementById('buyer-detail-modal');
  var content = document.getElementById('buyer-detail-content');
  content.innerHTML = '<div class="p-6"><p class="text-center py-8" style="color:var(--txs);">載入帶看紀錄…</p></div>';
  modal.classList.remove('hidden');

  fetch('/api/showings?buyer_id=' + id).then(r => r.json()).then(d => {
    var showings = d.items || [];
    var types = (b.types||[]).join('、');
    var html = '<div class="p-6">'
      + '<div class="flex items-start justify-between mb-4">'
      + '<div>'
      + '<div class="flex items-center gap-2 mb-1"><span class="text-lg font-bold" style="color:var(--tx);">' + esc(b.name) + '</span>' + statusBadge(b.status) + '</div>'
      + (b.phone ? '<p class="text-sm" style="color:var(--txs);">📞 ' + esc(b.phone) + '</p>' : '')
      + '</div>'
      + '<button onclick="buyerDetailClose()" class="text-xl leading-none" style="color:var(--txs);">×</button>'
      + '</div>'
      + '<div class="grid grid-cols-2 gap-2 text-sm mb-4">'
      + '<div class="rounded-lg p-3" style="background:var(--bg-t);"><span style="color:var(--txs);">預算</span><br><span class="font-medium" style="color:var(--tx);">' + fmtBudget(b.budget_min, b.budget_max) + '</span></div>'
      + '<div class="rounded-lg p-3" style="background:var(--bg-t);"><span style="color:var(--txs);">坪數</span><br><span class="font-medium" style="color:var(--tx);">' + (fmtSize(b.size_min, b.size_max)||'不限') + '</span></div>'
      + '<div class="rounded-lg p-3" style="background:var(--bg-t);"><span style="color:var(--txs);">地區</span><br><span class="font-medium" style="color:var(--tx);">' + (esc(b.area)||'不限') + '</span></div>'
      + '<div class="rounded-lg p-3" style="background:var(--bg-t);"><span style="color:var(--txs);">類型</span><br><span class="font-medium" style="color:var(--tx);">' + (esc(types)||'不限') + '</span></div>'
      + '</div>'
      + (b.note ? '<div class="rounded-lg p-3 text-sm mb-4" style="background:var(--bg-t);color:var(--txs);">' + esc(b.note) + '</div>' : '')
      + '<div class="flex items-center justify-between mb-3">'
      + '<h4 class="font-semibold text-sm" style="color:var(--tx);">🗓 帶看紀錄（' + showings.length + ' 筆）</h4>'
      + '<button class="btn-primary text-xs py-1 px-3" onclick="showingOpenNewForBuyer(\'' + b.id + '\',\'' + esc(b.name) + '\')">＋ 新增帶看</button>'
      + '</div>';
    if (!showings.length) {
      html += '<p class="text-sm text-center py-4" style="color:var(--txm);">尚無帶看紀錄</p>';
    } else {
      html += '<div class="space-y-2">';
      showings.forEach(function(s) {
        var libLink = (LIBRARY_URL && s.prop_name)
          ? '<a href="' + LIBRARY_URL + '?prop_name=' + encodeURIComponent(s.prop_name) + '" target="_blank" class="text-blue-400 hover:text-blue-300 text-xs underline ml-1">查看物件↗</a>'
          : '';
        // 判斷此帶看是否有進行中的斡旋
        var linkedWar = _warByShowingId[s.id];
        var warBtn = linkedWar
          ? '<button class="text-xs font-bold px-2 py-1 rounded border transition" '
            + 'style="color:#fef3c7;border-color:#b45309;background:#92400e;" '
            + 'title="點擊編輯斡旋" '
            + 'onclick="warOpenEdit(\'' + linkedWar.id + '\')">⚔️ 斡旋中</button>'
          : '<button class="text-xs text-amber-400 hover:text-amber-300 px-2 py-1 rounded border border-slate-600 hover:border-amber-500 transition" '
            + 'title="升級為斡旋戰況" '
            + 'onclick="showingToWar(\'' + s.id + '\',\'' + esc(s.prop_name) + '\',\'' + esc(s.prop_address||'') + '\',\'' + esc(s.prop_id||'') + '\',\'' + esc(b.name) + '\',\'' + id + '\',\'' + id + '\')">⚔️ 斡旋</button>';
        var cardStyle = linkedWar
          ? 'border-radius:12px;padding:12px 16px;border-left:4px solid var(--warn);background:var(--bg-t);'
          : 'border-radius:12px;padding:12px 16px;background:var(--bg-t);';
        html += '<div style="' + cardStyle + '">'
          + '<div class="flex items-start justify-between gap-2">'
          + '<div class="flex-1 min-w-0">'
          + '<div class="text-sm font-medium" style="color:var(--tx);">' + reactionIcon(s.reaction) + ' ' + esc(s.prop_name) + libLink + '</div>'
          + '<div class="text-xs mt-0.5" style="color:var(--txs);">' + esc(s.date) + (s.prop_address ? '　' + esc(s.prop_address) : '') + '</div>'
          + (s.note ? '<p class="text-xs mt-1" style="color:var(--txs);">' + esc(s.note) + '</p>' : '')
          + '</div>'
          + '<div class="flex gap-1.5 flex-shrink-0 ml-2">'
          + '<button class="text-xs px-2 py-1 rounded border transition" style="color:var(--ac);border-color:var(--bd);" '
          +   'onclick="showingEditOpen(\'' + s.id + '\',\'' + esc(s.date) + '\',\'' + esc(s.reaction) + '\')" data-note="' + esc(s.note||'') + '" data-from-detail="1" data-buyer-id="' + esc(id) + '">編輯</button>'
          + warBtn
          + '<button class="text-xs px-2 py-1 rounded border transition" style="color:var(--dg);border-color:var(--bd);" '
          +   'onclick="showingDelete(\'' + s.id + '\',true,\'' + id + '\')">刪除</button>'
          + '</div></div></div>';
      });
      html += '</div>';
    }
    html += '</div>';
    content.innerHTML = html;
  });
}

function buyerDetailClose() {
  document.getElementById('buyer-detail-modal').classList.add('hidden');
}

// ═══════════════════════════
//  戰況版
// ═══════════════════════════
var _wars = [];

function warLoad() {
  fetch('/api/war').then(r => r.json()).then(d => {
    _wars = d.items || [];
    warRender();
  }).catch(e => toast('載入戰況失敗', 'error'));
}

function warRender() {
  var list = document.getElementById('war-list');
  if (!_wars.length) {
    list.innerHTML = '<div class="text-center py-16" style="color:var(--txs);"><div class="text-5xl mb-3">🕊️</div><p class="text-lg" style="color:var(--txs);">目前沒有斡旋物件</p></div>';
    return;
  }
  list.innerHTML = _wars.map(function(w) {
    // 物件庫連結：跳到物件庫並帶案名，讓物件庫直接搜尋定位
    var libLink = (LIBRARY_URL && w.prop_name)
      ? '<a href="' + LIBRARY_URL + '?prop_name=' + encodeURIComponent(w.prop_name) + '" target="_blank" class="text-blue-400 hover:text-blue-300 text-xs underline ml-2">物件庫↗</a>'
      : '';
    // 來源帶看紀錄連結：用 data-sid 傳 showing_id，避免引號問題
    var showingLink = w.showing_id
      ? '<a href="#" class="war-showing-link text-amber-400 hover:text-amber-300 text-xs underline" data-sid="' + esc(w.showing_id) + '">📋 來源帶看紀錄</a>'
      : '';
    return '<div class="card hover:border-slate-500 transition">'
      + '<div class="flex items-start justify-between mb-2">'
      + '<div>'
      + '<div class="flex items-center gap-2 flex-wrap">'
      + '<span class="font-semibold" style="color:var(--tx);">' + esc(w.prop_name) + '</span>'
      + warStatusBadge(w.status) + libLink
      + '</div>'
      + (w.prop_address ? '<p class="text-xs mt-0.5" style="color:var(--txs);">' + esc(w.prop_address) + '</p>' : '')
      + '</div>'
      + '<div class="flex gap-2 flex-shrink-0 ml-2">'
      + '<button class="btn-ghost text-xs py-1" onclick="warOpenEdit(\'' + w.id + '\')">編輯</button>'
      + '<button class="text-xs py-1 px-2 rounded border transition" style="color:var(--dg);border-color:var(--bd);" onclick="warDelete(\'' + w.id + '\',\'' + esc(w.prop_name) + '\')">刪除</button>'
      + '</div></div>'
      + '<div class="grid grid-cols-3 gap-2 text-xs mt-2" style="color:var(--txs);">'
      + '<div class="rounded-lg p-2" style="background:var(--bg-t);"><span class="block" style="color:var(--txm);">公告</span>' + (w.prop_price != null ? w.prop_price + '萬' : '—') + '</div>'
      + '<div class="rounded-lg p-2" style="background:var(--bg-t);"><span class="block" style="color:var(--txm);">承購</span>' + (w.purchase_price != null ? '<span style="color:var(--ac);font-weight:600;">' + w.purchase_price + '萬</span>' : (w.my_offer != null ? '<span style="color:var(--ac);">' + w.my_offer + '萬</span>' : '—')) + '</div>'
      + '<div class="rounded-lg p-2" style="background:var(--bg-t);"><span class="block" style="color:var(--txm);">底價</span>' + (w.floor_price != null ? '<span style="color:var(--warn);font-weight:600;">' + w.floor_price + '萬</span>' : '—') + '</div>'
      + '</div>'
      + (w.war_no ? '<p class="text-xs mt-1" style="color:var(--txm);">編號：' + esc(w.war_no) + '</p>' : '')
      + (w.deposit_amount != null ? '<p class="text-xs mt-1" style="color:var(--txs);">斡旋金：<span style="color:var(--tx);">' + w.deposit_amount + '萬</span>'
          + (w.deposit_type ? '　<span style="color:var(--txm);">' + esc(w.deposit_type) + '</span>' : '')
          + (w.expire_date ? '　到期：<span style="color:var(--txs);">' + esc(w.expire_date) + '</span>' : '')
          + (w.contract_change_expire ? '　<span style="color:var(--warn);">（契變→' + esc(w.contract_change_expire) + '）</span>' : '') + '</p>' : '')
      + (w.buyer_name ? '<p class="text-xs mt-1" style="color:var(--txs);">買方：<span style="color:var(--tx);">' + esc(w.buyer_name) + '</span>'
          + (w.buyer_phone ? '　' + esc(w.buyer_phone) : '') + '</p>' : '')
      + (showingLink ? '<p class="mt-1">' + showingLink + '</p>' : '')
      + (w.note ? '<p class="text-xs mt-1 rounded p-2" style="color:var(--txs);background:var(--bg-t);">' + esc(w.note) + '</p>' : '')
      + '</div>';
  }).join('');

  // 「來源帶看紀錄」連結事件（用事件委派，避免 onclick 引號問題）
  list.querySelectorAll('.war-showing-link').forEach(function(a) {
    a.addEventListener('click', function(e) {
      e.preventDefault();
      var sid = this.dataset.sid;
      switchTab('showings');
      setTimeout(function() {
        var el = document.getElementById('sl-' + sid);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 400);
    });
  });
}

// 清空戰況 Modal 所有欄位
function warClearModal() {
  var ids = [
    'war-no',
    'prop-name','prop-address','prop-price','my-offer','floor-price',
    'review-date','war-date','expire-date',
    'contract-change-no','contract-change-expire','contract-change-amount',
    'deposit-amount','deposit-type',
    'purchase-price','sign-amount','sign-ratio','tax-amount','tax-ratio',
    'handover-amount','handover-ratio','loan-amount',
    'service-fee-ratio','service-fee-amount',
    'buyer-name','buyer-phone','buyer-id-no','buyer-birthday','buyer-address',
    'note'
  ];
  ids.forEach(function(k) {
    var el = document.getElementById('wm-' + k);
    if (el) el.value = '';
  });
  document.getElementById('wm-status').value = '斡旋中';
  // 服務費預設 2%
  document.getElementById('wm-service-fee-ratio').value = 2;
}

function warOpenNew() {
  _clearDirty();
  document.getElementById('war-modal-title').textContent = '新增戰況';
  warClearModal();
  document.getElementById('wm-id').value = '';
  document.getElementById('wm-prop-id').value = '';
  document.getElementById('war-modal').classList.remove('hidden');
}

function warOpenEdit(id) {
  _clearDirty();
  var w = _wars.find(function(x){ return x.id === id; });
  // 若 _wars 尚未載入（例如直接從買方帶看卡片點擊），先拉一次 API 再開啟
  if (!w) {
    fetch('/api/war').then(r => r.json()).then(function(d) {
      _wars = d.items || [];
      var ww = _wars.find(function(x){ return x.id === id; });
      if (ww) warOpenEdit(id);
      else toast('找不到此斡旋紀錄', 'error');
    }).catch(function() { toast('載入斡旋失敗', 'error'); });
    return;
  }
  document.getElementById('war-modal-title').textContent = '編輯戰況';
  warClearModal();
  // 斡旋書編號
  document.getElementById('wm-war-no').value       = w.war_no || '';
  // 物件資訊
  document.getElementById('wm-prop-name').value    = w.prop_name || '';
  document.getElementById('wm-prop-address').value = w.prop_address || '';
  document.getElementById('wm-prop-price').value   = w.prop_price != null ? w.prop_price : '';
  document.getElementById('wm-my-offer').value     = w.my_offer != null ? w.my_offer : '';
  document.getElementById('wm-floor-price').value  = w.floor_price != null ? w.floor_price : '';
  // 斡旋期間
  document.getElementById('wm-review-date').value  = w.review_date || '';
  document.getElementById('wm-war-date').value      = w.war_date || '';
  document.getElementById('wm-expire-date').value   = w.expire_date || '';
  // 契約變更
  document.getElementById('wm-contract-change-no').value     = w.contract_change_no || '';
  document.getElementById('wm-contract-change-expire').value = w.contract_change_expire || '';
  document.getElementById('wm-contract-change-amount').value = w.contract_change_amount != null ? w.contract_change_amount : '';
  // 斡旋金
  document.getElementById('wm-deposit-amount').value = w.deposit_amount != null ? w.deposit_amount : '';
  document.getElementById('wm-deposit-type').value   = w.deposit_type || '';
  // 承購總價款
  document.getElementById('wm-purchase-price').value   = w.purchase_price != null ? w.purchase_price : '';
  document.getElementById('wm-sign-amount').value      = w.sign_amount != null ? w.sign_amount : '';
  document.getElementById('wm-sign-ratio').value       = w.sign_ratio != null ? w.sign_ratio : '';
  document.getElementById('wm-tax-amount').value       = w.tax_amount != null ? w.tax_amount : '';
  document.getElementById('wm-tax-ratio').value        = w.tax_ratio != null ? w.tax_ratio : '';
  document.getElementById('wm-handover-amount').value  = w.handover_amount != null ? w.handover_amount : '';
  document.getElementById('wm-handover-ratio').value   = w.handover_ratio != null ? w.handover_ratio : '';
  document.getElementById('wm-loan-amount').value      = w.loan_amount != null ? w.loan_amount : '';
  // 服務報酬
  document.getElementById('wm-service-fee-ratio').value  = w.service_fee_ratio != null ? w.service_fee_ratio : 2;
  document.getElementById('wm-service-fee-amount').value = w.service_fee_amount != null ? w.service_fee_amount : '';
  // 買方個人資料
  document.getElementById('wm-buyer-name').value     = w.buyer_name || '';
  document.getElementById('wm-buyer-phone').value    = w.buyer_phone || '';
  document.getElementById('wm-buyer-id-no').value    = w.buyer_id_no || '';
  document.getElementById('wm-buyer-birthday').value = w.buyer_birthday || '';
  document.getElementById('wm-buyer-address').value  = w.buyer_address || '';
  // 狀態與備註
  document.getElementById('wm-status').value = w.status || '斡旋中';
  document.getElementById('wm-note').value   = w.note || '';
  // 隱藏欄位
  document.getElementById('wm-id').value     = w.id;
  document.getElementById('wm-prop-id').value = w.prop_id || '';
  document.getElementById('war-modal').classList.remove('hidden');
}

function warCloseModal() {
  _safeClose('war', function() {
    document.getElementById('war-modal').classList.add('hidden');
  });
}

// 承購總價款→各款項金額連動（依比例計算）
function warCalcPayment() {
  var total = parseFloat(document.getElementById('wm-purchase-price').value) || 0;
  if (!total) return;
  ['sign','tax','handover'].forEach(function(k) {
    var ratio = parseFloat(document.getElementById('wm-' + k + '-ratio').value) || 0;
    if (ratio) document.getElementById('wm-' + k + '-amount').value = (total * ratio / 100).toFixed(2);
  });
  var feeRatio = parseFloat(document.getElementById('wm-service-fee-ratio').value) || 0;
  if (feeRatio) document.getElementById('wm-service-fee-amount').value = (total * feeRatio / 100).toFixed(2);
}

// 金額→比例連動
function warSyncRatio(type) {
  var total = parseFloat(document.getElementById('wm-purchase-price').value) || 0;
  if (!total) return;
  var amtId   = type === 'fee' ? 'wm-service-fee-amount' : ('wm-' + type + '-amount');
  var ratioId = type === 'fee' ? 'wm-service-fee-ratio'  : ('wm-' + type + '-ratio');
  var amt = parseFloat(document.getElementById(amtId).value) || 0;
  if (amt) document.getElementById(ratioId).value = (amt / total * 100).toFixed(2);
}

// 比例→金額連動
function warSyncAmount(type) {
  var total = parseFloat(document.getElementById('wm-purchase-price').value) || 0;
  if (!total) return;
  var amtId   = type === 'fee' ? 'wm-service-fee-amount' : ('wm-' + type + '-amount');
  var ratioId = type === 'fee' ? 'wm-service-fee-ratio'  : ('wm-' + type + '-ratio');
  var ratio = parseFloat(document.getElementById(ratioId).value) || 0;
  if (ratio) document.getElementById(amtId).value = (total * ratio / 100).toFixed(2);
}

function warSave() {
  var id = document.getElementById('wm-id').value.trim();
  var propName = document.getElementById('wm-prop-name').value.trim();
  if (!propName) { toast('請填寫物件名稱', 'error'); return; }
  var pf = function(eid) { var v = parseFloat(document.getElementById(eid).value); return isNaN(v) ? null : v; };
  var sv = function(eid) { return document.getElementById(eid).value.trim(); };
  var body = {
    // 斡旋書編號
    war_no:       sv('wm-war-no'),
    // 物件資訊
    prop_name:    propName,
    prop_address: sv('wm-prop-address'),
    prop_price:   pf('wm-prop-price'),
    my_offer:     pf('wm-my-offer'),
    floor_price:  pf('wm-floor-price'),
    prop_id:      sv('wm-prop-id'),
    // 斡旋期間
    review_date:  sv('wm-review-date'),
    war_date:     sv('wm-war-date'),
    expire_date:  sv('wm-expire-date'),
    // 契約變更
    contract_change_no:     sv('wm-contract-change-no'),
    contract_change_expire: sv('wm-contract-change-expire'),
    contract_change_amount: pf('wm-contract-change-amount'),
    // 斡旋金
    deposit_amount: pf('wm-deposit-amount'),
    deposit_type:   sv('wm-deposit-type'),
    // 承購總價款
    purchase_price:   pf('wm-purchase-price'),
    sign_amount:      pf('wm-sign-amount'),
    sign_ratio:       pf('wm-sign-ratio'),
    tax_amount:       pf('wm-tax-amount'),
    tax_ratio:        pf('wm-tax-ratio'),
    handover_amount:  pf('wm-handover-amount'),
    handover_ratio:   pf('wm-handover-ratio'),
    loan_amount:      pf('wm-loan-amount'),
    // 服務報酬
    service_fee_ratio:  pf('wm-service-fee-ratio'),
    service_fee_amount: pf('wm-service-fee-amount'),
    // 買方個人資料
    buyer_name:     sv('wm-buyer-name'),
    buyer_phone:    sv('wm-buyer-phone'),
    buyer_id_no:    sv('wm-buyer-id-no'),
    buyer_birthday: sv('wm-buyer-birthday'),
    buyer_address:  sv('wm-buyer-address'),
    // 狀態與備註
    status: document.getElementById('wm-status').value,
    note:   sv('wm-note'),
  };
  var url    = id ? '/api/war/' + id : '/api/war';
  var method = id ? 'PUT' : 'POST';
  fetch(url, {method: method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json()).then(d => {
      if (d.error) { toast(d.error, 'error'); return; }
      _clearDirty();
      toast(id ? '已更新' : '已新增', 'success');
      warCloseModal();
      warLoad();
    }).catch(e => toast('儲存失敗', 'error'));
}

function warDelete(id, name) {
  if (!confirm('確定刪除「' + name + '」的戰況紀錄？')) return;
  fetch('/api/war/' + id, {method:'DELETE'}).then(r => r.json()).then(d => {
    if (d.error) { toast(d.error, 'error'); return; }
    toast('已刪除', 'success');
    warLoad();
  });
}

// ═══════════════════════════
//  帶看紀錄
// ═══════════════════════════
function showingLoadBuyerFilter() {
  fetch('/api/buyers').then(r => r.json()).then(d => {
    var buyers = d.items || [];
    var sel = document.getElementById('showing-buyer-filter');
    var cur = sel.value;
    sel.innerHTML = '<option value="">全部買方</option>';
    buyers.forEach(function(b) {
      var opt = document.createElement('option');
      opt.value = b.id;
      opt.textContent = b.name;
      if (b.id === cur) opt.selected = true;
      sel.appendChild(opt);
    });
    // 同步更新帶看 Modal 的買方選單
    var sm = document.getElementById('sm-buyer-id');
    sm.innerHTML = '<option value="">請選擇買方</option>';
    buyers.forEach(function(b) {
      var opt = document.createElement('option');
      opt.value = b.id;
      opt.textContent = b.name;
      sm.appendChild(opt);
    });
  });
}

function showingLoad() {
  var buyerId = document.getElementById('showing-buyer-filter').value;
  var url = '/api/showings' + (buyerId ? '?buyer_id=' + buyerId : '');
  fetch(url).then(r => r.json()).then(d => {
    var items = d.items || [];
    var list = document.getElementById('showing-list');
    if (!items.length) {
      list.innerHTML = '<p class="text-center py-12" style="color:var(--txs);">尚無帶看紀錄</p>';
      return;
    }
    list.innerHTML = items.map(function(s) {
      var libLink = (LIBRARY_URL && s.prop_name)
        ? '<a href="' + LIBRARY_URL + '?prop_name=' + encodeURIComponent(s.prop_name) + '" target="_blank" class="text-xs underline ml-1" style="color:var(--ac);">查看物件↗</a>'
        : '';
      var linkedWar = _warByShowingId[s.id];
      var warBtn = linkedWar
        ? '<button style="background:var(--warn);color:#1a1208;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;border:none;cursor:pointer;" '
          + 'title="點擊編輯斡旋" onclick="warOpenEdit(\'' + linkedWar.id + '\')">⚔️ 斡旋中</button>'
        : '<button class="text-xs py-1 px-2 rounded border transition" style="color:var(--warn);border-color:var(--bd);" '
          + 'title="升級為斡旋戰況" '
          + 'onclick="showingToWar(\'' + s.id + '\',\'' + esc(s.prop_name) + '\',\'' + esc(s.prop_address||'') + '\',\'' + esc(s.prop_id||'') + '\',\'' + esc(s.buyer_name||'') + '\',\'\',\'' + esc(s.buyer_id||'') + '\')">⚔️ 斡旋</button>';
      var cardStyle = linkedWar ? 'border-left:4px solid var(--warn);' : '';
      return '<div class="card" id="sl-' + s.id + '" style="' + cardStyle + '">'
        + '<div class="flex items-start justify-between gap-3">'
        + '<div class="flex-1 min-w-0">'
        + '<div class="flex items-center gap-2 flex-wrap">'
        + '<span class="font-medium" style="color:var(--tx);">' + reactionIcon(s.reaction) + ' ' + esc(s.prop_name) + '</span>'
        + libLink
        + '<span class="text-xs px-2 py-0.5 rounded-full" style="color:var(--ac);background:var(--acs);">' + esc(s.buyer_name||'') + '</span>'
        + (linkedWar ? '<span style="background:var(--warn);color:#1a1208;font-size:10px;padding:1px 6px;border-radius:4px;">⚔️ ' + esc(linkedWar.prop_name||'') + '</span>' : '')
        + '</div>'
        + '<div class="text-xs mt-0.5" style="color:var(--txs);">' + esc(s.date) + (s.prop_address ? '　' + esc(s.prop_address) : '') + '</div>'
        + (s.note ? '<p class="text-xs mt-1" style="color:var(--txs);">' + esc(s.note) + '</p>' : '')
        + '</div>'
        + '<div class="flex gap-1.5 flex-shrink-0 flex-col items-end">'
        + warBtn
        + '<div class="flex gap-1">'
        + '<button class="text-xs py-1 px-2 rounded border transition" style="color:var(--ac);border-color:var(--bd);" '
        +   'onclick="showingEditOpen(\'' + s.id + '\',\'' + esc(s.date) + '\',\'' + esc(s.reaction) + '\')" data-note="' + esc(s.note||'') + '" data-from-detail="" data-buyer-id="">編輯</button>'
        + '<button class="text-xs py-1 px-2 rounded border transition" style="color:var(--dg);border-color:var(--bd);" '
        +   'onclick="showingDelete(\'' + s.id + '\',false,\'\')">刪除</button>'
        + '</div></div></div></div>';
    }).join('');
  }).catch(e => toast('載入帶看紀錄失敗', 'error'));
}

function showingOpenNew() {
  _clearDirty();
  document.getElementById('showing-modal-title').textContent = '新增帶看紀錄';
  document.getElementById('sm-buyer-id').value     = '';
  document.getElementById('sm-prop-name').value    = '';
  document.getElementById('sm-prop-loc').value     = '';
  document.getElementById('sm-prop-address').value = '';
  document.getElementById('sm-date').value         = new Date().toISOString().slice(0,10);
  document.getElementById('sm-reaction').value     = '有興趣';
  document.getElementById('sm-note').value         = '';
  document.getElementById('sm-id').value           = '';
  document.getElementById('sm-prop-id').value      = '';
  // 清掉候選清單
  var box = document.getElementById('sm-prop-suggest');
  if (box) box.classList.add('hidden');
  document.getElementById('showing-modal').classList.remove('hidden');
}

// ── 物件名稱自動完成 ──
var _propSuggestTimer = null;

function propSuggest(val) {
  var box = document.getElementById('sm-prop-suggest');
  if (!box) return;
  clearTimeout(_propSuggestTimer);
  var q = val.trim();
  if (!q) { box.classList.add('hidden'); return; }
  // 防抖 300ms
  _propSuggestTimer = setTimeout(function() {
    fetch('/api/prop-suggest?q=' + encodeURIComponent(q))
      .then(function(r){ return r.json(); })
      .then(function(d) {
        var items = d.items || [];
        if (!items.length) { box.classList.add('hidden'); return; }
        box.innerHTML = items.map(function(item) {
          var catName = item['類別'] || '';
          var propName = item['案名'] || '';
          // 類別欄空時，用案名關鍵字判斷是否為土地
          var isLand = ['農地','建地','農建地'].includes(catName)
                    || /農地|建地|農建地/.test(propName);
          var sellingTag = item['銷售中']
            ? '<span class="text-xs px-1.5 py-0.5 rounded-full" style="background:var(--ok);color:#fff;">銷售中</span>'
            : '<span class="text-xs px-1.5 py-0.5 rounded-full" style="background:var(--bg-h);color:var(--txs);">非銷售中</span>';
          // 土地顯示縣市地段地號，一般物件顯示地址
          var locText = '';
          if (isLand && item['段別']) {
            locText = (item['縣市鄉鎮'] || '') + ' ' + item['段別'] + (item['地號'] ? ' 地號 ' + item['地號'] : '');
          } else if (item['地址']) {
            locText = item['地址'];
          }
          // 所有權人
          var ownerText = item['所有權人'] ? '👤 ' + item['所有權人'] : '';
          // 把土地的 locText 存在 data-land-loc 供帶看 Modal 用
          return '<div class="prop-suggest-item px-4 py-2.5 cursor-pointer" style="border-bottom:1px solid var(--bd);"'
               + ' data-id="' + esc(item.id) + '"'
               + ' data-name="' + esc(item['案名']) + '"'
               + ' data-addr="' + esc(item['地址']) + '"'
               + ' data-land-loc="' + esc(locText) + '"'
               + ' data-is-land="' + (isLand ? '1' : '0') + '"'
               + ' onmouseover="this.style.background=\'var(--bg-h)\'" onmouseout="this.style.background=\'\'">'
               + '<div class="flex items-center gap-1.5 flex-wrap mb-0.5">'
               + '<span class="text-sm font-medium" style="color:var(--tx);">' + esc(item['案名']) + '</span>'
               + sellingTag
               + (item['類別'] ? '<span class="text-xs" style="color:var(--ac);">' + esc(item['類別']) + '</span>' : '')
               + '</div>'
               + (locText ? '<div class="text-xs" style="color:var(--txs);">' + esc(locText) + '</div>' : '')
               + (ownerText ? '<div class="text-xs" style="color:var(--txm);">' + ownerText + '</div>' : '')
               + '</div>';
        }).join('');
        box.classList.remove('hidden');
        // 點選候選
        box.querySelectorAll('.prop-suggest-item').forEach(function(el) {
          el.addEventListener('mousedown', function(e) {
            e.preventDefault();  // 防止 input blur 先觸發
            var isLand  = this.dataset.isLand === '1';
            var locVal  = isLand ? this.dataset.landLoc : this.dataset.addr;
            document.getElementById('sm-prop-name').value    = this.dataset.name;
            document.getElementById('sm-prop-loc').value     = locVal || '';
            document.getElementById('sm-prop-id').value      = this.dataset.id;
            // 同步更新隱藏的原始地址欄（給後端存）
            document.getElementById('sm-prop-address').value = this.dataset.addr;
            box.classList.add('hidden');
          });
        });
      })
      .catch(function() { box.classList.add('hidden'); });
  }, 300);
}

// 點擊其他地方關閉候選清單
document.addEventListener('click', function(e) {
  var box = document.getElementById('sm-prop-suggest');
  if (box && !box.contains(e.target) && e.target.id !== 'sm-prop-name') {
    box.classList.add('hidden');
  }
});

// 記錄帶看 Modal 是否從買方詳情開啟（儲存後要刷新詳情）
var _showingFromDetailBuyerId = '';

function showingOpenNewForBuyer(buyerId, buyerName) {
  showingOpenNew();
  // 鎖定買方：隱藏 select，顯示固定名稱
  document.getElementById('sm-buyer-id').value = buyerId;
  document.getElementById('sm-buyer-id').classList.add('hidden');
  var locked = document.getElementById('sm-buyer-locked');
  locked.textContent = '🔒 ' + buyerName;
  locked.classList.remove('hidden');
  _showingFromDetailBuyerId = buyerId;
  document.getElementById('showing-modal').classList.remove('hidden');
  // 自動 focus 物件名稱欄
  setTimeout(function(){ document.getElementById('sm-prop-name').focus(); }, 100);
}

function showingCloseModal() {
  _safeClose('showing', function() {
    document.getElementById('showing-modal').classList.add('hidden');
    _showingFromDetailBuyerId = '';
    // 解鎖買方：恢復 select 顯示
    document.getElementById('sm-buyer-id').classList.remove('hidden');
    var locked = document.getElementById('sm-buyer-locked');
    locked.classList.add('hidden');
    locked.textContent = '';
  });
}

function showingSave() {
  var id      = document.getElementById('sm-id').value.trim();
  // 鎖定模式優先用 _showingFromDetailBuyerId，否則讀 select
  var buyerId = _showingFromDetailBuyerId || document.getElementById('sm-buyer-id').value;
  var propName = document.getElementById('sm-prop-name').value.trim();
  if (!buyerId)  { toast('請選擇買方', 'error'); return; }
  if (!propName) { toast('請填寫物件名稱', 'error'); return; }
  // 取得買方姓名：鎖定時從 locked 文字取，否則從 select option 取
  var buyerName = '';
  var locked = document.getElementById('sm-buyer-locked');
  if (_showingFromDetailBuyerId && locked && !locked.classList.contains('hidden')) {
    buyerName = locked.textContent.replace('🔒 ', '').trim();
  } else {
    var buyerOpt = document.querySelector('#sm-buyer-id option[value="'+buyerId+'"]');
    buyerName = buyerOpt ? buyerOpt.textContent : '';
  }
  var body = {
    buyer_id:     buyerId,
    buyer_name:   buyerName,
    prop_id:      document.getElementById('sm-prop-id').value.trim(),
    prop_name:    propName,
    prop_address: (document.getElementById('sm-prop-loc').value || document.getElementById('sm-prop-address').value || '').trim(),
    date:         document.getElementById('sm-date').value,
    reaction:     document.getElementById('sm-reaction').value,
    note:         document.getElementById('sm-note').value.trim(),
  };
  var url    = id ? '/api/showings/' + id : '/api/showings';
  var method = id ? 'PUT' : 'POST';
  var fromDetailId = _showingFromDetailBuyerId;
  fetch(url, {method:method, headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
    .then(r => r.json()).then(d => {
      if (d.error) { toast(d.error, 'error'); return; }
      _clearDirty();
      toast('已儲存', 'success');
      showingCloseModal();
      if (fromDetailId) {
        // 從詳情開啟：關掉帶看 Modal 後刷新詳情（詳情還開著）
        buyerDetail(fromDetailId);
      } else {
        showingLoad();
      }
    }).catch(e => toast('儲存失敗', 'error'));
}

// ── 編輯帶看紀錄 ──
// note 改從按鈕的 data-note 屬性讀取，避免單引號在 onclick 裡斷行
function showingEditOpen(id, date, reaction) {
  // 找呼叫此函數的按鈕（event.currentTarget 或 document.activeElement）
  var btn = document.activeElement;
  var note       = btn ? (btn.dataset.note || '') : '';
  var fromDetail = btn ? (btn.dataset.fromDetail === '1') : false;
  var buyerId    = btn ? (btn.dataset.buyerId || '') : '';
  document.getElementById('se-id').value          = id;
  document.getElementById('se-date').value        = date;
  document.getElementById('se-reaction').value    = reaction;
  document.getElementById('se-note').value        = note;
  document.getElementById('se-from-detail').value = fromDetail ? '1' : '';
  document.getElementById('se-buyer-id').value    = buyerId;
  document.getElementById('showing-edit-modal').classList.remove('hidden');
}

function showingEditClose() {
  document.getElementById('showing-edit-modal').classList.add('hidden');
}

function showingEditSave() {
  var id         = document.getElementById('se-id').value.trim();
  var fromDetail = document.getElementById('se-from-detail').value === '1';
  var buyerId    = document.getElementById('se-buyer-id').value.trim();
  var body = {
    date:     document.getElementById('se-date').value,
    reaction: document.getElementById('se-reaction').value,
    note:     document.getElementById('se-note').value.trim(),
  };
  fetch('/api/showings/' + id, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
    .then(r => r.json()).then(d => {
      if (d.error) { toast(d.error, 'error'); return; }
      toast('已更新', 'success');
      showingEditClose();
      if (fromDetail && buyerId) buyerDetail(buyerId);
      else showingLoad();
    }).catch(e => toast('儲存失敗', 'error'));
}

// ── 帶看升級為斡旋 ──
function showingToWar(showingId, propName, propAddress, propId, buyerName, fromDetailBuyerId, buyerId) {
  if (!confirm('將「' + propName + '」加入斡旋戰況版？\n（戰況版會新增一筆，帶看紀錄仍保留）')) return;
  var body = {
    prop_name:    propName,
    prop_address: propAddress,
    prop_id:      propId,
    buyer_id:     buyerId || fromDetailBuyerId || '',
    buyer_name:   buyerName,
    showing_id:   showingId,   // 記錄來源帶看紀錄 ID，供反查
    status:       '斡旋中',
    note:         '',
  };
  fetch('/api/war', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)})
    .then(r => r.json()).then(d => {
      if (d.error) { toast(d.error, 'error'); return; }
      toast('✅ 已加入戰況版：' + propName, 'success');
      // 重新整理買方清單（更新斡旋標示）
      buyerLoad();
      // 若從詳情開啟，刷新詳情
      if (fromDetailBuyerId) buyerDetail(fromDetailBuyerId);
    }).catch(e => toast('升級失敗', 'error'));
}

function showingDelete(id, fromDetail, buyerId) {
  if (!confirm('確定刪除這筆帶看紀錄？')) return;
  fetch('/api/showings/' + id, {method:'DELETE'}).then(r => r.json()).then(d => {
    if (d.error) { toast(d.error, 'error'); return; }
    toast('已刪除', 'success');
    if (fromDetail && buyerId) buyerDetail(buyerId);
    else showingLoad();
  });
}

// ── 初始化 ──
buyerLoad();

// 為三個 Modal 掛上 dirty 偵測（監聽所有輸入欄位的變動）
_watchDirty('buyer-modal',   'buyer');
_watchDirty('war-modal',     'war');
_watchDirty('showing-modal', 'showing');

// 若有 URL 參數 ?action=showing，自動開啟帶看 Modal
(function() {
  var params = new URLSearchParams(window.location.search);
  var action = params.get('action');
  if (action === 'showing') {
    var propId   = params.get('prop_id') || '';
    var propName = params.get('prop_name') || '';
    var propAddr = params.get('prop_address') || '';
    // 等買方載入後再開 Modal
    setTimeout(function() {
      showingOpenNew();
      document.getElementById('sm-prop-id').value      = propId;
      document.getElementById('sm-prop-name').value    = propName;
      document.getElementById('sm-prop-address').value = propAddr;
      switchTab('showings');
    }, 800);
  }
})();

// ── 頭像 fallback 處理 ──
function _setAvatar(ids, picUrl, name) {
  var initial = (name || '?').trim().charAt(0).toUpperCase();
  ids.forEach(function(id) {
    var wrap = document.getElementById(id);
    if (!wrap) return;
    if (picUrl) {
      wrap.innerHTML = '<img src="' + picUrl + '" referrerpolicy="no-referrer" alt="" /><div class="av-fb" style="display:none">' + initial + '</div>';
      var img = wrap.querySelector('img');
      img.onerror = function() { this.style.display='none'; wrap.querySelector('.av-fb').style.display='flex'; };
    } else {
      wrap.innerHTML = '<div class="av-fb">' + initial + '</div>';
    }
  });
}
// 頁面載入後嘗試填入 Google 頭像圖片
(function() {
  var pic = '__AVATAR__';
  var name = '__USER_NAME__';
  if (pic) { _setAvatar(['sb-avatar', 'hd-avatar'], pic, name); }
})();

// ── Sidebar 工具函數 ──
(function() {
  var LIBRARY_URL_SB = __LIBRARY_URL__;
  var PORTAL_URL_SB  = '__PORTAL_URL__';
  var IS_ADMIN_SB    = __IS_ADMIN__;

  // 物件庫連結（sidebar，直接連）
  if (LIBRARY_URL_SB) {
    var sbLib = document.getElementById('sb-library');
    if (sbLib) { sbLib.href = LIBRARY_URL_SB; sbLib.target = 'tool-library'; sbLib.classList.remove('hidden'); }
  }
  // 所有 Tab Bar 和 Sidebar 透過 Portal SSO 跳轉
  if (PORTAL_URL_SB && PORTAL_URL_SB !== '/') {
    var portalBase = PORTAL_URL_SB.replace(/\/$/, '');
    // Tab Bar：全部設定（不再 hidden 動態顯示，固定顯示）
    var tbLib = document.getElementById('tb-library');
    if (tbLib) { tbLib.href = portalBase + '/api/enter/library'; tbLib.target = 'tool-library'; }
    var tbAd = document.getElementById('tb-ad');
    if (tbAd) { tbAd.href = portalBase + '/api/enter/post'; tbAd.target = 'tool-post'; }
    var tbSurvey = document.getElementById('tb-survey');
    if (tbSurvey) { tbSurvey.href = portalBase + '/api/enter/survey'; tbSurvey.target = 'tool-survey'; }
    var tbCalendar = document.getElementById('tb-calendar');
    if (tbCalendar) { tbCalendar.href = portalBase + '/api/enter/calendar'; tbCalendar.target = 'tool-calendar'; }
    // Sidebar 廣告、周邊、行事曆
    var sbAd = document.getElementById('sb-ad');
    if (sbAd) { sbAd.href = portalBase + '/api/enter/post'; sbAd.target = 'tool-post'; sbAd.classList.remove('hidden'); }
    var sbSurvey = document.getElementById('sb-survey');
    if (sbSurvey) { sbSurvey.href = portalBase + '/api/enter/survey'; sbSurvey.target = 'tool-survey'; sbSurvey.classList.remove('hidden'); }
    var sbCalendar = document.getElementById('sb-calendar');
    if (sbCalendar) { sbCalendar.href = portalBase + '/api/enter/calendar'; sbCalendar.target = 'tool-calendar'; sbCalendar.classList.remove('hidden'); }
  }
  // Portal 衍生連結（升級/帳號/後台）
  if (PORTAL_URL_SB && PORTAL_URL_SB !== '/') {
    var ddPlans   = document.getElementById('dd-plans');
    var ddAccount = document.getElementById('dd-account');
    var ddAdmin   = document.getElementById('dd-admin');
    if (ddPlans)   { ddPlans.href   = PORTAL_URL_SB.replace(/\/$/, '') + '/plans';   ddPlans.classList.remove('hidden'); }
    if (ddAccount) { ddAccount.href = PORTAL_URL_SB.replace(/\/$/, '') + '/account'; ddAccount.classList.remove('hidden'); }
    if (IS_ADMIN_SB && ddAdmin) {
      ddAdmin.href = PORTAL_URL_SB.replace(/\/$/, '') + '/admin'; ddAdmin.classList.remove('hidden');
    }
  }
})();

function buyerToggleDropdown(e) {
  e.stopPropagation();
  var dd = document.getElementById('user-dropdown');
  var bd = document.getElementById('user-dropdown-backdrop');
  if (dd.style.display === 'block') { buyerCloseDropdown(); return; }
  var rect = e.currentTarget.getBoundingClientRect();
  var ddW = 220;
  var left = Math.max(8, rect.right - ddW);
  if (rect.top > window.innerHeight / 2) {
    dd.style.bottom = (window.innerHeight - rect.top + 8) + 'px'; dd.style.top = '';
  } else {
    dd.style.top = (rect.bottom + 8) + 'px'; dd.style.bottom = '';
  }
  dd.style.left = left + 'px';
  dd.style.display = 'block'; bd.style.display = 'block';
}
function buyerCloseDropdown() {
  document.getElementById('user-dropdown').style.display = 'none';
  document.getElementById('user-dropdown-backdrop').style.display = 'none';
}
function buyerDoLogout() {
  fetch('/auth/logout', {method:'POST'}).then(function(r){ return r.json(); }).then(function(d) {
    window.location.href = d.redirect || '__PORTAL_URL__';
  }).catch(function(){ window.location.reload(); });
}

// ══ 主題系統 ══
(function() {
  var STYLE_MODES = {
    navy:    { dark:'navy-dark',    light:'navy-light'    },
    forest:  { dark:'forest-dark',  light:'forest-light'  },
    amber:   { dark:'amber-dark',   light:'amber-light'   },
    minimal: { dark:'minimal-dark', light:'minimal-light' },
    rose:    { dark:'rose-dark',    light:'rose-light'    },
    oled:    { dark:'oled-dark',    light:'oled-dark'     },
  };
  var DARK_ONLY = ['oled'];
  var _style = 'navy';
  var _mode  = 'system';
  var _isAdmin = false;

  // 套用主題到 DOM
  function _applyTheme() {
    var sys = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var eff = _mode === 'system' ? (sys ? 'dark' : 'light') : _mode;
    if (DARK_ONLY.indexOf(_style) >= 0) eff = 'dark';
    var key = (STYLE_MODES[_style] || STYLE_MODES.navy)[eff];
    document.body.setAttribute('data-theme', key);
    // 更新面板按鈕選取狀態
    ['dark','light','system'].forEach(function(m) {
      var btn = document.getElementById('tp-btn-' + m);
      if (btn) btn.classList.toggle('active', m === _mode);
    });
    Object.keys(STYLE_MODES).forEach(function(s) {
      var card = document.getElementById('tp-card-' + s);
      if (card) card.classList.toggle('selected', s === _style);
    });
    // OLED 停用淺色、系統模式
    var isOled = DARK_ONLY.indexOf(_style) >= 0;
    ['light','system'].forEach(function(m) {
      var btn = document.getElementById('tp-btn-' + m);
      if (btn) { btn.disabled = isOled; btn.style.opacity = isOled ? '0.4' : '1'; }
    });
  }

  // 個人模式切換（存 localStorage）
  window._tpSetMode = function(m) {
    _mode = m;
    localStorage.setItem('up_mode', m);
    _applyTheme();
    // 同步寫入 Firestore，讓所有工具下次載入時讀到同樣的 mode
    fetch('/api/theme', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mode:m})}).catch(function(){});
  };

  // 管理員風格切換（預覽，儲存時才送後端）
  window._tpAdminSetStyle = function(s) {
    _style = s;
    localStorage.setItem('up_style', s);
    _applyTheme();
  };

  var _PORTAL = '__PORTAL_URL__'.replace(/\/$/, '');
  var _IS_ADMIN = __IS_ADMIN__;

  // 儲存並推到後端（管理員）
  window._tpSaveStyle = function() {
    fetch('/api/theme', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({style: _style})
    }).then(function(r){ return r.json(); }).then(function(d) {
      if (d.ok) {
        localStorage.setItem('up_style', _style);
        var msg = document.getElementById('tp-save-msg');
        if (msg) { msg.style.display='block'; setTimeout(function(){msg.style.display='none';},3000); }
      }
    }).catch(function(){});
  };

  // 初始化：從 Portal 取後台風格，再套個人模式
  function _init() {
    _mode = localStorage.getItem('up_mode') || 'system';
    var cached = localStorage.getItem('up_style') || 'navy';
    _style = cached;
    _applyTheme();
    // 從後台讀取 style 和 mode，確保跨工具同步
    fetch('/api/theme')
      .then(function(r){ return r.json(); })
      .then(function(d) {
        var changed = false;
        if (d.style && d.style !== _style) { _style = d.style; localStorage.setItem('up_style', _style); changed = true; }
        if (d.mode && d.mode !== _mode) { _mode = d.mode; localStorage.setItem('up_mode', _mode); changed = true; }
        if (changed) _applyTheme();
      }).catch(function(){});
    // 判斷是否管理員（顯示儲存按鈕）
    var adminEl = document.getElementById('tp-admin-only');
    if (adminEl && _IS_ADMIN) adminEl.style.display = 'block';
    // 系統模式監聽
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function() {
      if (_mode === 'system') _applyTheme();
    });
  }
  // 立即套用快取，避免閃白
  (function() {
    var s = localStorage.getItem('up_style') || 'navy';
    var m = localStorage.getItem('up_mode') || 'system';
    var sys = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var eff = m === 'system' ? (sys ? 'dark' : 'light') : m;
    if (DARK_ONLY.indexOf(s) >= 0) eff = 'dark';
    document.body.setAttribute('data-theme', (STYLE_MODES[s] || STYLE_MODES.navy)[eff]);
  })();
  document.addEventListener('DOMContentLoaded', _init);
})();
</script>
</body>
</html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=True)
