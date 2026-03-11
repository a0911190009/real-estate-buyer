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
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = not os.environ.get("FLASK_DEBUG")

PORTAL_URL      = (os.environ.get("PORTAL_URL") or "").strip()
LIBRARY_URL     = (os.environ.get("LIBRARY_URL") or "").strip()
ADMIN_EMAILS    = [e.strip() for e in (os.environ.get("ADMIN_EMAILS") or "").split(",") if e.strip()]
TOKEN_SERIALIZER = URLSafeTimedSerializer(app.secret_key)
TOKEN_MAX_AGE   = 60  # seconds


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


@app.route("/auth/portal-login")
def auth_portal_login():
    """Portal 跳轉過來時，驗證 token 建立 session。"""
    token = request.args.get("token", "")
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
    return redirect("/")


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

@app.route("/")
def index():
    email, err = _require_user()
    if err:
        # 未登入 → 導回 Portal
        return redirect(PORTAL_URL or "/auth/portal-login")

    is_admin    = _is_admin(email)
    user_name   = session.get("user_name", email)
    user_picture = session.get("user_picture", "")
    portal_url  = PORTAL_URL or "/"
    library_url = LIBRARY_URL or ""

    IS_ADMIN_JSON = json.dumps(is_admin)
    role_label = "管理員" if is_admin else "業務"
    badge_class = "admin" if is_admin else "points"
    initial = (user_name or user_picture or "?")[0].upper()

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


# ══════════════════════════════════════════
#  HTML 模板
# ══════════════════════════════════════════

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
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

<!-- ── 手機底部 Tab Bar ── -->
<nav id="buyer-tab-bar">
  <a href="__PORTAL_URL__" target="tool-portal" class="buyer-tb-item">
    <span style="font-size:1.3rem;">🏠</span>
    <span>首頁</span>
  </a>
  <a href="javascript:void(0)" id="tb-ad" class="buyer-tb-item hidden">
    <span style="font-size:1.3rem;">📝</span>
    <span>廣告</span>
  </a>
  <a href="javascript:void(0)" id="tb-library" class="buyer-tb-item hidden">
    <span style="font-size:1.3rem;">📁</span>
    <span>物件庫</span>
  </a>
  <a href="#" class="buyer-tb-item buyer-tb-active">
    <span style="font-size:1.3rem;">👥</span>
    <span>買方</span>
  </a>
  <a href="javascript:void(0)" id="tb-survey" class="buyer-tb-item hidden">
    <span style="font-size:1.3rem;">📍</span>
    <span>周邊</span>
  </a>
  <a href="javascript:void(0)" id="tb-calendar" class="buyer-tb-item hidden">
    <span style="font-size:1.3rem;">📅</span>
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

  // 物件庫連結（sidebar 和 tab bar，不放 dropdown）
  if (LIBRARY_URL_SB) {
    var sbLib = document.getElementById('sb-library');
    if (sbLib) { sbLib.href = LIBRARY_URL_SB; sbLib.target = 'tool-library'; sbLib.classList.remove('hidden'); }
    var tbLib = document.getElementById('tb-library');
    if (tbLib) { tbLib.href = LIBRARY_URL_SB; tbLib.target = 'tool-library'; tbLib.classList.remove('hidden'); }
  }
  // Tab Bar 廣告和周邊（透過 Portal /api/enter/ 跳轉）
  if (PORTAL_URL_SB && PORTAL_URL_SB !== '/') {
    var portalBase = PORTAL_URL_SB.replace(/\/$/, '');
    var tbAd = document.getElementById('tb-ad');
    if (tbAd) { tbAd.href = portalBase + '/api/enter/post'; tbAd.target = 'tool-post'; tbAd.classList.remove('hidden'); }
    var tbSurvey = document.getElementById('tb-survey');
    if (tbSurvey) { tbSurvey.href = portalBase + '/api/enter/survey'; tbSurvey.target = 'tool-survey'; tbSurvey.classList.remove('hidden'); }
    // Sidebar 廣告和周邊連結
    var sbAd = document.getElementById('sb-ad');
    if (sbAd) { sbAd.href = portalBase + '/api/enter/post'; sbAd.target = 'tool-post'; sbAd.classList.remove('hidden'); }
    var sbSurvey = document.getElementById('sb-survey');
    if (sbSurvey) { sbSurvey.href = portalBase + '/api/enter/survey'; sbSurvey.target = 'tool-survey'; sbSurvey.classList.remove('hidden'); }
    // 業務行事曆
    var tbCalendar = document.getElementById('tb-calendar');
    if (tbCalendar) { tbCalendar.href = portalBase + '/api/enter/calendar'; tbCalendar.target = 'tool-calendar'; tbCalendar.classList.remove('hidden'); }
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
