"""
BUYER → PEOPLE 整合層

把 PEOPLE 集合 + roles/buyer 子文件包裝成 BUYER 介面期待的格式。
所有「買方」資料來自 people 集合（以 active_roles 含 'buyer' 篩選）。
buyers/ collection 保留為備份，不再讀寫。

主要函式：
    list_buyers(db, email, is_admin) → [{...buyer dict...}, ...]
    get_buyer(db, person_id, email, is_admin) → {...buyer dict...} | None
    create_buyer(db, email, data) → person_id
    update_buyer(db, person_id, email, data) → person_id
    archive_buyer(db, person_id, email) → bool

回傳的 buyer dict 格式（與舊 buyers 集合相容）：
    {
        id, name, phone,
        budget_min, budget_max, area, types, size_min, size_max,
        note, status, card_color, photo_b64,
        created_by, created_at, updated_at, last_contact_at, sort_order,
        attachments: [{id, gcs_path, filename, mime_type, uploaded_at,
                       transcript?, summary?, keywords?}, ...]
    }
"""
from __future__ import annotations
from typing import Any
from datetime import datetime
import logging

# 對應到 people 角色子集合用的常數
PEOPLE_BUCKET_DEFAULT = "normal"
BUYER_ROLE_DOC_ID = "buyer"

# BUYER 用的物件類別需符合 PEOPLE 的 PROPERTY_CATEGORIES（不在裡面的會被丟掉）
VALID_CATEGORIES = {
    "透天", "別墅", "農舍", "公寓", "華廈", "套房",
    "建地", "農地", "店面", "店住", "房屋", "其他",
}
VALID_BUYER_STATUSES = {"洽談中", "持續看物件", "暫無需求", "保持連繫", "成交", "流失"}


def _ts_to_str(v):
    """Firestore Timestamp / datetime → ISO 字串；其他保持原樣。"""
    if v is None:
        return None
    if hasattr(v, "isoformat"):
        try:
            return v.isoformat()
        except Exception:
            pass
    return v


def _to_files_list(files_docs) -> list[dict]:
    """把 people/{id}/files 子集合轉成 BUYER 期待的 attachments 陣列格式。"""
    items = []
    for d in files_docs:
        data = d.to_dict() or {}
        items.append({
            "id":          data.get("id") or d.id,
            "gcs_path":    data.get("gcs_path"),
            "filename":    data.get("filename"),
            "mime_type":   data.get("mime_type"),
            "uploaded_at": _ts_to_str(data.get("uploaded_at")),
            "transcript":  data.get("transcript"),
            "summary":     data.get("summary"),
            "keywords":    data.get("keywords"),
        })
    return items


def _normalize_avatar(avatar_b64):
    """確保 avatar 是完整 data URL 格式（BUYER 前端 src=值 時才能顯示）。"""
    if not avatar_b64:
        return None
    if isinstance(avatar_b64, str) and avatar_b64.startswith("data:"):
        return avatar_b64
    # 純 base64 → 補上 jpeg 前綴
    return "data:image/jpeg;base64," + avatar_b64


def person_to_buyer(person: dict, role: dict | None, files: list[dict]) -> dict:
    """把 PEOPLE doc + roles/buyer doc + files 陣列 → BUYER API 格式。"""
    role = role or {}
    size_indoor = role.get("size_indoor") or {}
    if not isinstance(size_indoor, dict):
        size_indoor = {}
    area_pref = role.get("area_pref") or []
    cat_pref = role.get("category_pref") or []

    return {
        "id":          person.get("id") or person.get("_id"),
        "name":        person.get("name", ""),
        "phone":       person.get("phone", "") or "",
        "note":        person.get("note", "") or "",
        "card_color":  person.get("card_color", "") or "",
        "photo_b64":   _normalize_avatar(person.get("avatar_b64")),
        # 買方專屬欄位 → role
        "budget_min":  role.get("budget_min"),
        "budget_max":  role.get("budget_max"),
        "size_min":    size_indoor.get("min") if isinstance(size_indoor, dict) else None,
        "size_max":    size_indoor.get("max") if isinstance(size_indoor, dict) else None,
        # area 保留為單一字串（取 area_pref 第一個）；types 是 list
        "area":        area_pref[0] if area_pref else "",
        "types":       cat_pref,
        "status":      role.get("status") or "洽談中",
        # 元資料
        "created_by":      person.get("created_by"),
        "created_at":      _ts_to_str(person.get("created_at")),
        "updated_at":      _ts_to_str(person.get("updated_at")),
        "last_contact_at": _ts_to_str(person.get("last_contact_at")),
        "sort_order":      person.get("sort_order"),
        # 附件
        "attachments":     files,
    }


def extract_person_patch(buyer_data: dict) -> dict:
    """從前端送來的 buyer dict → 拆出可寫進 PEOPLE 主檔的欄位（PATCH 用）。"""
    out = {}
    if "name" in buyer_data:
        v = str(buyer_data.get("name", "") or "").strip()
        if v:
            out["name"] = v
    if "phone" in buyer_data:
        out["phone"] = str(buyer_data.get("phone", "") or "").strip() or None
    if "note" in buyer_data:
        out["note"] = str(buyer_data.get("note", "") or "").strip() or None
    if "card_color" in buyer_data:
        cc = str(buyer_data.get("card_color", "") or "").strip()
        out["card_color"] = cc if (cc.startswith("#") and 4 <= len(cc) <= 9) else None
    if "photo_b64" in buyer_data:
        # photo_b64=None 代表清除頭像
        out["avatar_b64"] = buyer_data.get("photo_b64") or None
    return out


def extract_role_payload(buyer_data: dict) -> dict:
    """從前端送來的 buyer dict → roles/buyer 子文件欄位。"""
    out = {}
    # 數字欄位
    for src, dst in [("budget_min", "budget_min"), ("budget_max", "budget_max")]:
        if src in buyer_data:
            v = buyer_data.get(src)
            try:
                out[dst] = float(v) if v not in (None, "", 0) else None
            except (TypeError, ValueError):
                out[dst] = None
    # size_min/max → size_indoor.{min,max}
    if "size_min" in buyer_data or "size_max" in buyer_data:
        si = {}
        for src, k in [("size_min", "min"), ("size_max", "max")]:
            v = buyer_data.get(src)
            try:
                if v not in (None, "", 0):
                    si[k] = float(v)
            except (TypeError, ValueError):
                pass
        out["size_indoor"] = si if si else None
    # area (str) → area_pref ([str])
    if "area" in buyer_data:
        v = str(buyer_data.get("area", "") or "").strip()
        out["area_pref"] = [v] if v else []
    # types ([str]) → category_pref（過濾掉無效）
    if "types" in buyer_data:
        types = buyer_data.get("types") or []
        if isinstance(types, list):
            out["category_pref"] = [t for t in types if t in VALID_CATEGORIES]
        else:
            out["category_pref"] = []
    # status
    if "status" in buyer_data:
        v = buyer_data.get("status")
        if v in VALID_BUYER_STATUSES:
            out["status"] = v
    return out


def _is_buyer_active(person: dict) -> bool:
    """判斷此人是否為「進行中的買方」 → active_roles 含 buyer 即可。"""
    return "buyer" in (person.get("active_roles") or [])


def list_buyers(db, email: str, is_admin: bool) -> list[dict]:
    """列出買方。為避免 Firestore 複合索引問題，先以 created_by 篩，
    再在 Python 端過濾 active_roles 是否含 buyer。"""
    if is_admin:
        # 管理員看全部 → 用 array_contains 即可（單欄查詢不需複合索引）
        q = db.collection("people").where("active_roles", "array_contains", "buyer")
    else:
        # 一般用戶：以 created_by 查全部，Python 端再篩買方角色
        q = db.collection("people").where("created_by", "==", email)
    items = []
    for doc in q.stream():
        person = doc.to_dict() or {}
        if person.get("is_group") or person.get("deleted_at"):
            continue
        if "buyer" not in (person.get("active_roles") or []):
            continue
        person["id"] = doc.id
        role_snap = doc.reference.collection("roles").document(BUYER_ROLE_DOC_ID).get()
        role = role_snap.to_dict() if role_snap.exists else {}
        files = _to_files_list(doc.reference.collection("files").stream())
        items.append(person_to_buyer(person, role, files))
    # 排序：sort_order 優先（小→大），None 殿後（依 last_contact_at desc）
    items.sort(key=lambda b: (
        0 if b.get("sort_order") is not None else 1,
        b.get("sort_order") if b.get("sort_order") is not None else 0,
        -1 if b.get("last_contact_at") else 0,
    ))
    return items


def get_buyer(db, person_id: str, email: str, is_admin: bool) -> dict | None:
    """讀單筆買方。回傳 None=找不到；False=無權限；dict=資料。"""
    ref = db.collection("people").document(person_id)
    snap = ref.get()
    if not snap.exists:
        return None
    person = snap.to_dict() or {}
    if not is_admin and person.get("created_by") != email:
        return False  # 用 False 區分「無權限」
    if not _is_buyer_active(person):
        return None  # 不是買方
    person["id"] = person_id
    role_snap = ref.collection("roles").document(BUYER_ROLE_DOC_ID).get()
    role = role_snap.to_dict() if role_snap.exists else {}
    files = _to_files_list(ref.collection("files").stream())
    return person_to_buyer(person, role, files)


def create_buyer(db, email: str, data: dict, server_timestamp_fn) -> str:
    """建立買方 = 建 person + 建 roles/buyer。回傳 person_id。"""
    name = str(data.get("name", "") or "").strip()
    if not name:
        raise ValueError("請填寫買方姓名")

    # 1. 建 person
    person_payload = {
        "name": name,
        "display_name": None,
        "birthday": None,
        "zodiac": None,
        "gender": None,
        "company": None,
        "contacts": [],
        "addresses": [],
        "bucket": PEOPLE_BUCKET_DEFAULT,
        "warning": None,
        "source": {"channel": "other", "referrer_person_id": None, "note": ""},
        "is_group": False,
        "group_type": None,
        "members": [],
        "card_color": None,
        "note": None,
        "phone": None,
        "avatar_b64": None,
        "active_roles": ["buyer"],   # 直接標記為買方
        "has_completed_deal": False,
        "relations": [],
        "legacy_buyer_id": None,
        "legacy_seller_id": None,
        "last_contact_at": None,
        "sort_order": None,
        "deleted_at": None,
        "created_by": email,
        "created_at": server_timestamp_fn(),
        "updated_at": server_timestamp_fn(),
    }
    # 套用前端送來的主檔欄位
    person_payload.update(extract_person_patch(data))

    person_ref = db.collection("people").document()
    person_ref.set(person_payload)

    # 2. 建 roles/buyer
    role_payload = extract_role_payload(data)
    role_payload.setdefault("status", "洽談中")
    role_payload["created_at"] = server_timestamp_fn()
    role_payload["created_by"] = email
    role_payload["updated_at"] = server_timestamp_fn()
    role_payload["archived_at"] = None
    person_ref.collection("roles").document(BUYER_ROLE_DOC_ID).set(role_payload)

    return person_ref.id


def update_buyer(db, person_id: str, email: str, is_admin: bool, data: dict, server_timestamp_fn) -> bool:
    """更新買方。person 主檔用 PATCH（只動有送來的欄位），roles/buyer 同樣 PATCH。"""
    ref = db.collection("people").document(person_id)
    snap = ref.get()
    if not snap.exists:
        return None  # 找不到
    person = snap.to_dict() or {}
    if not is_admin and person.get("created_by") != email:
        return False  # 無權限

    # 1. 更新主檔
    person_patch = extract_person_patch(data)
    if person_patch:
        person_patch["updated_at"] = server_timestamp_fn()
        ref.update(person_patch)

    # 2. 更新角色
    role_patch = extract_role_payload(data)
    if role_patch:
        role_patch["updated_at"] = server_timestamp_fn()
        # 確保角色文件存在；不存在就建立
        role_ref = ref.collection("roles").document(BUYER_ROLE_DOC_ID)
        rsnap = role_ref.get()
        if not rsnap.exists:
            role_patch["created_at"] = server_timestamp_fn()
            role_patch["created_by"] = email
            role_patch["archived_at"] = None
            role_patch.setdefault("status", "洽談中")
        role_ref.set(role_patch, merge=True)
        # 同步 active_roles：如果 role.status 改成「成交」，refresh 一下
        # 這裡簡化處理：只要寫入 role 就把 buyer 加進 active_roles
        active = list(person.get("active_roles") or [])
        if "buyer" not in active:
            active.append("buyer")
            ref.update({"active_roles": active})

    return True


def archive_buyer(db, person_id: str, email: str, is_admin: bool, server_timestamp_fn) -> bool:
    """『撕去買方標籤』= archive roles/buyer + 從 active_roles 移除 buyer。
    主檔保留（人脈管理仍看得到此人，只是少了買方標籤）。
    """
    ref = db.collection("people").document(person_id)
    snap = ref.get()
    if not snap.exists:
        return None
    person = snap.to_dict() or {}
    if not is_admin and person.get("created_by") != email:
        return False

    role_ref = ref.collection("roles").document(BUYER_ROLE_DOC_ID)
    rsnap = role_ref.get()
    if rsnap.exists:
        role_ref.update({"archived_at": server_timestamp_fn()})

    # 從 active_roles 移除 buyer
    active = [r for r in (person.get("active_roles") or []) if r != "buyer"]
    ref.update({"active_roles": active, "updated_at": server_timestamp_fn()})
    return True


def soft_delete_person(db, person_id: str, email: str, is_admin: bool, server_timestamp_fn) -> bool:
    """『連人脈一起刪』= 軟刪除整個 person（設 deleted_at）。
    人脈管理也看不到，但可從垃圾桶救回。
    """
    ref = db.collection("people").document(person_id)
    snap = ref.get()
    if not snap.exists:
        return None
    person = snap.to_dict() or {}
    if not is_admin and person.get("created_by") != email:
        return False
    ref.update({
        "deleted_at": server_timestamp_fn(),
        "updated_at": server_timestamp_fn(),
    })
    return True
