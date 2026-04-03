# ==========================================================
# GCS 工具函數 — 處理 Google Cloud Storage 的上傳、刪除、列表、串流
# ==========================================================
import os
import mimetypes
from flask import Response

# GCS 客戶端（延遲初始化，避免本地開發沒裝 GCS 也能跑）
_storage_client = None
_bucket = None

GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET", "")


def _init_gcs():
    """延遲初始化 GCS 客戶端和 bucket，只跑一次"""
    global _storage_client, _bucket
    if _storage_client is not None:
        return _bucket is not None
    bucket_name = GCS_BUCKET_NAME or os.environ.get("GCS_BUCKET", "")
    if not bucket_name:
        print("[GCS] 未設定 GCS_BUCKET，圖片功能不可用", flush=True)
        _storage_client = False  # 標記為已嘗試但失敗
        return False
    try:
        from google.cloud import storage
        _storage_client = storage.Client()
        _bucket = _storage_client.bucket(bucket_name)
        print(f"[GCS] 已連接 bucket: {bucket_name}", flush=True)
        return True
    except Exception as e:
        print(f"[GCS] 初始化失敗: {e}", flush=True)
        _storage_client = False
        return False


def gcs_upload_image(gcs_path, file_bytes, content_type="image/jpeg"):
    """
    上傳圖片到 GCS
    - gcs_path: 儲存路徑（例如 ad-photos/email/obj_id/uuid.jpg）
    - file_bytes: 圖片的 bytes 資料
    - content_type: MIME 類型
    回傳 gcs_path（成功）或 None（失敗）
    """
    if not _init_gcs():
        return None
    try:
        blob = _bucket.blob(gcs_path)
        blob.upload_from_string(file_bytes, content_type=content_type)
        print(f"[GCS] 上傳成功: {gcs_path}", flush=True)
        return gcs_path
    except Exception as e:
        print(f"[GCS] 上傳失敗 {gcs_path}: {e}", flush=True)
        return None


def gcs_delete_blob(gcs_path):
    """
    刪除 GCS 上的單一檔案
    - 如果檔案不存在，不會報錯（靜默成功）
    """
    if not _init_gcs():
        return
    try:
        blob = _bucket.blob(gcs_path)
        blob.delete()
        print(f"[GCS] 已刪除: {gcs_path}", flush=True)
    except Exception as e:
        # 404 Not Found 不算錯誤
        if hasattr(e, "code") and e.code == 404:
            return
        print(f"[GCS] 刪除失敗 {gcs_path}: {e}", flush=True)


def gcs_delete_prefix(prefix):
    """
    刪除某個前綴下的所有檔案
    - 用於刪除整個廣告活動的所有截圖
    """
    if not _init_gcs():
        return
    try:
        blobs = list(_bucket.list_blobs(prefix=prefix))
        for blob in blobs:
            blob.delete()
        print(f"[GCS] 已刪除前綴 {prefix} 下 {len(blobs)} 個檔案", flush=True)
    except Exception as e:
        print(f"[GCS] 刪除前綴失敗 {prefix}: {e}", flush=True)


def gcs_list_blobs(prefix):
    """
    列出某個前綴下的所有檔案名稱
    回傳 [blob.name, ...] 列表
    """
    if not _init_gcs():
        return []
    try:
        blobs = _bucket.list_blobs(prefix=prefix)
        return [b.name for b in blobs]
    except Exception as e:
        print(f"[GCS] 列表失敗 {prefix}: {e}", flush=True)
        return []


def gcs_serve_blob(gcs_path):
    """
    從 GCS 讀取檔案並回傳 Flask Response（圖片代理）
    - 自動偵測 Content-Type
    - 加上快取 header（1 小時）
    回傳 Response 物件，或 (錯誤訊息, 狀態碼)
    """
    if not _init_gcs():
        return ("GCS 未設定", 503)
    try:
        blob = _bucket.blob(gcs_path)
        # 先檢查檔案是否存在
        if not blob.exists():
            return ("檔案不存在", 404)
        data = blob.download_as_bytes()
        # 從路徑推斷 Content-Type
        ct = mimetypes.guess_type(gcs_path)[0] or "application/octet-stream"
        return Response(
            data,
            content_type=ct,
            headers={
                "Cache-Control": "private, max-age=3600",  # 快取 1 小時
            }
        )
    except Exception as e:
        print(f"[GCS] 串流失敗 {gcs_path}: {e}", flush=True)
        return ("讀取失敗", 500)
