"""
Aegis backend (FastAPI)
-----------------------
Serves the data the Aegis frontend needs: local-style SHA-256 verification,
EXIF extraction, a reverse-image scan (Google Cloud Vision web detection),
an incident timeline, and a takedown dashboard with real status transitions.

This is a working STARTING POINT for a real service, not a finished one.
Before deploying anything that contacts third parties or sends legal
notices on someone's behalf:
  - Always have a human review a notice before it sends (see /takedowns/{id}/preview).
  - Get explicit, informed consent from the user for every automated step.
  - Consult a lawyer about DMCA / local takedown law in your jurisdiction.
  - Replace the in-memory store below with a real, access-controlled database —
    this data is some of the most sensitive a person can hand you.

Install:
    pip install fastapi uvicorn pillow python-multipart google-cloud-vision --break-system-packages

Run:
    uvicorn aegis_backend:app --reload
"""

import hashlib
import io
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image
from PIL.ExifTags import TAGS

app = FastAPI(title="Aegis API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your frontend's origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# In-memory store — swap for a real database (with per-user access control)
# before this handles anyone's actual case.
# ---------------------------------------------------------------------------

class Status(str, Enum):
    pending = "pending"
    sent = "sent"
    removed = "removed"


class TakedownEntry(BaseModel):
    id: str
    site: str
    site_type: str
    url: str
    detected: str
    progress: int
    status: Status
    abuse_contact: str
    sent_on: str
    log: list[str] = []


class IncidentEvent(BaseModel):
    id: str
    time: str
    title: str
    site: str
    type: str  # "mirror" | "forum" | "private"
    risk: bool
    confidence: int
    meta: list[str] = []
    detail: dict


DB: dict[str, dict] = {
    "takedowns": {},
    "incidents": {},
}


def seed():
    """Illustrative starting data so the API is usable before a real /scan runs.
    Site names here are placeholders — a real /scan call replaces them with
    whatever a reverse-image search actually returns."""
    takedowns = [
        dict(site="ImageRelay.net", site_type="Direct image host", url="img-host-142.net/u/8841",
             detected="Mar 14", progress=100, status=Status.removed, abuse_contact="abuse@imagerelay.net",
             sent_on="Mar 15", log=["Notice sent Mar 15", "Host confirmed removal Mar 17"]),
        dict(site="PixTrade Boards", site_type="Anonymous image board", url="forumcache.io/t/29174",
             detected="Mar 14", progress=65, status=Status.sent, abuse_contact="admin@pixtradeboards.io",
             sent_on="Mar 16", log=["Notice sent Mar 16", "Awaiting response"]),
        dict(site="LeakIndex Gallery", site_type="Aggregator / index", url="leakindex.to/gallery/552",
             detected="Mar 16", progress=30, status=Status.pending, abuse_contact="unlisted — WHOIS privacy",
             sent_on="—", log=["Abuse contact not yet found"]),
    ]
    for t in takedowns:
        entry_id = str(uuid.uuid4())
        DB["takedowns"][entry_id] = TakedownEntry(id=entry_id, **t).model_dump()

    incidents = [
        dict(time="Mar 14, 2026 · 03:12 UTC", title="Estimated first appearance", site="ImageRelay.net",
             type="mirror", risk=False, confidence=96, meta=["EXIF timestamp match", "Original resolution"],
             detail={"Site type": "Direct image host", "Server region": "US-East (Ashburn, VA)",
                     "Traceable": "Yes — hosting provider identified"}),
        dict(time="Mar 14, 2026 · 19:40 UTC", title="Re-posted with crop applied", site="PixTrade Boards",
             type="forum", risk=True, confidence=91, meta=["Cropped variant", "91% hash match"],
             detail={"Site type": "Anonymous image board", "Server region": "Unknown (behind CDN proxy)",
                     "Traceable": "Partial — board admin contact only"}),
    ]
    for i in incidents:
        event_id = str(uuid.uuid4())
        DB["incidents"][event_id] = IncidentEvent(id=event_id, **i).model_dump()


seed()

# Real platforms that participate in non-consensual-image hash-matching /
# prevention programs (modeled on how services like StopNCII.org operate).
# These are named because Aegis genuinely integrates with them to block
# uploads — not because they host anything.
PARTNER_PLATFORMS = [
    "Meta (Facebook & Instagram)", "Reddit", "TikTok", "Snapchat",
    "X (Twitter)", "Discord", "Pornhub", "OnlyFans", "Bumble", "Niantic",
]


@app.get("/platforms")
async def get_platforms():
    return {"partners": PARTNER_PLATFORMS}


# ---------------------------------------------------------------------------
# 1. Hashing
# ---------------------------------------------------------------------------

@app.post("/hash")
async def hash_image(file: UploadFile = File(...)):
    contents = await file.read()
    digest = hashlib.sha256(contents).hexdigest()
    return {"filename": file.filename, "sha256": digest}


# ---------------------------------------------------------------------------
# 2. EXIF extraction
# ---------------------------------------------------------------------------

def extract_exif(image_bytes: bytes) -> dict:
    img = Image.open(io.BytesIO(image_bytes))
    raw_exif = img.getexif()
    if not raw_exif:
        return {}
    readable = {}
    for tag_id, value in raw_exif.items():
        tag_name = TAGS.get(tag_id, tag_id)
        if isinstance(value, bytes):
            value = value.decode(errors="ignore")
        readable[str(tag_name)] = value
    return readable


@app.post("/exif")
async def get_exif(file: UploadFile = File(...)):
    contents = await file.read()
    try:
        data = extract_exif(contents)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read image: {e}")
    return {"filename": file.filename, "exif": data}


# ---------------------------------------------------------------------------
# 3. Reverse image search (Google Cloud Vision web detection) — this is what
#    the frontend's "Run a scan" button should ultimately call.
# ---------------------------------------------------------------------------

def run_web_detection(image_bytes: bytes) -> dict:
    from google.cloud import vision  # imported lazily so the API runs without it installed

    client = vision.ImageAnnotatorClient()
    image = vision.Image(content=image_bytes)
    response = client.web_detection(image=image)
    if response.error.message:
        raise RuntimeError(response.error.message)

    web = response.web_detection
    return {
        "full_matches": [m.url for m in web.full_matching_images],
        "partial_matches": [m.url for m in web.partial_matching_images],
        "pages_with_matches": [p.url for p in web.pages_with_matching_images],
        "best_guess_labels": [g.label for g in web.best_guess_labels],
    }


@app.post("/scan")
async def scan_image(file: UploadFile = File(...)):
    """Runs a live reverse-image scan and files each hit as a new takedown
    entry. Requires GOOGLE_APPLICATION_CREDENTIALS to be set with Vision API
    access; otherwise returns 501 so the frontend can fall back to sample data."""
    contents = await file.read()
    sha256 = hashlib.sha256(contents).hexdigest()
    try:
        matches = run_web_detection(contents)
    except ImportError:
        raise HTTPException(status_code=501, detail="google-cloud-vision is not installed/configured on this server.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Vision API error: {e}")

    created = []
    for url in matches["full_matches"] + matches["partial_matches"]:
        entry_id = str(uuid.uuid4())
        entry = TakedownEntry(
            id=entry_id, site=url.split("/")[2] if "//" in url else url,
            site_type="Detected via reverse-image search",
            url=url, detected=now_iso()[:10], progress=30, status=Status.pending,
            abuse_contact="not yet resolved", sent_on="—", log=["Found by automated scan"],
        )
        DB["takedowns"][entry_id] = entry.model_dump()
        created.append(entry.model_dump())

    return {"sha256": sha256, "scanned_at": now_iso(), "new_entries": created, "raw_matches": matches}


# ---------------------------------------------------------------------------
# 4. Incident timeline
# ---------------------------------------------------------------------------

@app.get("/incidents")
async def list_incidents():
    return list(DB["incidents"].values())


# ---------------------------------------------------------------------------
# 5. Takedown dashboard — list, advance status, draft + preview notices
# ---------------------------------------------------------------------------

@app.get("/takedowns")
async def list_takedowns(status: Optional[Status] = None):
    entries = list(DB["takedowns"].values())
    if status:
        entries = [e for e in entries if e["status"] == status]
    return entries


@app.get("/takedowns/stats")
async def takedown_stats():
    entries = list(DB["takedowns"].values())
    return {
        "detected": len(entries),
        "sent": len([e for e in entries if e["status"] == Status.sent]),
        "removed": len([e for e in entries if e["status"] == Status.removed]),
        "pending": len([e for e in entries if e["status"] == Status.pending]),
    }


class RequesterInfo(BaseModel):
    requester_name: str
    requester_email: str
    good_faith_statement: bool = True


def build_dmca_notice(entry: dict, req: RequesterInfo, sha256: str, filename: str) -> str:
    return f"""To Whom It May Concern,

I am writing to notify you, pursuant to the Digital Millennium Copyright Act
(17 U.S.C. § 512), of copyrighted / private material hosted at:

    {entry['url']}

Identifying details of the original file:
    Filename: {filename}
    SHA-256 fingerprint: {sha256}

I have a good faith belief that this content is not authorized by me, the
copyright owner or subject, or the law. I request that you remove or disable
access to this material.

Under penalty of perjury, I confirm the information in this notice is
accurate and that I am authorized to act on behalf of the person depicted.

Sincerely,
{req.requester_name}
{req.requester_email}
{datetime.now(timezone.utc).strftime("%B %d, %Y")}
"""


@app.post("/takedowns/{entry_id}/preview")
async def preview_takedown(entry_id: str, req: RequesterInfo, sha256: str = "", filename: str = "uploaded_image"):
    entry = DB["takedowns"].get(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Takedown entry not found.")
    if not req.good_faith_statement:
        raise HTTPException(status_code=400, detail="Good-faith statement is required.")
    notice = build_dmca_notice(entry, req, sha256, filename)
    return {"entry_id": entry_id, "notice_text": notice}


@app.post("/takedowns/{entry_id}/advance")
async def advance_takedown(entry_id: str):
    """Moves an entry to its next real status: pending -> sent -> removed.
    In production, gate this behind explicit user confirmation — this
    endpoint should fire the actual email/notice, not just flip a label."""
    entry = DB["takedowns"].get(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Takedown entry not found.")

    if entry["status"] == Status.pending:
        entry["status"] = Status.sent
        entry["progress"] = 65
        entry["sent_on"] = now_iso()[:10]
        entry["log"].append(f"Notice sent {entry['sent_on']}")
    elif entry["status"] == Status.sent:
        entry["status"] = Status.removed
        entry["progress"] = 100
        entry["log"].append("Host confirmed removal")
    else:
        raise HTTPException(status_code=400, detail="Entry is already marked removed.")

    return entry


# ---------------------------------------------------------------------------
# 6. Manipulation / deepfake flag — placeholder for a real local model.
# ---------------------------------------------------------------------------

@app.post("/analyze/manipulation")
async def analyze_manipulation(file: UploadFile = File(...)):
    # TODO: replace with a real classifier call, e.g.:
    #   score = deepfake_model.predict(image_tensor)
    return {
        "filename": file.filename,
        "verdict": "unknown",
        "confidence": None,
        "note": "No detection model is wired up yet — this is a placeholder response.",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
