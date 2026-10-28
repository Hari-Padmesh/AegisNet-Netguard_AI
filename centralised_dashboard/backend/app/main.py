from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import re

from bson import ObjectId
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pymongo import AsyncMongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError

from app.config import settings
from app.schemas import IngestEvent, IngestTelemetry, LoginBody, ProjectCreate, SignupBody
from app.security import SESSION_COOKIE, digest, new_ingest_key, new_session, password_hash, session_digest


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.mongo_uri:
        raise RuntimeError("MONGODB_URI is required. Configure backend/.env before starting the API.")
    if len(settings.session_secret) < 32:
        raise RuntimeError("SESSION_SECRET must contain at least 32 characters.")
    if settings.cookie_samesite not in {"lax", "strict", "none"}:
        raise RuntimeError("COOKIE_SAMESITE must be lax, strict, or none.")
    if settings.cookie_samesite == "none" and not settings.cookie_secure:
        raise RuntimeError("COOKIE_SECURE=true is required when COOKIE_SAMESITE=none.")
    client = AsyncMongoClient(settings.mongo_uri, serverSelectionTimeoutMS=8000, tz_aware=True)
    await client.admin.command("ping")
    db = client[settings.mongo_database]
    await db.users.create_index("email", unique=True)
    await db.sessions.create_index("token_hash", unique=True)
    await db.sessions.create_index("expires_at", expireAfterSeconds=0)
    await db.projects.create_index("project_id", unique=True)
    await db.projects.create_index("ingest_key_hash", unique=True)
    await db.projects.create_index([("owner_id", 1), ("created_at", DESCENDING)])
    await db.events.create_index([("project_id", 1), ("received_at", DESCENDING)])
    await db.telemetry.create_index([("project_id", 1), ("received_at", DESCENDING)])
    app.state.mongo_client = client
    app.state.db = db
    try:
        yield
    finally:
        await client.close()


app = FastAPI(title="NetGuard Cloud Dashboard", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def database(request: Request):
    return request.app.state.db


async def current_user(request: Request, db=Depends(database)):
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(status_code=401, detail="Sign in required")
    session = await db.sessions.find_one({"token_hash": session_digest(raw)})
    now = datetime.now(timezone.utc)
    if not session or session["expires_at"] <= now:
        raise HTTPException(status_code=401, detail="Session expired")
    user = await db.users.find_one({"_id": session["user_id"]}, {"password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Account not found")
    return user


def public_user(user: dict) -> dict:
    return {"id": str(user["_id"]), "email": user["email"], "name": user["name"]}


async def set_session(response: Response, db, user_id: ObjectId) -> None:
    raw, expires = new_session()
    await db.sessions.insert_one({
        "token_hash": session_digest(raw), "user_id": user_id, "created_at": datetime.now(timezone.utc),
        "expires_at": expires,
    })
    response.set_cookie(
        SESSION_COOKIE, raw, httponly=True, secure=settings.cookie_secure,
        samesite=settings.cookie_samesite, max_age=settings.session_days * 86400, path="/",
    )


@app.get("/api/health")
async def health(db=Depends(database)):
    await db.command("ping")
    return {"status": "ok", "database": "connected"}


@app.get("/api/meta")
async def metadata():
    return {"public_api_url": settings.public_api_url}


@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
async def signup(body: SignupBody, response: Response, db=Depends(database)):
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="Name cannot be blank")
    user = {
        "email": body.email.lower().strip(), "name": body.name.strip(),
        "password_hash": password_hash.hash(body.password), "created_at": datetime.now(timezone.utc),
    }
    try:
        result = await db.users.insert_one(user)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail="An account with this email already exists") from exc
    user["_id"] = result.inserted_id
    await set_session(response, db, result.inserted_id)
    return {"user": public_user(user)}


@app.post("/api/auth/login")
async def login(body: LoginBody, response: Response, db=Depends(database)):
    user = await db.users.find_one({"email": body.email.lower().strip()})
    if not user or not password_hash.verify(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    await set_session(response, db, user["_id"])
    return {"user": public_user(user)}


@app.post("/api/auth/logout", status_code=204)
async def logout(request: Request, response: Response, db=Depends(database)):
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        await db.sessions.delete_one({"token_hash": session_digest(raw)})
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=settings.cookie_secure, samesite=settings.cookie_samesite)


@app.get("/api/auth/me")
async def me(user=Depends(current_user)):
    return {"user": public_user(user)}


@app.get("/api/projects")
async def list_projects(user=Depends(current_user), db=Depends(database)):
    cursor = db.projects.find({"owner_id": user["_id"]}).sort("created_at", DESCENDING)
    projects = []
    async for project in cursor:
        projects.append(project_summary(project))
    return {"projects": projects}


def project_summary(project: dict) -> dict:
    last_seen = project.get("last_seen")
    return {
        "project_id": project["project_id"], "name": project["name"],
        "framework": project["framework"], "created_at": project["created_at"],
        "last_seen": last_seen, "last_stats": project.get("last_stats", {}),
        "status": freshness(last_seen),
    }


def freshness(last_seen: datetime | None) -> str:
    if not last_seen:
        return "waiting_for_data"
    age = (datetime.now(timezone.utc) - last_seen).total_seconds()
    return "online" if age <= 120 else "stale"


@app.post("/api/projects", status_code=201)
async def create_project(body: ProjectCreate, user=Depends(current_user), db=Depends(database)):
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="Project name cannot be blank")
    if body.framework.strip().lower() != "fastapi":
        raise HTTPException(status_code=400, detail="The MVP currently supports FastAPI projects")
    import secrets

    project_id = "ngp_" + secrets.token_urlsafe(12)
    ingest_key = new_ingest_key()
    project = {
        "project_id": project_id, "owner_id": user["_id"], "name": body.name.strip(),
        "framework": "FastAPI", "ingest_key_hash": digest(ingest_key),
        "created_at": datetime.now(timezone.utc), "last_seen": None, "last_stats": {},
    }
    await db.projects.insert_one(project)
    return {"project": project_summary(project), "ingest_key": ingest_key}


async def owned_project(project_id: str, owner_id: ObjectId, db):
    project = await db.projects.find_one({"project_id": project_id, "owner_id": owner_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@app.get("/api/projects/{project_id}/overview")
async def project_overview(project_id: str, user=Depends(current_user), db=Depends(database)):
    project = await owned_project(project_id, user["_id"], db)
    latest = await db.telemetry.find_one({"project_id": project_id}, sort=[("received_at", DESCENDING)])
    if latest:
        latest["id"] = str(latest.pop("_id"))
        latest.pop("owner_id", None)
    events = await db.events.find({"project_id": project_id}).sort("received_at", DESCENDING).limit(100).to_list(100)
    for event in events:
        event["id"] = str(event.pop("_id"))
        event.pop("owner_id", None)
    return {"project": project_summary(project), "latest_telemetry": latest, "events": events}


@app.get("/api/projects/{project_id}/events")
async def project_events(project_id: str, limit: int = 100, user=Depends(current_user), db=Depends(database)):
    await owned_project(project_id, user["_id"], db)
    limit = max(1, min(limit, 500))
    events = await db.events.find({"project_id": project_id}).sort("received_at", DESCENDING).limit(limit).to_list(limit)
    for event in events:
        event["id"] = str(event.pop("_id"))
        event.pop("owner_id", None)
    return {"events": events}


@app.post("/api/projects/{project_id}/rotate-key")
async def rotate_project_key(project_id: str, user=Depends(current_user), db=Depends(database)):
    await owned_project(project_id, user["_id"], db)
    key = new_ingest_key()
    await db.projects.update_one({"project_id": project_id, "owner_id": user["_id"]}, {"$set": {"ingest_key_hash": digest(key)}})
    return {"ingest_key": key}


@app.delete("/api/projects/{project_id}", status_code=204)
async def delete_project(project_id: str, user=Depends(current_user), db=Depends(database)):
    await owned_project(project_id, user["_id"], db)
    await db.projects.delete_one({"project_id": project_id, "owner_id": user["_id"]})
    await db.events.delete_many({"project_id": project_id})
    await db.telemetry.delete_many({"project_id": project_id})


async def ingest_project(authorization: str | None, payload_project_id: str, db):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Project bearer key required")
    key_hash = digest(authorization[7:].strip())
    project = await db.projects.find_one({"ingest_key_hash": key_hash})
    if not project:
        raise HTTPException(status_code=401, detail="Invalid project key")
    if payload_project_id != project["project_id"]:
        raise HTTPException(status_code=403, detail="Project ID does not match this key")
    return project


@app.post("/api/ingest/events", status_code=202)
@app.post("/api/events", status_code=202, include_in_schema=False)
async def ingest_event(payload: IngestEvent, authorization: str | None = Header(default=None), db=Depends(database)):
    project = await ingest_project(authorization, payload.project_id, db)
    now = datetime.now(timezone.utc)
    document = payload.model_dump(include={
        "project_id", "timestamp", "severity", "label", "confidence", "client_ip",
        "path", "method", "rule_id", "flow_summary", "detection_source",
    })
    # The current SDK Alert payload includes the originating IP/path in its
    # human-readable flow_summary. Normalize those values for dashboard filters.
    summary = document.get("flow_summary") or ""
    match = re.match(r"^HTTP\s+(\S+)\s+(.*)$", summary)
    if match:
        client_ip, remainder = match.groups()
        if client_ip != "->" and not document.get("client_ip"):
            document["client_ip"] = client_ip
        path_match = re.search(r"(?:\bpath=|^)(/\S*)", remainder)
        if path_match and not document.get("path"):
            document["path"] = path_match.group(1)
        elif " | rule=" in remainder and not document.get("path"):
            document["path"] = remainder.split(" | rule=", 1)[0].strip()
        rule_match = re.search(r"\brule=([^\s|]+)", remainder)
        if rule_match and not document.get("rule_id"):
            document["rule_id"] = rule_match.group(1)
    document.update({"owner_id": project["owner_id"], "received_at": now})
    await db.events.insert_one(document)
    await db.projects.update_one({"_id": project["_id"]}, {"$set": {"last_seen": now}})
    return {"accepted": True}


@app.post("/api/ingest/telemetry", status_code=202)
@app.post("/api/telemetry", status_code=202, include_in_schema=False)
async def ingest_telemetry(payload: IngestTelemetry, authorization: str | None = Header(default=None), db=Depends(database)):
    project = await ingest_project(authorization, payload.project_id, db)
    now = datetime.now(timezone.utc)
    document = {"project_id": project["project_id"], "owner_id": project["owner_id"], "stats": payload.stats, "received_at": now}
    await db.telemetry.insert_one(document)
    await db.projects.update_one({"_id": project["_id"]}, {"$set": {"last_seen": now, "last_stats": payload.stats}})
    return {"accepted": True}
