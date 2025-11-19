import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import (
    User, Listing, Message,
    RegisterRequest, LoginRequest, ProfileUpdate,
    ListingCreate, ListingUpdate, SendMessageRequest,
    ApproveListingRequest, BlockUserRequest,
)

app = FastAPI(title="SRH Student Marketplace API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Auth setup ----------
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TTL_MIN = int(os.getenv("ACCESS_TTL_MIN", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TTL_MIN))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def current_user(payload: dict = Depends(verify_token)):
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user or user.get("is_blocked"):
        raise HTTPException(status_code=403, detail="User not found or blocked")
    user["_id"] = str(user["_id"])  # stringify
    return user


def admin_user(user=Depends(current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


# ---------- Public routes ----------
@app.get("/")
def health():
    return {"status": "ok", "service": "srh-marketplace"}


@app.post("/auth/register")
def register(payload: RegisterRequest):
    email = payload.email.lower().strip()
    if db["user"].find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    if not email.endswith("@srh.de"):
        # allow but mark non-verified domain
        pass
    password_hash = pwd_context.hash(payload.password)
    user = User(
        name=payload.name,
        email=email,
        password_hash=password_hash,
        avatar_url=None,
        campus="Berlin",
        is_admin=False,
        is_blocked=False,
    )
    user_id = create_document("user", user)
    access = create_access_token({"sub": user_id})
    return {"token": access, "user": {"_id": user_id, "name": user.name, "email": user.email, "campus": user.campus}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    email = payload.email.lower().strip()
    user = db["user"].find_one({"email": email})
    if not user or not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("is_blocked"):
        raise HTTPException(status_code=403, detail="Account is blocked")
    access = create_access_token({"sub": str(user["_id"])})
    user["_id"] = str(user["_id"])  # stringify
    # remove sensitive
    user.pop("password_hash", None)
    return {"token": access, "user": user}


# ---------- Profile ----------
@app.get("/me")
def me(user=Depends(current_user)):
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    return safe


@app.patch("/me")
def update_me(data: ProfileUpdate, user=Depends(current_user)):
    update = {k: v for k, v in data.model_dump(exclude_none=True).items()}
    if not update:
        return {"updated": False}
    update["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$set": update})
    updated = db["user"].find_one({"_id": ObjectId(user["_id"])})
    updated["_id"] = str(updated["_id"])  # stringify
    updated.pop("password_hash", None)
    return updated


# ---------- Listings ----------
@app.post("/listings")
def create_listing(data: ListingCreate, user=Depends(current_user)):
    listing = Listing(
        user_id=user["_id"],
        title=data.title,
        description=data.description,
        price=data.price,
        category=data.category,
        condition=data.condition,
        images=data.images or [],
        approved=False,
    )
    listing_id = create_document("listing", listing)
    return {"_id": listing_id}


@app.get("/listings")
def list_listings(q: Optional[str] = None, category: Optional[str] = None, condition: Optional[str] = None, sort: Optional[str] = None, limit: int = 50, user=Depends(current_user)):
    f = {"approved": True}
    if q:
        f["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]
    if category:
        f["category"] = category
    if condition:
        f["condition"] = condition

    cursor = db["listing"].find(f)
    if sort == "price_asc":
        cursor = cursor.sort("price", 1)
    elif sort == "price_desc":
        cursor = cursor.sort("price", -1)
    elif sort == "newest":
        cursor = cursor.sort("created_at", -1)

    cursor = cursor.limit(min(limit, 100))
    items = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])  # stringify
        items.append(doc)
    return items


@app.get("/listings/mine")
def my_listings(user=Depends(current_user)):
    cursor = db["listing"].find({"user_id": user["_id"]}).sort("created_at", -1)
    items = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])  # stringify
        items.append(doc)
    return items


@app.patch("/listings/{listing_id}")
def update_listing(listing_id: str, data: ListingUpdate, user=Depends(current_user)):
    doc = db["listing"].find_one({"_id": ObjectId(listing_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Listing not found")
    if doc.get("user_id") != user["_id"] and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Not permitted")
    update = {k: v for k, v in data.model_dump(exclude_none=True).items()}
    update["updated_at"] = datetime.now(timezone.utc)
    db["listing"].update_one({"_id": ObjectId(listing_id)}, {"$set": update})
    new_doc = db["listing"].find_one({"_id": ObjectId(listing_id)})
    new_doc["_id"] = str(new_doc["_id"])  # stringify
    return new_doc


@app.delete("/listings/{listing_id}")
def delete_listing(listing_id: str, user=Depends(current_user)):
    doc = db["listing"].find_one({"_id": ObjectId(listing_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Listing not found")
    if doc.get("user_id") != user["_id"] and not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Not permitted")
    db["listing"].delete_one({"_id": ObjectId(listing_id)})
    return {"deleted": True}


# ---------- Messaging ----------
@app.post("/messages")
def send_message(data: SendMessageRequest, user=Depends(current_user)):
    # validate listing exists
    listing = db["listing"].find_one({"_id": ObjectId(data.listing_id)})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    msg = Message(
        listing_id=data.listing_id,
        sender_id=user["_id"],
        receiver_id=data.to_user_id,
        content=data.content,
    )
    msg_id = create_document("message", msg)
    return {"_id": msg_id}


@app.get("/messages/thread/{listing_id}")
def get_thread(listing_id: str, with_user: Optional[str] = None, user=Depends(current_user)):
    f = {"listing_id": listing_id, "$or": [{"sender_id": user["_id"]}, {"receiver_id": user["_id"]}]}
    if with_user:
        f["$and"] = [{"$or": [{"sender_id": user["_id"]}, {"receiver_id": user["_id"]}]}, {"$or": [{"sender_id": with_user}, {"receiver_id": with_user}]}]
    cursor = db["message"].find(f).sort("created_at", 1)
    out = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])  # stringify
        out.append(doc)
    return out


# ---------- Admin ----------
@app.post("/admin/listings/approve")
def approve_listing(data: ApproveListingRequest, _admin=Depends(admin_user)):
    db["listing"].update_one({"_id": ObjectId(data.listing_id)}, {"$set": {"approved": data.approve, "updated_at": datetime.now(timezone.utc)}})
    doc = db["listing"].find_one({"_id": ObjectId(data.listing_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Listing not found")
    doc["_id"] = str(doc["_id"])  # stringify
    return doc


@app.post("/admin/users/block")
def block_user(data: BlockUserRequest, _admin=Depends(admin_user)):
    db["user"].update_one({"_id": ObjectId(data.user_id)}, {"$set": {"is_blocked": data.block, "updated_at": datetime.now(timezone.utc)}})
    u = db["user"].find_one({"_id": ObjectId(data.user_id)})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["_id"] = str(u["_id"])  # stringify
    u.pop("password_hash", None)
    return u


# ---------- Utilities ----------
@app.get("/test")
def test_database():
    resp = {"backend": "ok", "db": "not configured"}
    try:
        if db is not None:
            resp["db"] = "connected"
            resp["collections"] = db.list_collection_names()
    except Exception as e:
        resp["db_error"] = str(e)
    return resp


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
