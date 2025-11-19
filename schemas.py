"""
Database Schemas for SRH Student Marketplace

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).

Collections:
- user
- listing
- message
"""

from pydantic import BaseModel, Field, HttpUrl, EmailStr
from typing import Optional, List
from datetime import datetime

# ---------- Core Domain Schemas ----------

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Student email address")
    password_hash: str = Field(..., description="Hashed password (bcrypt)")
    avatar_url: Optional[HttpUrl] = Field(None, description="Public URL of avatar image")
    campus: str = Field("Berlin", description="Campus name")
    is_admin: bool = Field(False, description="Admin privileges")
    is_blocked: bool = Field(False, description="Whether the user is blocked")


class Listing(BaseModel):
    user_id: str = Field(..., description="Owner user id (stringified ObjectId)")
    images: List[str] = Field(default_factory=list, description="Array of image URLs")
    title: str
    description: str
    price: float = Field(..., ge=0)
    category: str = Field(..., description="Books|Electronics|Furniture|Clothing|Misc")
    condition: str = Field(..., description="New|Like New|Used|Heavily Used")
    approved: bool = Field(False, description="Visible in marketplace when approved or owner/admin viewing")


class Message(BaseModel):
    listing_id: str
    sender_id: str
    receiver_id: str
    content: str


# ---------- Request/Response DTOs ----------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    avatar_url: Optional[HttpUrl] = None
    campus: Optional[str] = None

class ListingCreate(BaseModel):
    title: str
    description: str
    price: float
    category: str
    condition: str
    images: List[str] = []

class ListingUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    condition: Optional[str] = None
    images: Optional[List[str]] = None

class SendMessageRequest(BaseModel):
    listing_id: str
    to_user_id: str
    content: str

class ApproveListingRequest(BaseModel):
    listing_id: str
    approve: bool = True

class BlockUserRequest(BaseModel):
    user_id: str
    block: bool = True
