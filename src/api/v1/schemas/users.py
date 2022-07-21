from typing import Optional

from datetime import datetime
from pydantic import BaseModel, EmailStr

__all__ = (
    "UserCreate",
    "UserLogin",
    "UserUpdate",
    "UserModel",
)


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserUpdate(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str]
    is_superuser: Optional[bool]


class UserModel(BaseModel):
    uuid: str
    username: str
    email: EmailStr
    created_at: Optional[datetime]
    is_superuser: Optional[bool]
