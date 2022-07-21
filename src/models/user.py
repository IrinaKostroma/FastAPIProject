from datetime import datetime

from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):
    uuid: str = Field(nullable=False, primary_key=True)
    username: str = Field(nullable=False)
    email: str = Field(nullable=False)
    password: str = Field(nullable=False)
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)
    is_superuser: bool = Field(default=False)
