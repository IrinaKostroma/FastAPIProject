import json
import jwt
import hashlib

from datetime import datetime, timedelta
from http import HTTPStatus
from fastapi import Depends, HTTPException
from functools import lru_cache
from sqlmodel import Session
from typing import Optional, Union
from uuid import uuid4

from src.api.v1.schemas import UserCreate, UserLogin, UserUpdate, UserModel
from src.core.config import JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from src.db import AbstractCache, get_cache, get_session
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def create_user(self, user: UserCreate) -> dict:
        """Создать(зарегистрировать) пльзователя."""
        password = hashlib.sha256(user.password.encode()).hexdigest()
        uuid = str(uuid4())
        new_user = User(uuid=uuid, username=user.username, email=user.email, password=password)
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        self.cache.set(key=f"{new_user.uuid}", value=new_user.json())
        return new_user.dict()

    def get_user_by_username(self, user: Union[UserLogin, UserCreate]) -> Optional[User]:
        return self.session.query(User).filter(User.username == user.username).first()

    def authenticate_user(self, user: UserLogin) -> Optional[UserModel]:
        """Аутентификация пользователя (имя-пароль)"""
        _user = self.get_user_by_username(user)
        if not _user:
            raise HTTPException(status_code=400, detail="User with this username doesn't exist.")
        if _user.password != hashlib.sha256(user.password.encode()).hexdigest():
            raise HTTPException(status_code=400, detail="Incorrect password.")
        return UserModel(**_user.dict())

    @staticmethod
    def generate_tokens(user: UserModel) -> tuple:
        """Генерация access и refresh токена"""
        refresh_jti = str(uuid4())
        exp_time = int(datetime.timestamp(datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)))
        payload = {
            "user_uuid": user.uuid,
            "exp": exp_time,
            "jti": refresh_jti,
            "type": "refresh"
        }
        refresh_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        # self.refresh_cache.add(user.uuid, jti)

        access_jti = str(uuid4())
        exp_time = int(datetime.timestamp(datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)))
        payload = {
            "username": user.username,
            "email": user.email,
            "user_uuid": user.uuid,
            "jti": access_jti,
            "exp": exp_time,
            "refresh_uuid": refresh_jti,
            "type": "access",
            # TODO одинаковый формат времени при создании и здесь ?
            "created_at": user.created_at.strftime("%a %b %d %H:%M:%S %Y")
        }
        access_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        return access_token, refresh_token

    @staticmethod
    def _is_valid(token: str) -> bool:
        """"Проверить валидность access токена"""
        payload = jwt.decode(token, JWT_SECRET_KEY, JWT_ALGORITHM)
        access_jti = payload.get("jti")
        refresh_jti = payload.get("refresh_uuid")
        user_uuid = payload.get("user_uuid")
        exp_time = payload.get("exp")
        if exp_time and exp_time > int(datetime.timestamp(datetime.now())):
            if access_jti and refresh_jti and user_uuid:
                return True
        else:
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Please refresh access_token.")

    def get_user_by_token(self, token: str) -> User:
        """Получить информацию о владельце указанного токена."""
        user = None
        if self._is_valid(token):
            payload = jwt.decode(token, JWT_SECRET_KEY, JWT_ALGORITHM)
            user_uuid = payload.get("user_uuid")
            if cached_user := self.cache.get(key=f"{user_uuid}"):
                return json.loads(cached_user)
            user = self.session.query(User).filter(User.uuid == user_uuid).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        self.cache.set(key=f"{user.user_uuid}", value=user.json())
        return user

    def update_user(self, user: UserUpdate, token: str) -> tuple:
        user_by_token = self.get_user_by_token(token) if self._is_valid(token) else None
        for key, value in user.dict(exclude_unset=True).items():
            setattr(user_by_token, key, value)
        self.session.add(user_by_token)
        self.session.commit()
        self.session.refresh(user_by_token)
        # TODO добавить пользователя в кеш
        access_token, refresh_token = self.generate_tokens(user=UserModel(*user_by_token))
        # TODO удалить старые токены и добавить новые
        return user_by_token, access_token, refresh_token

    def refresh_tokens(self, token: str) -> Optional[tuple]:
        """Обновить токены по refresh token"""
        payload = jwt.decode(token, JWT_SECRET_KEY, JWT_ALGORITHM)
        type_token = payload.get("type")
        if type_token != "refresh":
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Please refresh access_token.")
        exp_time = payload.get("exp")
        if exp_time and exp_time < int(datetime.timestamp(datetime.now())):
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Please refresh access_token.")
        user_uuid = payload.get("user_uuid")
        user = self.session.query(User).filter(User.uuid == user_uuid).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found.")
        access_token, refresh_token = self.generate_tokens(UserModel(**user.dict()))
        return access_token, refresh_token


# get_post_service — это провайдер UserService. Синглтон
@lru_cache()
def get_user_service(
    cache: AbstractCache = Depends(get_cache),
    session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache, session=session)
