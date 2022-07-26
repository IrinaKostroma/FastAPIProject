import jwt
import hashlib

from datetime import datetime, timedelta
from http import HTTPStatus
from fastapi import Depends, HTTPException
from functools import lru_cache
from sqlmodel import Session
from typing import Optional
from uuid import uuid4

from src.api.v1.schemas import UserCreate, UserLogin, UserUpdate, UserModel
from src.core.config import *
from src.db import AbstractCache, get_cache, get_black_list, get_session
from src.models import User
from src.services import ServiceMixin

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def identification(self, user: UserCreate) -> User:
        """Идентификация пользователя по имени"""
        return self.get_user_by_username(user.username)

    def create_user(self, user: UserCreate) -> dict:
        """Создать(зарегистрировать) пльзователя"""
        password = hashlib.sha256(user.password.encode()).hexdigest()
        uuid = str(uuid4())
        new_user = User(uuid=uuid, username=user.username, email=user.email, password=password)
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        return new_user.dict()

    def authentication(self, user: UserLogin) -> Optional[UserModel]:
        """Аутентификация пользователя (имя-пароль)"""
        _user = self.get_user_by_username(user.username)
        if not _user:
            raise HTTPException(status_code=400, detail="User with this username doesn't exist.")
        if _user.password != hashlib.sha256(user.password.encode()).hexdigest():
            raise HTTPException(status_code=400, detail="Incorrect password.")
        return UserModel(**_user.dict())

    def get_user_by_username(self, username: str) -> Optional[User]:
        return self.session.query(User).filter(User.username == username).first()

    def get_user_by_uuid(self, uuid) -> Optional[User]:
        return self.session.query(User).filter(User.uuid == uuid).first()

    def create_refresh_token(self, user: UserModel) -> str:
        """Создать refresh_token"""
        refresh_jti = str(uuid4())
        exp_time = int(datetime.timestamp(datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)))
        payload = {
            "user_uuid": user.uuid,
            "exp": exp_time,
            "jti": refresh_jti,
            "type": "refresh"
        }
        refresh_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        # self.cache.set(key=f'{user.uuid}refresh', value=refresh_token, expire=exp_time)
        self.cache.set(key=f'{user.uuid}refresh', value=refresh_jti, expire=exp_time)

        return refresh_token

    def create_access_token(self, user: UserModel) -> str:
        """Создать access_token"""
        access_jti = str(uuid4())
        exp_time = int(datetime.timestamp(datetime.now() + timedelta(days=ACCESS_TOKEN_EXPIRE_MINUTES)))
        payload = {
            "username": user.username,
            "user_uuid": user.uuid,
            "jti": access_jti,
            "exp": exp_time,
            "refresh_uuid": access_jti,
            "type": "access",
            "created_at": user.created_at.strftime("%a %b %d %H:%M:%S %Y")
        }
        access_token = jwt.encode(payload, JWT_SECRET_KEY, JWT_ALGORITHM)
        # self.cache.set(key=f'{user.uuid}access', value=access_token, expire=exp_time)
        # self.cache.set(key=access_token, value=f'{user.uuid}', expire=exp_time)
        self.cache.set(key=f'{user.uuid}access', value=access_jti, expire=exp_time)
        self.cache.set(key=access_jti, value=f'{user.uuid}', expire=exp_time)

        return access_token

    def get_me(self, token: str) -> User:
        """Получить информацию о пользователе"""
        type_token, user_uuid = self._is_valid(token)
        if type_token != 'access':
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Take access token.")
        user: User = self.get_user_by_uuid(user_uuid)
        if not user:
            raise HTTPException(status_code=400, detail="User with this username doesn't exist.")
        return user

    def _is_valid(self, token: str) -> tuple:
        """"Проверить валидность access токена"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, JWT_ALGORITHM)
            type_token = payload.get("type")
            user_uuid = payload.get("user_uuid")
            jti = payload.get("jti")
        except Exception:
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Invalid token.")
        if user_uuid is None or type_token is None:
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Invalid token.")
        # access и refresh токенам было установлено время жизни
        # Redis автоматически удаляет "протухшие" ключи
        if jti_cached_token := self.cache.get(user_uuid + type_token):
            if jti_cached_token.decode() == jti:
                return type_token, user_uuid
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="Invalid token.")

    def update_user(self, new_data: UserUpdate, token: str) -> User:
        """"Обновить данные пользователя"""
        user = self.get_me(token)
        for key, value in new_data.dict().items():
            if value is not None:
                setattr(user, key, value)
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def delete_tokens(self, user_uuid) -> None:
        """Удалить ассеss_token"""
        if jti_cached_token := self.cache.get(key=f"{user_uuid}access"):
            self.cache.delete(key=f"{user_uuid}access")
            self.cache.delete(key=jti_cached_token)
        """Добавить в black_list"""
        self.black_list.set(key=jti_cached_token, value=f'{user_uuid}', expire=CACHE_EXPIRE_DAYS)

    def refresh_tokens(self, token: str) -> Optional[tuple]:
        """Обновить токены по refresh_token"""
        type_token, user_uuid = self._is_valid(token)
        if type_token != 'refresh':
            raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                                detail="Take refresh token.")
        user = self.get_user_by_uuid(user_uuid)
        if not user:
            raise HTTPException(status_code=400, detail="User with this username doesn't exist.")

        access_token = self.create_access_token(UserModel(**user.dict()))
        refresh_token = self.create_refresh_token(UserModel(**user.dict()))

        return access_token, refresh_token

    def logout(self, token: str) -> bool:
        """Разлогиниться"""
        type_token, user_uuid = self._is_valid(token)
        # Удалить ассеss_token
        self.delete_tokens(user_uuid)
        return True

    def logout_all(self, token: str) -> bool:
        """Выйти со всех устройств"""
        type_token, user_uuid = self._is_valid(token)
        # Удалить ассеss_token
        self.delete_tokens(user_uuid)
        # Удалить refresh_token
        self.cache.delete(key=f"{user_uuid}refresh")
        return True


# get_post_service — это провайдер UserService. Синглтон
@lru_cache()
def get_user_service(
    cache: AbstractCache = Depends(get_cache),
    black_list: AbstractCache = Depends(get_black_list),
    session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache, black_list=black_list, session=session)
