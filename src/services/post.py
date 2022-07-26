import jwt
import json

from http import HTTPStatus
from functools import lru_cache
from typing import Optional
from fastapi import Depends, HTTPException
from sqlmodel import Session

from src.api.v1.schemas import PostCreate, PostModel
from src.db import AbstractCache, get_cache, get_black_list, get_session
from src.core.config import *
from src.models import Post
from src.services import ServiceMixin

__all__ = ("PostService", "get_post_service")


class PostService(ServiceMixin):
    def get_post_list(self) -> dict:
        """Получить список постов."""
        posts = self.session.query(Post).order_by(Post.created_at).all()
        return {"posts": [PostModel(**post.dict()) for post in posts]}

    def get_post_detail(self, item_id: int) -> Optional[dict]:
        """Получить детальную информацию поста."""
        if cached_post := self.cache.get(key=f"{item_id}"):
            return json.loads(cached_post)

        post = self.session.query(Post).filter(Post.id == item_id).first()
        if post:
            self.cache.set(key=f"{post.id}", value=post.json(), expire=CACHE_EXPIRE_DAYS)
        return post.dict() if post else None

    def create_post(self, post: PostCreate) -> dict:
        """Создать пост."""
        new_post = Post(title=post.title, description=post.description)
        self.session.add(new_post)
        self.session.commit()
        self.session.refresh(new_post)
        return new_post.dict()

    def _is_valid(self, token: str) -> bool:
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
                return True
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="Invalid token.")


# get_post_service — это провайдер PostService. Синглтон
@lru_cache()
def get_post_service(
    cache: AbstractCache = Depends(get_cache),
    black_list: AbstractCache = Depends(get_black_list),
    session: Session = Depends(get_session),
) -> PostService:
    return PostService(cache=cache, black_list=black_list, session=session)
