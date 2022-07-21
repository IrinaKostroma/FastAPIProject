from fastapi import FastAPI

import redis

from src.api.v1.resources import posts, user_endpoints
from src.core import config
from src.db import cache, redis_cache

import uvicorn


app = FastAPI(
    # Конфигурируем название проекта. Оно будет отображаться в документации
    title=config.PROJECT_NAME,
    version=config.VERSION,
    # Адрес документации в красивом интерфейсе
    docs_url="/api/openapi",
    redoc_url="/api/redoc",
    # Адрес документации в формате OpenAPI
    openapi_url="/api/openapi.json",
)


@app.get("/")
def root():
    return {"service": config.PROJECT_NAME, "version": config.VERSION}


@app.on_event("startup")
def startup():
    """Подключаемся к базам при старте сервера"""
    cache.cache = redis_cache.CacheRedis(
        cache_instance=redis.Redis(
            host=config.REDIS_HOST, port=config.REDIS_PORT, db=0, max_connections=10
        )
    )
    cache.blocked_access_cache = redis_cache.CacheRedis(
        redis.Redis(
            host=config.REDIS_HOST, port=config.REDIS_PORT, db=1, decode_responses=True
        )
    )
    cache.active_refresh_cache = redis_cache.CacheRedis(
        redis.Redis(
            host=config.REDIS_HOST, port=config.REDIS_PORT, db=2, decode_responses=True
        )
    )


@app.on_event("shutdown")
def shutdown():
    """Отключаемся от баз при выключении сервера"""
    cache.cache.close()
    cache.blocked_access_cache.close()
    cache.active_refresh_cache.close()


# Подключаем роутеры к серверу
app.include_router(router=posts.router, prefix="/api/v1/posts")
app.include_router(router=user_endpoints.user_router, prefix="/api/v1")

if __name__ == "__main__":
    # Приложение может запускаться командой
    # `uvicorn main:app --host 0.0.0.0 --port 8000`
    # но чтобы не терять возможность использовать дебагер,
    # запустим uvicorn сервер через python
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
    )