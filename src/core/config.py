import os
from pathlib import Path

VERSION: str = "1.0.0"

# JWT SETTINGS
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "SmallSecret")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")

# TOKEN SETTINGS
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 2)
REFRESH_TOKEN_EXPIRE_DAYS = os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 1)
CACHE_EXPIRE_DAYS = os.getenv("CACHE_EXPIRE_DAYS", 100)

# Название проекта. Используется в Swagger-документации
PROJECT_NAME: str = os.getenv("PROJECT_NAME", "ylab_hw_3")

# Настройки Redis
REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
CACHE_EXPIRE_IN_SECONDS: int = 60 * 5  # 5 минут

# Настройки Postgres
POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", 5432))
POSTGRES_DB: str = os.getenv("POSTGRES_DB", "ylab_hw")
POSTGRES_USER: str = os.getenv("POSTGRES_USER", "ylab_hw")
POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "ylab_hw")

DATABASE_URL: str = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# Корень проекта
BASE_DIR = Path(__file__).resolve().parent.parent
