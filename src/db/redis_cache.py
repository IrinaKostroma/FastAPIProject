from typing import NoReturn, Optional, Union

from src.db import AbstractCache

__all__ = ("CacheRedis",)


class CacheRedis(AbstractCache):
    def get(self, key: str) -> Optional[dict]:
        return self.cache.get(name=key)

    def set(
        self,
        key: str,
        value: Union[bytes, str],
        expire: int,
    ):
        self.cache.set(name=key, value=value, ex=expire)

    def delete(self, key: str,):
        self.cache.delete(key)

    def close(self) -> NoReturn:
        self.cache.close()
