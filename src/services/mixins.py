from sqlmodel import Session

from src.db import AbstractCache


class ServiceMixin:
    def __init__(self, cache: AbstractCache, black_list: AbstractCache, session: Session):
        self.cache: AbstractCache = cache
        self.black_list: AbstractCache = black_list
        self.session: Session = session
