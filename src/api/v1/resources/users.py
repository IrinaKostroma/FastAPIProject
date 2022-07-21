from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from src.api.v1.schemas import UserCreate, UserLogin, UserUpdate, UserModel
from src.services import UserService, get_user_service

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")


@router.post(
    path="/signup",
    summary="Зарегистрировать пользователя",
    tags=["users"],
)
def register(user: UserCreate,
             user_service: UserService = Depends(get_user_service)):
    if user_service.get_user_by_username(user):
        raise HTTPException(status_code=400, detail="User with this username already exists.")
    user: dict = user_service.create_user(user)
    return {
        "msg": "User created.",
        "user": user
    }


@router.post(
    path="/login",
    summary="Авторизовать пользователя",
    tags=["users"],
)
def login(user: UserLogin,
          user_service: UserService = Depends(get_user_service)):
    user: UserModel = user_service.authenticate_user(user)
    access_token, refresh_token = user_service.generate_tokens(user)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@router.get(
    path="/users/me",
    tags=["users"],
    summary="Посмотреть профиль",
)
def get_user_me(token: str = Depends(oauth2_scheme),
                user_service: UserService = Depends(get_user_service)):
    user = user_service.get_user_by_token(token)
    return user.dict()


@router.patch(
    path="/users/me",
    tags=["users"],
    summary="Обновить данные профиля",
)
def update_user(user: UserUpdate,
                token: str = Depends(oauth2_scheme),
                user_service: UserService = Depends(get_user_service)):
    updated_user, access_token = user_service.update_user(user, token)
    return {
        "msg": "Update is successful. Please use new access_token.",
        "user": updated_user,
        "access_token": access_token
    }


@router.post(
    path="/refresh",
    summary="Обновить токены",
    tags=["users"],
)
def refresh(token: str = Depends(oauth2_scheme),
            user_service: UserService = Depends(get_user_service)):
    access_token, refresh_token = user_service.refresh_tokens(token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
