from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from src.api.v1.schemas import UserCreate, UserLogin, UserUpdate, UserModel
from src.services import UserService, get_user_service
from src.models import User

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")


@router.post(
    path="/signup",
    summary="Зарегистрировать пользователя",
    tags=["users"],
)
def register(user: UserCreate,
             user_service: UserService = Depends(get_user_service)):
    if user_service.identification(user):
        raise HTTPException(status_code=400, detail="User with this username already exists.")
    new_user: dict = user_service.create_user(user)
    return {
        "msg": "User created.",
        "user": new_user
    }


@router.post(
    path="/login",
    summary="Авторизовать пользователя",
    tags=["users"],
)
def login(user: UserLogin,
          user_service: UserService = Depends(get_user_service)):
    user: UserModel = user_service.authentication(user)
    access_token = user_service.create_access_token(user)
    refresh_token = user_service.create_refresh_token(user)
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
    user: User = user_service.get_me(token)
    return user.dict()


@router.patch(
    path="/users/me",
    tags=["users"],
    summary="Обновить данные профиля",
)
def update_user(user: UserUpdate,
                token: str = Depends(oauth2_scheme),
                user_service: UserService = Depends(get_user_service)):
    updated_user: User = user_service.update_user(user, token)
    user_service.delete_tokens(updated_user.uuid)
    access_token = user_service.create_access_token(UserModel(**updated_user.dict()))
    return {
        "msg": "Update is successful. Please use new access_token.",
        "user": updated_user.dict(),
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


@router.post(
    path='/logout',
    summary="Разлогиниться",
    tags=['users'],
)
def logout(token: str = Depends(oauth2_scheme),
           user_service: UserService = Depends(get_user_service)):
    if user_service.logout(token):
        return {"msg": "You logged out."}


@router.post(
    path='/logout_all',
    summary="Разлогиниться",
    tags=['users'],
)
def logout_all(token: str = Depends(oauth2_scheme),
               user_service: UserService = Depends(get_user_service)):
    if user_service.logout_all(token):
        return {"msg": "You logged out from all devices."}
