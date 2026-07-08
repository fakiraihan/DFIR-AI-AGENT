"""Authentication endpoints and dependencies."""

from typing import Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator

from modules.auth_store import SESSION_DAYS, auth_store, normalize_username


SESSION_COOKIE_NAME = "dfir_session"

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterPayload(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    email: str = Field(min_length=3, max_length=160)
    password: str = Field(min_length=8, max_length=256)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        return validate_username_value(value)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return validate_email_value(value)


class LoginPayload(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=8, max_length=256)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        return validate_username_value(value)


def validate_username_value(value: str) -> str:
    return normalize_username(value)


def validate_email_value(value: str) -> str:
    cleaned = str(value or "").strip().lower()
    if "@" not in cleaned or "." not in cleaned.rsplit("@", 1)[-1]:
        raise ValueError("Enter a valid email address")
    return cleaned


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_DAYS * 24 * 60 * 60,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


def get_current_user(
    dfir_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict[str, Any]:
    user = auth_store.get_user_for_token(dfir_session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


@router.post("/register")
async def register(payload: RegisterPayload, response: Response):
    try:
        user = auth_store.create_user(
            username=payload.username,
            email=payload.email,
            password=payload.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    token = auth_store.create_auth_session(user["id"])
    set_session_cookie(response, token)
    return {"user": user}


@router.post("/login")
async def login(payload: LoginPayload, response: Response):
    user = auth_store.authenticate_user(
        username=payload.username,
        password=payload.password,
    )
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = auth_store.create_auth_session(user["id"])
    set_session_cookie(response, token)
    return {"user": user}


@router.post("/logout")
async def logout(
    response: Response,
    dfir_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    auth_store.revoke_auth_session(dfir_session or "")
    clear_session_cookie(response)
    return {"logged_out": True}


@router.get("/me")
async def me(current_user: dict[str, Any] = Depends(get_current_user)):
    return {"user": current_user}
