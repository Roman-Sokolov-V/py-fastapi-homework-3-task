from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, exists
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from  security.passwords import hash_password
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
)




router = APIRouter()

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
    summary="Register a new user",
    description=(
            "<h3>This endpoint register user by email and password. "
            "It add user in default user_group 'USER' and create"
            "activation token.</h3>"
    ),
    responses={
        201: {
            "description": "User registered successfully.",
        },
        409: {
            "description": "A user with the same email already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email test@example.com already exists."}
                }
            },
        },
        422: {
            "description": "Invalid input.",
            "content": {
                "application/json": {
                    "example": {"detail": "Password must contain at least 8 characters."}
                }
            }
        },
        500: {
            "description": "An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            }
        }
    }
)
async def register(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == user.email)
    is_user_exists = (await db.execute(stmt)).scalar_one_or_none()
    if is_user_exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )
    hashed_password = hash_password(user.password)
    user_dict = user.model_dump()
    user_dict["password"] = hashed_password
    group_id_stmt = select(UserGroupModel.id).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    group_id = (await db.execute(group_id_stmt)).scalar_one_or_none()

    user_dict["group_id"] = group_id
    db_user = UserModel(**user_dict)
    db.add(db_user)
    try:
        await db.flush()
        await db.refresh(db_user)
        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    return db_user


