from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
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
from database.models.accounts import UserProfileModel
from exceptions import BaseSecurityError
from routes.accounts_crud import get_user, get_activation_token
from security.interfaces import JWTAuthManagerInterface
from  security.passwords import hash_password
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema, MessageResponseSchema,
    UserActivationRequestSchema,
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

    user_orm = await get_user(email=user.email, db=db)
    if user_orm:
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
        user_profile = UserProfileModel(user_id=db_user.id)
        activation_token = ActivationTokenModel(user_id=db_user.id)

        db.add(activation_token)
        db.add(user_profile)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    return db_user

@router.post("/activate/",
    response_model=MessageResponseSchema,
    status_code=200,
    summary="Account actvation",
    description=(
            "<h3>This endpoint retrieves the activation token and verifies its validity</h3>"
    ),
    responses={
        200: {
            "description": "User account activated successfully.",
        },
        400: {
            "description": "Case_1. Token is invalid or expired. "
                           "Case_2. User's account is already active",
            "content": {
                "application/json": {
                    "example": {
                        "case_1": {"detail": "Invalid or expired activation token."},
                        "case_2": {"detail": "User account is already active."}
                    }
                }
            },
        },
        404: {
            "description": "User not found.",
            "content": {
                "application/json": {
                    "example": {"detail": "User with email example@email.com not found."}
                }
            }
        }
    }
)
async def activate(
        request_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_db = await get_user(email=request_data.email, db=db)

    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {request_data.email} not found."
        )
    if user_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    activation_token = await get_activation_token(user=user_db, db=db)
    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    expires_at = (cast(datetime, activation_token.expires_at).
                  replace(tzinfo=timezone.utc))
    if (
            activation_token.token != request_data.token
            or expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    user_db.is_active = True
    await db.delete(activation_token)
    await db.commit()
    await db.refresh(user_db)
    return MessageResponseSchema(
        message="User account activated successfully."
    )

