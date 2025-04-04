from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager
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

from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema, MessageResponseSchema,
    UserActivationRequestSchema, PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema, UserLoginResponseSchema,
    UserLoginRequestSchema, TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
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
                    "example": {
                        "detail": "A user with this email test@example.com already exists."}
                }
            },
        },
        422: {
            "description": "Invalid input.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Password must contain at least 8 characters."}
                }
            }
        },
        500: {
            "description": "An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred during user creation."}
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
    user_dict = user.model_dump()
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
                                 "case_1": {
                                     "detail": "Invalid or expired activation token."},
                                 "case_2": {
                                     "detail": "User account is already active."}
                             }
                         }
                     },
                 },
                 404: {
                     "description": "User not found.",
                     "content": {
                         "application/json": {
                             "example": {
                                 "detail": "User with email example@email.com not found."}
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


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200,
    summary="Account actvation",
    description=(
            "<h3>This endpoint is deletes reset_token and generate a new one</h3>"
    ),
    responses={
        200: {
            "description": "To prevent information leaks, the endpoint always"
                           " responds with the same success message, regardless"
                           " of whether the user exists or is active.",
            "content": {
                "application/json": {
                    "example": {
                        "message": "If you are registered, you will receive an email with instructions."}
                }
            }
        }
    }
)
async def password_reset_token(
        reset_schema: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_db = await get_user(email=reset_schema.email, db=db)
    if user_db and user_db.is_active:
        user_db.password_reset_token = None
        await db.commit()
        user_db.password_reset_token = PasswordResetTokenModel(
            user_id=user_db.id)
        await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200,
    summary="Change password",
    description=(
            "<h3>This endpoint allows users to reset their password using"
            " a valid password reset token</h3>"
    ),
    responses={
        200: {
            "description": "Password reset successfully.",
            "content": {
                "application/json": {
                    "example": {"message": "Password reset successfully."}
                }
            }
        },
        400: {
            "description": "If the email or token is invalid, or the token has"
                           " expired, the system deletes the token"
                           " (if it exists) and returns an error response with"
                           " a 400 Bad Request status code. If the user does"
                           " not exist or is inactive, an error response with"
                           " a 400 Bad Request status code is returned.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email or token."}
                }
            }
        },
        500: {
            "description": "If a database error occurs while updating "
                           "the password, the transaction is rolled back,"
                           " and a 500 Internal Server Error is returned.",
            "content": {
                "application/json": {
                    "example": {
                        "An error occurred while resetting the password."
                    }
                }
            }
        }
    }
)
async def reset_password_complete(
        new_cred_data_schema: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_db = await get_user(email=new_cred_data_schema.email, db=db)
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    token_user_db = user_db.password_reset_token
    if not token_user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = (cast(datetime, token_user_db.expires_at).
                  replace(tzinfo=timezone.utc))
    if (
            token_user_db.token != new_cred_data_schema.token
            or expires_at < datetime.now(timezone.utc)
    ):
        await db.delete(token_user_db)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    user_db.password = new_cred_data_schema.password
    try:
        await db.delete(token_user_db)
        await db.commit()
        await db.refresh(user_db)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201,
    summary="User login",
    description=(
            "<h3>This endpoint authenticates a user based on their"
            " email and password, generates access and refresh tokens"
            " upon successful login, stores the refresh token in"
            " the database, and return access and refresh tokens</h3>"
    ),
)
async def login_user(
        cred_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user_db = await get_user(email=cred_data.email, db=db)
    if not user_db or not user_db.verify_password(cred_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    token_payload = {
        "user_id": user_db.id,
        # "group_id": user_db.group_id,
        # "is_active": user_db.is_active
    }
    access_token = jwt_manager.create_access_token(data=token_payload)

    refresh_token = jwt_manager.create_refresh_token(data=token_payload)

    ref_token_data = jwt_manager.decode_refresh_token(refresh_token)
    print(f"{ref_token_data=}")
    days_valid = int((ref_token_data["exp"] - datetime.now(
        timezone.utc).timestamp()) / 86400)

    print(f"{days_valid=}")
    refresh_token_orm = RefreshTokenModel.create(
        user_id=user_db.id,
        days_valid=days_valid,
        token=refresh_token
    )
    db.add(refresh_token_orm)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200,
    summary="User login",
    description=(
            "<h3>This endpoint authenticates a user based on their"
            " email and password, generates access and refresh tokens"
            " upon successful login, stores the refresh token in"
            " the database, and return access and refresh tokens</h3>"
    ),
)
async def refresh_access_token(
        refresh_token_schema: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    refresh_token = refresh_token_schema.refresh_token
    try:
        refresh_token_dict = jwt_manager.decode_refresh_token(refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    print(f"{refresh_token_dict=}")

    query = (
        select(RefreshTokenModel).
        options(joinedload(RefreshTokenModel.user)).
        where(RefreshTokenModel.token == refresh_token)
    )
    refresh_token_db = (await db.execute(query)).scalar_one_or_none()
    print(f"{refresh_token_db=}")

    if not refresh_token_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    if not refresh_token_db.user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(
        {"user_id": refresh_token_db.user_id}
    )
    return TokenRefreshResponseSchema(
        access_token=access_token
    )
