import re

from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, field_validator, Field
from pydantic import AfterValidator, BaseModel, ValidationError
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Path, status

from database import accounts_validators, ActivationTokenModel


def password_validator(password: str) -> str:
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least 8 characters."
        )

    if not re.search(r'[a-z]', password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one lower letter."
        )
    if not re.search(r'[A-Z]', password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one uppercase letter."
        )

    if not re.search(r'[0-9]', password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one digit."
        )

    if not re.search(r'[@$!%*?&#]', password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one special character: @, $, !, %, *, ?, #, &."
        )
    return password


class UserRegistrationRequestSchema(BaseModel):
    email: Annotated[EmailStr, Field(..., max_length=255)]
    password: Annotated[str, AfterValidator(password_validator)]



class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str



class UserActivationRequestSchema(BaseModel):
    email: Annotated[EmailStr, Field(..., max_length=255)]
    token: str



class MessageResponseSchema(BaseModel):
    message: str

class PasswordResetRequestSchema(BaseModel):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    pass


class UserLoginResponseSchema(BaseModel):
    pass


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass

