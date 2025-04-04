from pydantic import BaseModel, EmailStr, AfterValidator
from typing import Annotated

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: Annotated[EmailStr, AfterValidator(accounts_validators.validate_email)]
    password: Annotated[str, AfterValidator(accounts_validators.validate_password_strength)]


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    email: Annotated[EmailStr, AfterValidator(accounts_validators.validate_email)]
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: Annotated[EmailStr, AfterValidator(accounts_validators.validate_email)]


class PasswordResetCompleteRequestSchema(BaseModel):
    email: Annotated[EmailStr, AfterValidator(accounts_validators.validate_email)]
    token: str
    password: Annotated[str, AfterValidator(accounts_validators.validate_password_strength)]


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: Annotated[EmailStr, AfterValidator(accounts_validators.validate_email)]
    password: Annotated[str, AfterValidator(accounts_validators.validate_password_strength)]


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
