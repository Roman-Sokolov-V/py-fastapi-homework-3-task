from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import joinedload

from database import (
    UserModel,
    ActivationTokenModel
)


async def get_user(db: AsyncSession, email: str) -> UserModel | None:
    stmt = select(UserModel).options(joinedload(UserModel.password_reset_token)).where(UserModel.email == email)
    user = (await db.execute(stmt)).scalar_one_or_none()
    return user


async def get_activation_token(
        db: AsyncSession,
        user: UserModel
) -> ActivationTokenModel:
    stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id
    )
    token = (await db.execute(stmt)).scalar_one_or_none()
    return token
