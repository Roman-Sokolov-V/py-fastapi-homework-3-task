from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)


async def get_user(db: AsyncSession, email: str) -> UserModel | None:
    stmt = select(UserModel).where(UserModel.email == email)
    user = (await db.execute(stmt)).scalar_one_or_none()
    return user

async def get_activation_token(db: AsyncSession, user: UserModel) -> ActivationTokenModel:
    stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    token = (await db.execute(stmt)).scalar_one_or_none()
    return token

# async def get_group(db: AsyncSession, group_name: str) -> UserGroupModel | None:
#     stmt = select(UserGroupModel).where(
#         UserGroupModel.name == UserGroupEnum.USER)
