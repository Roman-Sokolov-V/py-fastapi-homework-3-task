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


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    query = select(UserModel).where(email=email)
    result = await db.execute(query)
    return result.scalars().first()


# async def get_group(db: AsyncSession, group_name: str) -> UserGroupModel | None:
#     stmt = select(UserGroupModel).where(
#         UserGroupModel.name == UserGroupEnum.USER)
