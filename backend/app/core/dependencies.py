from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.core.security import decode_token
from app.models.admin_user import AdminUser

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_admin(token: str = Depends(oauth2_scheme)) -> AdminUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = decode_token(token)
    if not username:
        raise credentials_exception
    admin = await AdminUser.find_one(AdminUser.username == username)
    if not admin:
        raise credentials_exception
    return admin
