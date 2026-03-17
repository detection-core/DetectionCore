from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from app.models.admin_user import AdminUser
from app.core.security import verify_password, create_access_token
from app.core.dependencies import get_current_admin
from app.schemas.base import ApiResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AdminOut(BaseModel):
    username: str
    email: str


@router.post("/login", response_model=ApiResponse[TokenResponse])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate admin and return JWT token."""
    admin = await AdminUser.find_one(AdminUser.username == form_data.username)
    if not admin or not verify_password(form_data.password, admin.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_access_token(subject=admin.username)
    return ApiResponse.ok(
        data=TokenResponse(access_token=token),
        message="Login successful",
    )


@router.get("/me", response_model=ApiResponse[AdminOut])
async def get_me(current_admin: AdminUser = Depends(get_current_admin)):
    """Return current authenticated admin info."""
    return ApiResponse.ok(
        data=AdminOut(username=current_admin.username, email=current_admin.email)
    )
