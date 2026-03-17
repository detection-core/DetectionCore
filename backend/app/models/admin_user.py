from beanie import Document
from datetime import datetime, timezone


class AdminUser(Document):
    username: str
    email: str  # plain str — on-prem local domains (e.g. .local) are valid here
    password_hash: str
    created_at: datetime = datetime.now(timezone.utc)

    class Settings:
        name = "admin_users"
        indexes = ["username", "email"]
