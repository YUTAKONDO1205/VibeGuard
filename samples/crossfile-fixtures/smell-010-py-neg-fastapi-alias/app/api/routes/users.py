"""User routes. The second file, so removing the alias clears MIN_FILES too."""

from typing import Any

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/")
def read_users(session: SessionDep, current_user: CurrentUser, skip: int = 0) -> Any:
    if current_user.is_superuser:
        return session.all_users(skip)
    return [current_user]


@router.delete("/me")
def delete_user_me(session: SessionDep, current_user: CurrentUser) -> Any:
    if current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="Super users are not allowed to delete themselves"
        )
    return {"message": "User deleted successfully"}
