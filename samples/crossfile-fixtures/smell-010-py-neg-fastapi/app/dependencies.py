"""Shared dependencies, in the shape of FastAPI's "Bigger Applications" and
"Security" tutorials.

`get_token_header` is the router-level dependency from the first; the
`get_current_user` / `get_current_active_user` pair is the second, verbatim in
structure. Every authorization decision in this application is taken here or in
a `dependencies=` list — never inside a path operation.

NEGATIVE FIXTURE for VG-SMELL-010's Python arm. Nothing here may be reported.
"""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from .db import Session, get_session
from .models import User


async def get_token_header(x_token: Annotated[str, Header()]):
    if x_token != "fake-super-secret-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Token header invalid",
        )


async def get_current_user(
    x_token: Annotated[str, Header()],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    user = session.lookup_by_token(x_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user
