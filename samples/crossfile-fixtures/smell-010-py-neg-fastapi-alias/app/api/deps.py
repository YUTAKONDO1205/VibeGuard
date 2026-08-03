"""Dependency ALIASES, in the shape of `fastapi/full-stack-fastapi-template`.

★ THIS FIXTURE EXISTS BECAUSE OF A CORPUS SWEEP, NOT BECAUSE OF A SPEC.

The first version of VG-SMELL-010's Python arm was swept over the 630
source-bearing repositories of `paper_data/corpus1k` and produced exactly one
finding: FastAPI's own official project template, six `current_user.is_superuser`
checks across two router files. It was false, and it was false for a reason no
hand-written fixture had contained — the template's handlers never write
`Depends(...)` at all. The dependency is declared once, here, and referred to by
a type name.

`SessionDep` is the control: it is a dependency alias too, and it is NOT a
security one, so it must not silence anything on its own.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.db import Session, open_db
from app.models import User

bearer_scheme = OAuth2PasswordBearer(tokenUrl="/login/access-token")

SessionDep = Annotated[Session, Depends(open_db)]
TokenDep = Annotated[str, Depends(bearer_scheme)]


def get_current_user(session: SessionDep, token: TokenDep) -> User:
    user = session.lookup(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
