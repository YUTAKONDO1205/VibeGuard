"""Item routes.

`current_user: CurrentUser` is the whole authorization declaration. The
superuser branches below narrow a result set by ownership once the caller is
known, which is the object-level half a dependency cannot express.
"""

from typing import Any

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, SessionDep

router = APIRouter(prefix="/items", tags=["items"])


@router.get("/")
def read_items(session: SessionDep, current_user: CurrentUser, skip: int = 0) -> Any:
    if current_user.is_superuser:
        return session.all_items(skip)
    return session.items_owned_by(current_user.id, skip)


@router.get("/{item_id}")
def read_item(session: SessionDep, current_user: CurrentUser, item_id: str) -> Any:
    item = session.get_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    if not current_user.is_superuser and item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return item
