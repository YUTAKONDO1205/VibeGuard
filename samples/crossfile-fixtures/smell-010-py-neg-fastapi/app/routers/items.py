"""Item routes.

Authorization is declared ONCE, on the router, exactly as FastAPI's "Bigger
Applications" page shows: `dependencies=[Depends(get_token_header)]` applies to
every path operation registered below. The role comparisons in the bodies narrow
a result set by ownership, which is an object-level concern the router-level
dependency cannot express.
"""

from fastapi import APIRouter, Depends, HTTPException

from ..dependencies import get_token_header
from ..store import current_actor, list_items, load_item

router = APIRouter(
    prefix="/items",
    tags=["items"],
    dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)


@router.get("/")
async def read_items():
    actor = current_actor()
    items = list_items()
    if actor.role != "admin":
        items = [i for i in items if i.owner_id == actor.id]
    return items


@router.put("/{item_id}")
async def update_item(item_id: str, name: str):
    actor = current_actor()
    item = load_item(item_id)
    if item.owner_id != actor.id and actor.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    item.rename(name)
    return item
