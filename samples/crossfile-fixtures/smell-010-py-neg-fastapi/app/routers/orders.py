"""Order routes. Same router-level declaration as `items.py`.

Two files carry the router-level form so that removing it in a copy of this
fixture yields four sites across two files — enough to clear both MIN_SITES and
MIN_FILES, which is what makes the silence here falsifiable rather than
incidental.
"""

from fastapi import APIRouter, Depends, HTTPException

from ..dependencies import get_token_header
from ..store import current_actor, list_items, load_item

router = APIRouter(
    prefix="/orders",
    tags=["orders"],
    dependencies=[Depends(get_token_header)],
    responses={404: {"description": "Not found"}},
)


@router.get("/")
async def read_orders():
    actor = current_actor()
    orders = list_items()
    if actor.role != "admin":
        orders = [o for o in orders if o.owner_id == actor.id]
    return orders


@router.post("/{order_id}/rename")
async def rename_order(order_id: str, name: str):
    actor = current_actor()
    order = load_item(order_id)
    if order.owner_id != actor.id and actor.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    order.rename(name)
    return order
