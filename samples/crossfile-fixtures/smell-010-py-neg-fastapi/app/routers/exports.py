"""Export routes. Same signature-level declaration as `reports.py`.

Two files carry the signature form for the same reason two carry the router
form: removing it must clear MIN_SITES and MIN_FILES on its own, or the test
that removes it proves nothing about this negative condition.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from ..dependencies import get_current_active_user
from ..models import User
from ..store import list_reports, load_report

router = APIRouter(prefix="/exports", tags=["exports"])


@router.get("/")
async def read_exports(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    exports = list_reports()
    if current_user.role != "auditor":
        exports = [e for e in exports if e.owner_id == current_user.id]
    return exports


@router.delete("/{export_id}")
async def delete_export(
    export_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    export = load_report(export_id)
    if export.owner_id != current_user.id and current_user.role != "auditor":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    export.retire()
    return {"ok": True}
