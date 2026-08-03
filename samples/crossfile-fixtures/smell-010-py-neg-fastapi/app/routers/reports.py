"""Report routes.

Authorization is declared per path operation, in the SIGNATURE, which is the
form FastAPI's security tutorial uses:
`current_user: Annotated[User, Depends(get_current_active_user)]`. The signature
spans several lines, which is how the tutorial writes it and is the case the
indexer's `bodyStart` cannot be used for — see `pythonSignature`.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from ..dependencies import get_current_active_user
from ..models import User
from ..store import list_reports, load_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/")
async def read_reports(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    reports = list_reports()
    if current_user.role != "auditor":
        reports = [r for r in reports if r.owner_id == current_user.id]
    return reports


@router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    report = load_report(report_id)
    if report.owner_id != current_user.id and current_user.role != "auditor":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    report.retire()
    return {"ok": True}
