"""Application entry point.

The routers are mounted plainly here — no `dependencies=` on `include_router`,
deliberately, so that the fixture's silence comes from the router-level and
signature-level declarations and NOT from an application-wide silencer that
would mask them both.
"""

from fastapi import FastAPI

from .routers import exports, items, orders, reports

app = FastAPI()

app.include_router(items.router)
app.include_router(orders.router)
app.include_router(reports.router)
app.include_router(exports.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
