"""Application entry point. The routers are mounted plainly."""

from fastapi import FastAPI

from app.api.routes import items, users

app = FastAPI()

app.include_router(items.router)
app.include_router(users.router)
