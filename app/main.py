"""FastAPI application entry point. Mounts the API router and serves the static UI."""

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .routes import router

app = FastAPI(
    title="Phish X",
    description="Simulate phishing and vishing attacks, detect AI-generated phishing, and improve user behaviour.",
    version="1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Serve frontend: when frozen (PyInstaller) use bundle dir, else project root
if getattr(sys, "frozen", False):
    _project_root = Path(sys._MEIPASS)
else:
    _project_root = Path(__file__).resolve().parent.parent
_static = _project_root / "static"
if _static.is_dir():
    app.mount("/static", StaticFiles(directory=_static, html=True), name="static")


@app.get("/")
def root():
    """API info; UI at /static/ when static folder is present."""
    payload = {"message": "Phish X API Running", "docs": "/docs", "api": "/api"}
    if _static.is_dir():
        payload["ui"] = "/static/"
    return payload