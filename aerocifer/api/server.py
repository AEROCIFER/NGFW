"""
AEROCIFER NGFW — FastAPI Server

Provides a REST API to monitor firewall health, packet statistics, active flows,
manage rules, and submit natural language AI configuration prompts.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio
import logging

from aerocifer.utils.logger import get_logger
from aerocifer.api.routes import status, ai_config, security, network, logs

log = get_logger("api")

def create_app(ngfw_instance) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AEROCIFER NGFW API",
        description="REST Control Plane for the AI-Powered Next-Gen Firewall",
        version="1.0.0"
    )

    # Inject the main firewall instance into app state
    app.state.ngfw = ngfw_instance

    # CORS for potential web dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(status.router, prefix="/api/v1/status", tags=["Status"])
    app.include_router(ai_config.router, prefix="/api/v1/ai", tags=["AI Configuration"])
    app.include_router(security.router, prefix="/api/v1/security", tags=["Security & Rules"])
    app.include_router(network.router, prefix="/api/v1/network", tags=["Interfaces & Zones"])
    app.include_router(logs.router, prefix="/api/v1/logs", tags=["Traffic Analytics"])

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        log.error(f"API Error on {request.url.path}: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "details": str(exc)}
        )

    return app

async def start_api_server(ngfw_instance, host: str, port: int):
    """Start the Uvicorn ASGI server."""
    app = create_app(ngfw_instance)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    
    log.info(f"Starting Control Plane API on http://{host}:{port}")
    await server.serve()
