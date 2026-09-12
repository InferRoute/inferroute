"""The per-session local endpoint Claude Code talks to on the confidential lane.

Listens on 127.0.0.1 only, lives exactly as long as the session, records nothing. Every
``/v1/messages`` goes through ``ConfidentialSession.messages`` (translate → seal → relay → open →
translate); ``/v1/models`` answers with the pinned model so Claude Code never tries another.
"""
from __future__ import annotations

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .session import ConfidentialSession


def create_app(session: ConfidentialSession) -> FastAPI:
    app = FastAPI(title="inferroute-confidential")

    @app.post("/v1/messages")
    async def messages(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"type": "error", "error": {"type": "invalid_request_error", "message": "Invalid JSON"}})
        status, headers, stream = await session.messages(body)
        if body.get("stream"):
            return StreamingResponse(stream, status_code=status, headers=headers, media_type="text/event-stream")
        chunks = []
        async for c in stream:
            chunks.append(c)
        raw = b"".join(chunks)
        try:
            return JSONResponse(content=json.loads(raw), status_code=status)
        except Exception:
            return JSONResponse(content={"type": "error", "error": {"type": "api_error", "message": raw.decode("utf-8", "replace")[:500]}}, status_code=500)

    @app.post("/v1/messages/count_tokens")
    async def count_tokens():
        return JSONResponse(status_code=404, content={"type": "error", "error": {"type": "not_found_error", "message": "not available on the confidential lane"}})

    @app.get("/v1/models")
    async def models():
        return {"object": "list", "data": [{"id": session.model_short, "type": "model", "display_name": session.upstream_model}]}

    @app.get("/health")
    async def health():
        r = session.receipt
        return {"status": "ok", "service": "inferroute-confidential", "verdict": r.verdict,
                "instance": (r.instance or {}).get("id"), "requests": r.counters["requests"]}

    @app.get("/confidential/receipt")
    async def receipt():
        from dataclasses import asdict
        return asdict(session.receipt)

    return app
