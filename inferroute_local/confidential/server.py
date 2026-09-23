"""The per-session local endpoint Claude Code talks to on the confidential lane.

Listens on 127.0.0.1 only, lives exactly as long as the session, records nothing. Every
``/v1/messages`` goes through ``ConfidentialSession.messages`` (translate → seal → relay → open →
translate); ``/v1/models`` answers with the pinned model so Claude Code never tries another.
"""
from __future__ import annotations

import hmac
import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .session import ConfidentialSession


def create_app(session: ConfidentialSession, token: str) -> FastAPI:
    """`token` is minted per session by the launcher and given only to the agent it starts.

    Until 23 Sep this endpoint checked nothing. An audit put it plainly: any process on the machine that
    found the port could send prompts through the professional's verified, billed session and read
    `/confidential/receipt`. The launcher did set `ir-confidential-local` — a constant in public source,
    so checking it would have proved nothing. The credential has to be a secret AND be checked.
    """
    app = FastAPI(title="inferroute-confidential")

    @app.middleware("http")
    async def _require_token(request: Request, call_next):
        # Claude Code sends ANTHROPIC_AUTH_TOKEN as `Authorization: Bearer`; the OpenAI-dialect agents
        # (pi, opencode, goose) send the api_key the same way; the Anthropic dialect also allows
        # `x-api-key`. Accept either header, compare in constant time, and say nothing about which.
        auth = request.headers.get("authorization", "")
        offered = auth[7:] if auth[:7].lower() == "bearer " else request.headers.get("x-api-key", "")
        if not hmac.compare_digest(offered, token):
            return JSONResponse(status_code=401,
                                content={"type": "error",
                                         "error": {"type": "authentication_error",
                                                   "message": "this endpoint belongs to one confidential "
                                                              "session on this machine"}})
        return await call_next(request)

    @app.post("/v1/messages")
    async def messages(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"type": "error", "error": {"type": "invalid_request_error", "message": "Invalid JSON"}})
        try:
            status, headers, stream = await session.messages(body)
        except Exception as e:  # never let a traceback reach the terminal; Claude Code shows this text instead
            session.receipt.counters["errors"] += 1
            msg = f"confidential lane: unexpected failure ({type(e).__name__}: {e}); nothing left this device in the clear"
            if body.get("stream"):
                return StreamingResponse(iter([f"event: error\ndata: {json.dumps({'type': 'error', 'error': {'type': 'api_error', 'message': msg}})}\n\n".encode()]),
                                         status_code=500, media_type="text/event-stream")
            return JSONResponse(status_code=500, content={"type": "error", "error": {"type": "api_error", "message": msg}})
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

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        """Native OpenAI dialect for agents that speak it (Pi, OpenCode, Goose): sealed as-is."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": {"message": "Invalid JSON", "type": "invalid_request_error"}})
        try:
            status, headers, stream = await session.chat_completions(body)
        except Exception as e:
            session.receipt.counters["errors"] += 1
            msg = f"confidential lane: unexpected failure ({type(e).__name__}: {e}); nothing left this device in the clear"
            if body.get("stream"):
                return StreamingResponse(iter([("data: " + json.dumps({"error": {"message": msg, "type": "server_error"}}) + "\n\n").encode()]),
                                         status_code=500, media_type="text/event-stream")
            return JSONResponse(status_code=500, content={"error": {"message": msg, "type": "server_error"}})
        if body.get("stream"):
            return StreamingResponse(stream, status_code=status, headers=headers, media_type="text/event-stream")
        chunks = []
        async for c in stream:
            chunks.append(c)
        raw = b"".join(chunks)
        try:
            return JSONResponse(content=json.loads(raw), status_code=status)
        except Exception:
            return JSONResponse(content={"error": {"message": raw.decode("utf-8", "replace")[:500], "type": "server_error"}}, status_code=500)

    @app.get("/v1/models")
    async def models():
        shown = getattr(session, "shown_model", session.model_short)
        return {"object": "list", "data": [{"id": shown, "type": "model", "display_name": f"{session.upstream_model} · confidential"}]}

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
