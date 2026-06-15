"""Configuration loaded from environment variables.

The daemon is a pure pass-through recorder: it records the user's model choice +
how the turn went (locally, privately) and forwards the request to the inferroute
cloud. There is NO classifier, router, compactor, or compression here anymore —
all of that retired with the local router. Config is correspondingly small.
See shared-docs/inferroute/local-decision-recorder-spec.md.
"""

import os
from dataclasses import dataclass


@dataclass
class Config:
    # Local daemon bind.
    host: str = "127.0.0.1"
    port: int = 5005

    # Conceptual upstream for the user's own credentials (used by `doctor`'s
    # reachability probe). The request path forwards to inferroute_server_url.
    anthropic_base_url: str = "https://api.anthropic.com"

    # inferroute cloud — where the daemon forwards /v1/messages.
    inferroute_server_url: str = "https://api.inferroute.ai"
    inferroute_api_key: str = ""

    # ── Local decision recorder ──────────────────────────────────────────
    # The privacy-local corpus of the user's model choices + how they turned
    # out. The corpus stays under record_dir on the user's machine; the daemon
    # emits only a one-way hash of each turn upstream (x-inferroute-content-hash
    # — a fingerprint, never text; see proxy._visibility_headers +
    # shared-docs/inferroute/recording-visibility-spec.md).
    #   level "off"      → record nothing (still captures per-session cost)
    #   level "metadata" → choice/outcome/signal events only (no prompt text)
    #   level "full"     → also a content-addressed blob store of raw payloads
    # Default ON (metadata). NOTE: with native-transcript ingestion (the
    # SessionEnd hook), "full" blobs duplicate the native CC transcript and are
    # generally unnecessary — prefer "metadata". See ingest.py.
    record_level: str = "metadata"
    record_dir: str = ""              # empty → ~/.inferroute
    record_ttl_days: int = 90         # raw blob GC age; 0 = keep forever
    record_blob_cap_bytes: int = 65536  # per-blob head+tail cap (oversize trim)

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            host=os.environ.get("INFERROUTE_HOST", "127.0.0.1"),
            port=int(os.environ.get("INFERROUTE_PORT", "5005")),
            anthropic_base_url=os.environ.get("ANTHROPIC_UPSTREAM", "https://api.anthropic.com"),
            inferroute_server_url=os.environ.get("INFERROUTE_SERVER_URL", "https://api.inferroute.ai"),
            inferroute_api_key=os.environ.get("INFERROUTE_API_KEY", ""),
            record_level=_record_level_default(),
            record_dir=os.environ.get(
                "INFERROUTE_RECORD_DIR", os.environ.get("INFERROUTE_LOG_DIR", "")
            ),
            record_ttl_days=int(os.environ.get("INFERROUTE_RECORD_TTL_DAYS", "90")),
            record_blob_cap_bytes=int(
                os.environ.get("INFERROUTE_RECORD_BLOB_CAP_BYTES", "65536")
            ),
        )


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean env var. Accepts 1/0, true/false, yes/no (case-insensitive)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _record_level_default() -> str:
    """Resolve the recorder level, honoring the legacy decision-log env vars so
    existing installs keep working:
      INFERROUTE_RECORD_LEVEL wins if set (off|metadata|full);
      else INFERROUTE_LOG_TRAINING=1 → full;
      else INFERROUTE_LOG_DECISIONS=0 → off;
      else → metadata (default ON)."""
    explicit = os.environ.get("INFERROUTE_RECORD_LEVEL")
    if explicit:
        lvl = explicit.strip().lower()
        return lvl if lvl in {"off", "metadata", "full"} else "metadata"
    if _env_bool("INFERROUTE_LOG_TRAINING", False):
        return "full"
    if not _env_bool("INFERROUTE_LOG_DECISIONS", True):
        return "off"
    return "metadata"
