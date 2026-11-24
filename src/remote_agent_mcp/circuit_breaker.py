from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from typing import Any

from .config import settings
from .security import SandboxError, audit_log


class ToolCircuitBreaker:
    """Server-side rate limiter and repeat-mutation guard.

    Complements browser-side auto-approval helpers (such as KenEasy-Gemini-MCP-Auto-Helper)
    by preventing runaway tool loops or accidental writes when auto-approval is active.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._call_timestamps: deque[float] = deque()
        self._last_mutation_sig: str | None = None
        self._repeat_mutation_count: int = 0

    def reset(self) -> None:
        with self._lock:
            self._call_timestamps.clear()
            self._last_mutation_sig = None
            self._repeat_mutation_count = 0

    def check(self, tool_name: str, *, mutating: bool = False, fingerprint: Any = None) -> None:
        if mutating and settings.read_only_mode:
            audit_log(tool_name, {"reason": "read_only_mode"}, "denied")
            raise SandboxError(f"Tool '{tool_name}' is blocked because MCP_READ_ONLY_MODE=true")

        now = time.monotonic()
        with self._lock:
            if settings.max_tool_calls_per_minute > 0:
                cutoff = now - 60.0
                while self._call_timestamps and self._call_timestamps[0] < cutoff:
                    self._call_timestamps.popleft()
                if len(self._call_timestamps) >= settings.max_tool_calls_per_minute:
                    audit_log(
                        tool_name,
                        {"limit_per_min": settings.max_tool_calls_per_minute},
                        "denied",
                        "rate_limit",
                    )
                    raise SandboxError("Tool rate limit exceeded (MCP_MAX_TOOL_CALLS_PER_MINUTE)")
                self._call_timestamps.append(now)

            if mutating and settings.max_repeat_mutations > 0:
                raw = json.dumps(
                    {"tool": tool_name, "fp": fingerprint}, sort_keys=True, default=str
                )
                sig = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                if sig == self._last_mutation_sig:
                    self._repeat_mutation_count += 1
                else:
                    self._last_mutation_sig = sig
                    self._repeat_mutation_count = 1
                if self._repeat_mutation_count > settings.max_repeat_mutations:
                    audit_log(
                        tool_name,
                        {"repeat_count": self._repeat_mutation_count},
                        "denied",
                        "repeat_mutation_breaker",
                    )
                    raise SandboxError(
                        "Repeated identical mutation blocked by server circuit breaker "
                        "(MCP_MAX_REPEAT_MUTATIONS)"
                    )


circuit_breaker = ToolCircuitBreaker()
