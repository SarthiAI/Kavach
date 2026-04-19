"""Kavach middleware for Python HTTP frameworks.

Works with FastAPI, Starlette, Flask, and any ASGI/WSGI framework.
All evaluation runs in the compiled Rust engine.

Example with FastAPI:
    from fastapi import FastAPI, Request, HTTPException
    from kavach import Gate, HttpKavachMiddleware

    gate = Gate.from_file("kavach.toml")
    kavach = HttpKavachMiddleware(gate)

    app = FastAPI()

    @app.middleware("http")
    async def kavach_middleware(request: Request, call_next):
        verdict = kavach.evaluate_request(request)
        if not verdict.is_permit:
            raise HTTPException(status_code=403, detail=verdict.reason)
        return await call_next(request)
"""

from typing import Callable, TypedDict

from kavach._kavach_engine import ActionContext, GeoLocation, Verdict
from kavach.wrappers import Gate


class GeoResolverResult(TypedDict, total=False):
    """Optional geo annotations returned by a ``geo_resolver``."""

    current_geo: GeoLocation | None
    origin_geo: GeoLocation | None


class HttpKavachMiddleware:
    """Kavach middleware for HTTP APIs.

    Translates HTTP requests to ActionContext and evaluates
    through the Rust gate. Framework-specific adapters call
    into this class.
    """

    def __init__(
        self,
        gate: Gate,
        *,
        gate_mutations_only: bool = True,
        excluded_paths: list[str] | None = None,
        principal_header: str = "X-Principal-Id",
        roles_header: str = "X-Roles",
        kind_header: str = "X-Principal-Kind",
        geo_resolver: Callable[..., GeoResolverResult | None] | None = None,
    ):
        """Args:
            geo_resolver: Optional callable invoked as
                ``geo_resolver(method=..., path=..., ip=..., headers=...)``
                returning a dict with ``current_geo`` / ``origin_geo`` keys
                (both optional ``GeoLocation``). Integrators plug in their
                GeoIP lookup here to drive tolerant-mode
                ``GeoLocationDrift``.
        """
        self._gate = gate
        self.gate_mutations_only = gate_mutations_only
        self.excluded_paths = excluded_paths or ["/health", "/ready", "/metrics"]
        self.principal_header = principal_header
        self.roles_header = roles_header
        self.kind_header = kind_header
        self._geo_resolver = geo_resolver

    def should_gate(self, method: str, path: str) -> bool:
        """Check if this request should be gated."""
        if any(path.startswith(p) for p in self.excluded_paths):
            return False
        if self.gate_mutations_only and method.upper() == "GET":
            return False
        return True

    def derive_action_name(self, method: str, path: str) -> str:
        """Derive action name from HTTP method + path.

        POST /api/v1/refunds → refunds.create
        DELETE /api/v1/users/123 → users.delete
        """
        parts = [
            p for p in path.split("/")
            if p and p != "api" and not p.startswith("v")
            and not p.isdigit()
        ]
        resource = parts[-1] if parts else "unknown"

        verb_map = {
            "GET": "read", "POST": "create",
            "PUT": "update", "PATCH": "update",
            "DELETE": "delete",
        }
        verb = verb_map.get(method.upper(), "unknown")
        return f"{resource}.{verb}"

    def evaluate(
        self,
        *,
        method: str,
        path: str,
        principal_id: str = "anonymous",
        principal_kind: str = "user",
        roles: list[str] | None = None,
        body: dict | None = None,
        ip: str | None = None,
        session_id: str | None = None,
        current_geo: GeoLocation | None = None,
        origin_geo: GeoLocation | None = None,
    ) -> Verdict:
        """Evaluate an HTTP request against the gate.

        Returns the Verdict, caller decides how to handle it. Pass
        ``current_geo`` / ``origin_geo`` (a ``GeoLocation`` with at
        least ``country_code`` and, for tolerant-mode drift,
        ``latitude``/``longitude``) to feed ``GeoLocationDrift``.
        """
        if not self.should_gate(method, path):
            # Return a synthetic permit for non-gated requests
            from kavach._kavach_engine import Verdict as _V
            # We can't construct a Verdict from Python, so we
            # just evaluate with a permissive context
            pass

        action_name = self.derive_action_name(method, path)

        numeric_params = {}
        if body:
            numeric_params = {
                k: float(v) for k, v in body.items()
                if isinstance(v, (int, float))
            }

        # Fall back to the configured geo_resolver if no explicit geo.
        if (
            current_geo is None
            and origin_geo is None
            and self._geo_resolver is not None
        ):
            resolved = self._geo_resolver(method=method, path=path, ip=ip) or {}
            current_geo = resolved.get("current_geo")
            origin_geo = resolved.get("origin_geo")

        ctx = ActionContext(
            principal_id=principal_id,
            principal_kind=principal_kind,
            action_name=action_name,
            roles=roles or [],
            resource=path,
            params=numeric_params or None,
            ip=ip,
            session_id=session_id,
            current_geo=current_geo,
            origin_geo=origin_geo,
        )

        return self._gate.evaluate(ctx)

    def check(self, **kwargs) -> None:
        """Evaluate and raise if not permitted.

        Same args as evaluate(). Raises Refused or Invalidated.
        """
        verdict = self.evaluate(**kwargs)
        if verdict.is_refuse:
            from kavach.wrappers import Refused
            raise Refused(verdict.reason, verdict.evaluator, verdict.code)
        if verdict.is_invalidate:
            from kavach.wrappers import Invalidated
            raise Invalidated(verdict.reason, verdict.evaluator)

    # ── Framework-specific helpers ────────────────────────────────

    def evaluate_fastapi(self, request) -> Verdict:
        """Evaluate a FastAPI/Starlette Request object.

        Usage:
            @app.middleware("http")
            async def kavach_gate(request: Request, call_next):
                verdict = kavach.evaluate_fastapi(request)
                if not verdict.is_permit:
                    return JSONResponse(status_code=403, content={"error": verdict.reason})
                return await call_next(request)
        """
        headers = dict(request.headers)
        return self.evaluate(
            method=request.method,
            path=request.url.path,
            principal_id=headers.get(self.principal_header.lower(), "anonymous"),
            principal_kind=headers.get(self.kind_header.lower(), "user"),
            roles=(headers.get(self.roles_header.lower(), "")).split(","),
            ip=request.client.host if request.client else None,
        )

    def evaluate_flask(self, request) -> Verdict:
        """Evaluate a Flask request object.

        Usage:
            @app.before_request
            def kavach_gate():
                verdict = kavach.evaluate_flask(request)
                if not verdict.is_permit:
                    return jsonify(error=verdict.reason), 403
        """
        return self.evaluate(
            method=request.method,
            path=request.path,
            principal_id=request.headers.get(self.principal_header, "anonymous"),
            principal_kind=request.headers.get(self.kind_header, "user"),
            roles=request.headers.get(self.roles_header, "").split(","),
            body=request.get_json(silent=True),
            ip=request.remote_addr,
        )
