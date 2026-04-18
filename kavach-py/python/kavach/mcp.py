"""Kavach middleware for Python MCP servers.

Wraps MCP tool handlers so every call passes through the Rust gate.
Works with the official MCP Python SDK.

Example:
    from mcp.server import Server
    from kavach import Gate, McpKavachMiddleware

    gate = Gate.from_file("kavach.toml")
    kavach = McpKavachMiddleware(gate)

    server = Server("my-server")

    @server.call_tool()
    async def handle_tool(name: str, arguments: dict) -> list:
        # Gate the call — raises Refused if blocked
        kavach.check_tool_call(
            tool_name=name,
            params=arguments,
            caller_id="agent-bot",
            caller_kind="agent",
        )

        # If we reach here, the gate permitted
        if name == "issue_refund":
            return [TextContent(text=process_refund(arguments))]

Distributed deployments
-----------------------
Pass a shared session store to make ``invalidate_session`` visible
across service replicas::

    from kavach import RedisSessionStore

    store = RedisSessionStore.from_url("redis://localhost/0")
    kavach = McpKavachMiddleware(gate, session_store=store)

The middleware will consult the store before every gated call and
raise :class:`~kavach.Invalidated` when a peer has revoked the
session. Without ``session_store``, an in-process
:class:`~kavach.InMemorySessionStore` is used — same code path,
single-node scope.
"""

from dataclasses import dataclass, field
from typing import Union

from kavach._kavach_engine import (
    ActionContext,
    GeoLocation,
    InMemorySessionStore,
    RedisSessionStore,
)
from kavach.wrappers import Gate, Invalidated


SessionStoreBackend = Union[InMemorySessionStore, RedisSessionStore]


@dataclass
class McpSession:
    """Tracks state for an MCP session."""

    session_id: str
    caller_id: str
    caller_kind: str = "agent"
    roles: list[str] = field(default_factory=list)
    ip: str | None = None
    action_count: int = 0
    invalidated: bool = False


class McpKavachMiddleware:
    """Kavach middleware for MCP servers.

    All evaluation runs in the compiled Rust engine.
    This class manages sessions and translates MCP concepts
    to Kavach ActionContext.
    """

    def __init__(
        self,
        gate: Gate,
        *,
        session_store: SessionStoreBackend | None = None,
    ):
        """Create a middleware bound to a :class:`~kavach.Gate`.

        Args:
            gate: The Kavach gate this middleware evaluates against.
            session_store: Optional backend for cross-replica session
                state — accepts an :class:`~kavach.InMemorySessionStore`
                or a :class:`~kavach.RedisSessionStore`. When unset, an
                in-process ``InMemorySessionStore`` is used internally
                so the same code path serves both single-node and
                multi-node deployments. When set to a Redis-backed
                store, :meth:`invalidate_session` fans out to peer
                replicas and :meth:`check_tool_call` honours
                cross-node invalidations before reaching the gate.
        """
        self._gate = gate
        self._store: SessionStoreBackend = (
            session_store if session_store is not None else InMemorySessionStore()
        )
        # Local cache of McpSession views (principal-facing fields that
        # aren't part of SessionState). Action-count mutations in here
        # are observational only — the gate itself reads action_count
        # from the ActionContext the caller passes in, not from this
        # cache.
        self._sessions: dict[str, McpSession] = {}

    def check_tool_call(
        self,
        *,
        tool_name: str,
        params: dict,
        caller_id: str,
        caller_kind: str = "agent",
        roles: list[str] | None = None,
        session_id: str | None = None,
        ip: str | None = None,
        current_geo: GeoLocation | None = None,
        origin_geo: GeoLocation | None = None,
    ) -> None:
        """Check a tool call against the gate. Raises if blocked.

        Args:
            tool_name: The MCP tool being called.
            params: Tool parameters.
            caller_id: Identity of the caller.
            caller_kind: "agent", "user", or "service".
            roles: Caller's roles.
            session_id: Session ID for drift tracking.
            ip: Caller's IP address.
            current_geo: Geographic location at this call. Set this plus
                ``origin_geo`` to unlock tolerant-mode GeoLocationDrift
                (an IP change within ``max_distance_km`` downgrades to a
                warning instead of a violation).
            origin_geo: Geographic location at session start.

        Raises:
            kavach.Refused: If the gate blocks the action.
            kavach.Invalidated: If the session is revoked (locally or
                by a peer via the shared session store).
        """
        # Fast-path remote-invalidation check. A peer replica that called
        # `invalidate_session` will have flipped the shared store's flag;
        # we honour that before even building the ActionContext.
        if session_id and self._store.is_invalidated(session_id):
            raise Invalidated(
                f"session {session_id} invalidated by a peer node",
                "session_store",
            )

        # Build numeric params for invariant checks
        numeric_params = {
            k: float(v) for k, v in params.items() if isinstance(v, (int, float))
        }

        ctx = ActionContext(
            principal_id=caller_id,
            principal_kind=caller_kind,
            action_name=tool_name,
            roles=roles or [],
            params=numeric_params or None,
            ip=ip,
            session_id=session_id,
            current_geo=current_geo,
            origin_geo=origin_geo,
        )

        # Crosses into Rust for evaluation
        self._gate.check(ctx)

        # If we get here, gate permitted — track the action locally
        if session_id:
            session = self._sessions.setdefault(
                session_id,
                McpSession(
                    session_id=session_id,
                    caller_id=caller_id,
                    caller_kind=caller_kind,
                    roles=roles or [],
                    ip=ip,
                ),
            )
            session.action_count += 1

    def evaluate_tool_call(
        self,
        *,
        tool_name: str,
        params: dict,
        caller_id: str,
        caller_kind: str = "agent",
        roles: list[str] | None = None,
        session_id: str | None = None,
        ip: str | None = None,
        current_geo: GeoLocation | None = None,
        origin_geo: GeoLocation | None = None,
    ):
        """Evaluate without raising — returns the Verdict object.

        Use this when you want to handle the verdict yourself
        rather than using exception flow. See ``check_tool_call`` for
        the semantics of ``current_geo`` / ``origin_geo``.
        """
        numeric_params = {
            k: float(v) for k, v in params.items() if isinstance(v, (int, float))
        }

        ctx = ActionContext(
            principal_id=caller_id,
            principal_kind=caller_kind,
            action_name=tool_name,
            roles=roles or [],
            params=numeric_params or None,
            ip=ip,
            session_id=session_id,
            current_geo=current_geo,
            origin_geo=origin_geo,
        )

        return self._gate.evaluate(ctx)

    def get_session(self, session_id: str) -> McpSession | None:
        """Return the locally-cached :class:`McpSession`, updated for
        remote invalidation from the shared store.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return None
        # Reflect remote invalidation in the local view so callers that
        # only read this object still see the correct state.
        if not session.invalidated and self._store.is_invalidated(session_id):
            session.invalidated = True
        return session

    def invalidate_session(self, session_id: str) -> None:
        """Invalidate locally and fan out via the shared session store.

        Local caches are updated immediately. The shared-store write
        is what makes the invalidation visible to peer replicas —
        their next :meth:`check_tool_call` will see it and raise
        :class:`~kavach.Invalidated`.
        """
        if session_id in self._sessions:
            self._sessions[session_id].invalidated = True
        self._store.invalidate(session_id)
