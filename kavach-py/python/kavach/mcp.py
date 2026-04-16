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
"""

from dataclasses import dataclass, field
from kavach._kavach_engine import ActionContext, GeoLocation
from kavach.wrappers import Gate


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

    def __init__(self, gate: Gate):
        self._gate = gate
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
            kavach.Invalidated: If the session is revoked.
        """
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

        # If we get here, gate permitted — track the action
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
        return self._sessions.get(session_id)

    def invalidate_session(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].invalidated = True
