"""Decorators for gating Python functions with Kavach.

These provide the most Pythonic way to add Kavach protection.
All gate evaluation runs in the Rust engine.

Example:
    gate = Gate.from_file("kavach.toml")

    @guarded(gate, action="issue_refund")
    async def issue_refund(order_id: str, amount: float) -> dict:
        # This only executes if the gate permits
        return {"status": "refunded", "amount": amount}

    # Call it, Kavach evaluates before execution
    result = await issue_refund(
        "ORD-123", 500.0,
        _principal_id="agent-bot",
        _principal_kind="agent",
        _roles=["support"],
    )
"""

import functools
import inspect
from typing import Any, Callable

from kavach._kavach_engine import ActionContext
from kavach.wrappers import Gate, Refused, Invalidated


def guarded(
    gate: Gate,
    *,
    action: str | None = None,
    param_fields: dict[str, str] | None = None,
) -> Callable:
    """Decorator that gates a function through Kavach.

    The decorated function only executes if the gate permits.
    Context is built from special _kavach prefixed kwargs.

    Args:
        gate: The Kavach gate instance.
        action: Action name (defaults to function name).
        param_fields: Map of action param names to function arg names.
                      e.g. {"amount": "amount"} extracts the 'amount' arg
                      and passes it to the gate for invariant checking.

    Kavach kwargs (stripped before calling your function):
        _principal_id: Who is performing the action.
        _principal_kind: "user", "agent", "service".
        _roles: List of roles.
        _resource: Resource being acted on.
        _ip: Caller's IP address.
        _session_id: Session identifier.
    """

    def decorator(fn: Callable) -> Callable:
        action_name = action or fn.__name__
        fields = param_fields or {}

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            ctx, clean_kwargs = _build_context(action_name, fields, kwargs, args, fn)
            gate.check(ctx)  # Raises Refused/Invalidated if blocked
            return await fn(*args, **clean_kwargs)

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            ctx, clean_kwargs = _build_context(action_name, fields, kwargs, args, fn)
            gate.check(ctx)  # Raises Refused/Invalidated if blocked
            return fn(*args, **clean_kwargs)

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator


def guarded_tool(
    gate: Gate,
    *,
    action: str | None = None,
) -> Callable:
    """Decorator specifically for MCP tool handlers.

    Extracts all tool parameters and passes them to the gate
    for policy and invariant evaluation.

    Example:
        @guarded_tool(gate, action="issue_refund")
        async def handle_refund(params: dict) -> dict:
            # params["amount"], params["order_id"], etc.
            return {"status": "done"}
    """

    def decorator(fn: Callable) -> Callable:
        action_name = action or fn.__name__

        @functools.wraps(fn)
        async def async_wrapper(params: dict, **kwargs):
            ctx = _build_tool_context(action_name, params, kwargs)
            gate.check(ctx)
            return await fn(params, **_strip_kavach_kwargs(kwargs))

        @functools.wraps(fn)
        def sync_wrapper(params: dict, **kwargs):
            ctx = _build_tool_context(action_name, params, kwargs)
            gate.check(ctx)
            return fn(params, **_strip_kavach_kwargs(kwargs))

        if inspect.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    return decorator


def _build_context(
    action_name: str,
    param_fields: dict[str, str],
    kwargs: dict,
    args: tuple,
    fn: Callable,
) -> tuple[ActionContext, dict]:
    """Build ActionContext from function kwargs."""
    principal_id = kwargs.pop("_principal_id", "unknown")
    principal_kind = kwargs.pop("_principal_kind", "user")
    roles = kwargs.pop("_roles", [])
    resource = kwargs.pop("_resource", None)
    ip = kwargs.pop("_ip", None)
    session_id = kwargs.pop("_session_id", None)

    # Extract numeric params for invariant checking
    params = {}
    sig = inspect.signature(fn)
    bound = sig.bind_partial(*args, **kwargs)
    bound.apply_defaults()

    for gate_param, fn_param in param_fields.items():
        if fn_param in bound.arguments:
            val = bound.arguments[fn_param]
            if isinstance(val, (int, float)):
                params[gate_param] = float(val)

    ctx = ActionContext(
        principal_id=principal_id,
        principal_kind=principal_kind,
        action_name=action_name,
        roles=roles,
        resource=resource,
        params=params or None,
        ip=ip,
        session_id=session_id,
    )

    return ctx, kwargs


def _build_tool_context(
    action_name: str,
    params: dict,
    kwargs: dict,
) -> ActionContext:
    """Build ActionContext from MCP tool params."""
    principal_id = kwargs.get("_principal_id", "unknown")
    principal_kind = kwargs.get("_principal_kind", "agent")
    roles = kwargs.get("_roles", [])
    ip = kwargs.get("_ip", None)
    session_id = kwargs.get("_session_id", None)

    # Extract numeric params for invariant checking
    numeric_params = {
        k: float(v) for k, v in params.items() if isinstance(v, (int, float))
    }

    return ActionContext(
        principal_id=principal_id,
        principal_kind=principal_kind,
        action_name=action_name,
        roles=roles,
        resource=params.get("resource"),
        params=numeric_params or None,
        ip=ip,
        session_id=session_id,
    )


def _strip_kavach_kwargs(kwargs: dict) -> dict:
    """Remove _kavach prefixed kwargs."""
    return {k: v for k, v in kwargs.items() if not k.startswith("_")}
