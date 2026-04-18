"""
Kavach कवच — Post-quantum execution boundary enforcement.

All gate evaluation runs in compiled Rust via the _kavach_engine module.
This package provides idiomatic Python wrappers, decorators, and helpers.

    from kavach import Gate, ActionContext

    gate = Gate.from_file("kavach.toml")
    verdict = gate.evaluate(ctx)
"""

from kavach._kavach_engine import Gate as _RustGate
from kavach._kavach_engine import (
    ActionContext,
    AuditEntry,
    DeviceFingerprint,
    DirectoryTokenVerifier,
    GeoLocation,
    InMemoryInvalidationBroadcaster,
    InMemorySessionStore,
    InvalidationListenerHandle,
    InvalidationScope,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    PublicKeyBundle,
    PublicKeyDirectory,
    RedisInvalidationBroadcaster,
    RedisRateLimitStore,
    RedisSessionStore,
    SecureChannel,
    SignedAuditChain,
    Verdict,
    spawn_invalidation_listener,
)
from kavach.wrappers import Gate, Refused, Invalidated
from kavach.decorators import guarded, guarded_tool
from kavach.mcp import McpKavachMiddleware
from kavach.http import HttpKavachMiddleware

__version__ = "0.1.0"
__all__ = [
    "Gate",
    "ActionContext",
    "GeoLocation",
    "DeviceFingerprint",
    "Verdict",
    "PermitToken",
    "PqTokenSigner",
    "KavachKeyPair",
    "PublicKeyBundle",
    "AuditEntry",
    "SignedAuditChain",
    "SecureChannel",
    "PublicKeyDirectory",
    "DirectoryTokenVerifier",
    "InMemorySessionStore",
    "InMemoryInvalidationBroadcaster",
    "InvalidationListenerHandle",
    "InvalidationScope",
    "RedisRateLimitStore",
    "RedisSessionStore",
    "RedisInvalidationBroadcaster",
    "spawn_invalidation_listener",
    "Refused",
    "Invalidated",
    "guarded",
    "guarded_tool",
    "McpKavachMiddleware",
    "HttpKavachMiddleware",
]
