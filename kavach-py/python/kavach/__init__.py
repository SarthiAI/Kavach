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
    DirectoryTokenVerifier,
    GeoLocation,
    KavachKeyPair,
    PermitToken,
    PqTokenSigner,
    PublicKeyBundle,
    PublicKeyDirectory,
    SecureChannel,
    SignedAuditChain,
    Verdict,
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
    "Refused",
    "Invalidated",
    "guarded",
    "guarded_tool",
    "McpKavachMiddleware",
    "HttpKavachMiddleware",
]
