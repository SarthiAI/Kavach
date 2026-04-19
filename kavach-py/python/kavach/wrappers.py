"""Idiomatic Python wrapper around the Rust Gate."""

from pathlib import Path
from typing import Any, Mapping, Union

from kavach._kavach_engine import (
    ActionContext,
    Gate as _RustGate,
    InMemoryInvalidationBroadcaster,
    PqTokenSigner,
    RedisInvalidationBroadcaster,
    RedisRateLimitStore,
    Verdict,
)

BroadcasterBackend = Union[InMemoryInvalidationBroadcaster, RedisInvalidationBroadcaster]


class Gate:
    """Kavach execution gate, all evaluation runs in Rust.

    Create from a TOML string, file, or dict of options.

    Example:
        gate = Gate.from_file("kavach.toml", invariants=[("max_refund", "amount", 50000)])
        verdict = gate.evaluate(ctx)
        if verdict.is_permit:
            do_the_thing()
    """

    def __init__(self, rust_gate: _RustGate):
        self._gate = rust_gate

    @classmethod
    def from_toml(
        cls,
        policy_toml: str,
        *,
        invariants: list[tuple[str, str, float]] | None = None,
        observe_only: bool = False,
        max_session_actions: int | None = None,
        enable_drift: bool = True,
        token_signer: PqTokenSigner | None = None,
        geo_drift_max_km: float | None = None,
        rate_store: RedisRateLimitStore | None = None,
        broadcaster: BroadcasterBackend | None = None,
    ) -> "Gate":
        """Create a gate from a TOML policy string.

        Args:
            policy_toml: TOML string with [[policy]] definitions.
            invariants: List of (name, field, max_value) for param_max invariants.
            observe_only: If True, log but never block.
            max_session_actions: Hard limit on actions per session.
            enable_drift: Enable built-in drift detectors.
            token_signer: Optional PqTokenSigner. When set, every Permit
                verdict carries a signed envelope in `verdict.signature`. If
                signing fails the gate fails closed (Refuse).
            geo_drift_max_km: Tolerance (km) for GeoLocationDrift. When
                unset, any mid-session IP change is a Violation. When set,
                IP changes within this distance are downgraded to Warning
                (requires both current_geo and origin_geo with
                latitude/longitude).
            rate_store: Optional ``RedisRateLimitStore``, swaps the
                default in-memory rate counter for a Redis-backed one
                that stays consistent across service replicas. Fail-closed
                on any Redis error (a ``record`` failure refuses the
                action).
            broadcaster: Optional ``RedisInvalidationBroadcaster``,
                publishes ``Invalidate`` verdicts to a Redis Pub/Sub
                channel so peer nodes drop the session locally. Publish
                failures are logged but never downgrade the local
                verdict (fail-closed locally, best-effort globally).
        """
        rg = _RustGate(
            policy_toml=policy_toml,
            invariants=invariants or [],
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
            rate_store=rate_store,
            broadcaster=broadcaster,
        )
        return cls(rg)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        invariants: list[tuple[str, str, float]] | None = None,
        observe_only: bool = False,
        max_session_actions: int | None = None,
        enable_drift: bool = True,
        token_signer: PqTokenSigner | None = None,
        geo_drift_max_km: float | None = None,
        rate_store: RedisRateLimitStore | None = None,
        broadcaster: BroadcasterBackend | None = None,
    ) -> "Gate":
        """Create a gate from a TOML policy file. See ``from_toml`` for kwargs."""
        content = Path(path).read_text()
        return cls.from_toml(
            content,
            invariants=invariants,
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
            rate_store=rate_store,
            broadcaster=broadcaster,
        )

    @classmethod
    def from_dict(
        cls,
        policies: Mapping[str, Any],
        *,
        invariants: list[tuple[str, str, float]] | None = None,
        observe_only: bool = False,
        max_session_actions: int | None = None,
        enable_drift: bool = True,
        token_signer: PqTokenSigner | None = None,
        geo_drift_max_km: float | None = None,
        rate_store: RedisRateLimitStore | None = None,
        broadcaster: BroadcasterBackend | None = None,
    ) -> "Gate":
        """Create a gate from a Python dict carrying the policy schema.

        The dict must have a top-level ``policies`` list. Each entry is itself
        a dict with ``name``, ``effect``, ``conditions`` (required) plus
        optional ``description`` and ``priority``. Each condition is a dict
        with one key naming the variant (``identity_kind``, ``param_max``,
        ``rate_limit``, ...).

        Example::

            gate = Gate.from_dict({
                "policies": [
                    {
                        "name": "agent_small_refunds",
                        "effect": "permit",
                        "conditions": [
                            {"identity_kind": "agent"},
                            {"action": "issue_refund"},
                            {"param_max": {"field": "amount", "max": 5000.0}},
                        ],
                    },
                ],
            })

        Typo'd or unknown field names raise ``ValueError`` instead of being
        silently dropped (deny_unknown_fields contract). All other kwargs
        match :meth:`from_toml`.
        """
        rg = _RustGate.from_dict(
            policies,
            invariants=invariants or [],
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
            rate_store=rate_store,
            broadcaster=broadcaster,
        )
        return cls(rg)

    @classmethod
    def from_json_string(
        cls,
        json_string: str,
        *,
        invariants: list[tuple[str, str, float]] | None = None,
        observe_only: bool = False,
        max_session_actions: int | None = None,
        enable_drift: bool = True,
        token_signer: PqTokenSigner | None = None,
        geo_drift_max_km: float | None = None,
        rate_store: RedisRateLimitStore | None = None,
        broadcaster: BroadcasterBackend | None = None,
    ) -> "Gate":
        """Create a gate from a JSON string carrying the policy schema.

        Same vocabulary as :meth:`from_dict`. Useful when the policy crosses
        a wire boundary (HTTP body, message queue, config service). Unknown
        fields raise ``ValueError``.
        """
        rg = _RustGate.from_json_string(
            json_string,
            invariants=invariants or [],
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
            rate_store=rate_store,
            broadcaster=broadcaster,
        )
        return cls(rg)

    @classmethod
    def from_json_file(
        cls,
        path: str | Path,
        *,
        invariants: list[tuple[str, str, float]] | None = None,
        observe_only: bool = False,
        max_session_actions: int | None = None,
        enable_drift: bool = True,
        token_signer: PqTokenSigner | None = None,
        geo_drift_max_km: float | None = None,
        rate_store: RedisRateLimitStore | None = None,
        broadcaster: BroadcasterBackend | None = None,
    ) -> "Gate":
        """Create a gate from a JSON policy file on disk. See :meth:`from_dict` for the schema."""
        rg = _RustGate.from_json_file(
            str(path),
            invariants=invariants or [],
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
            rate_store=rate_store,
            broadcaster=broadcaster,
        )
        return cls(rg)

    def evaluate(self, ctx: ActionContext) -> Verdict:
        """Evaluate an action context. Returns a Verdict.

        All evaluation logic (policy, drift, invariants) runs in Rust.
        """
        return self._gate.evaluate(ctx)

    def reload(self, policy_toml: str) -> None:
        """Hot-reload the policy set from a fresh TOML string.

        Parse errors raise ValueError; the previous good set stays in
        place. Empty TOML is valid (= default-deny everything).
        """
        self._gate.reload(policy_toml)

    def check(self, ctx: ActionContext) -> None:
        """Evaluate and raise if not permitted.

        Raises:
            kavach.Refused: If the gate refuses the action.
            kavach.Invalidated: If the gate invalidates the session.
        """
        verdict = self.evaluate(ctx)
        if verdict.is_refuse:
            raise Refused(verdict.reason, verdict.evaluator, verdict.code)
        if verdict.is_invalidate:
            raise Invalidated(verdict.reason, verdict.evaluator)

    @property
    def evaluator_count(self) -> int:
        return self._gate.evaluator_count


class Refused(Exception):
    """Raised when the gate refuses an action."""

    def __init__(self, reason: str, evaluator: str, code: str):
        self.reason = reason
        self.evaluator = evaluator
        self.code = code
        super().__init__(f"[{code}] {evaluator}: {reason}")


class Invalidated(Exception):
    """Raised when the gate invalidates a session."""

    def __init__(self, reason: str, evaluator: str):
        self.reason = reason
        self.evaluator = evaluator
        super().__init__(f"session invalidated by {evaluator}: {reason}")
