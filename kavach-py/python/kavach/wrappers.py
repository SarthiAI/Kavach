"""Idiomatic Python wrapper around the Rust Gate."""

from pathlib import Path
from kavach._kavach_engine import (
    ActionContext,
    Gate as _RustGate,
    PqTokenSigner,
    Verdict,
)


class Gate:
    """Kavach execution gate — all evaluation runs in Rust.

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
        """
        rg = _RustGate(
            policy_toml=policy_toml,
            invariants=invariants or [],
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
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
    ) -> "Gate":
        """Create a gate from a TOML policy file."""
        content = Path(path).read_text()
        return cls.from_toml(
            content,
            invariants=invariants,
            observe_only=observe_only,
            max_session_actions=max_session_actions,
            enable_drift=enable_drift,
            token_signer=token_signer,
            geo_drift_max_km=geo_drift_max_km,
        )

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
