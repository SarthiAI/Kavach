"""Key + directory setup for the demo.

In a real deployment:

- The agent generates its own keypair at startup (or loads from KMS / Vault).
- An ops team signs a directory manifest containing that bundle with a root
  key, and ships the manifest to verifiers (e.g., the payment service).
- Verifiers load the manifest from disk, pinning the root VK from config.

For this demo we do all three in one setup step since everything runs on
localhost. The agent keypair stays **in memory** inside the agent process —
only the directory manifest and the pinned root VK touch disk.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from kavach import KavachKeyPair

STATE_DIR = Path(__file__).parent / "state"


@dataclass
class Bootstrap:
    """Key material produced by [`setup`]."""

    root_kp: KavachKeyPair
    """ML-DSA root that signs the directory manifest. Ops controls this."""

    agent_kp: KavachKeyPair
    """Agent's own keypair. Signs every PermitToken + audit entry."""

    directory_path: Path
    """Signed directory manifest on disk. The payment service reads this."""

    root_vk_path: Path
    """Pinned root VK the payment service loads. Equivalent to a config secret."""


def setup(state_dir: Path = STATE_DIR) -> Bootstrap:
    """Generate keys, write the signed directory + pinned root VK to disk.

    Idempotent-ish: regenerates fresh keys on every call, so the previous
    run's directory bytes are overwritten. Keeps runs clean.
    """
    state_dir.mkdir(exist_ok=True)

    root_kp = KavachKeyPair.generate()
    agent_kp = KavachKeyPair.generate()

    directory_path = state_dir / "directory.json"
    root_vk_path = state_dir / "root_vk.bin"

    # Sign the directory with the root key's ML-DSA seed (never crosses FFI).
    directory_path.write_bytes(
        root_kp.build_signed_manifest([agent_kp.public_keys()])
    )
    root_vk_path.write_bytes(bytes(root_kp.public_keys().ml_dsa_verifying_key))

    return Bootstrap(
        root_kp=root_kp,
        agent_kp=agent_kp,
        directory_path=directory_path,
        root_vk_path=root_vk_path,
    )


if __name__ == "__main__":
    # When run directly, just emit a setup so an operator can see what
    # would land on disk.
    bs = setup()
    print(f"  ✓ root VK       → {bs.root_vk_path}  ({bs.root_vk_path.stat().st_size} bytes)")
    print(f"  ✓ directory     → {bs.directory_path}  ({bs.directory_path.stat().st_size} bytes)")
    print(f"  ✓ agent key_id  = {bs.agent_kp.public_keys().id}")
    print("Setup complete. Directory + root VK are ready for the payment service.")
