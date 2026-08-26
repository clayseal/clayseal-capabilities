"""Ed25519 signing for the evidence plane.

Shared, identity-agnostic primitive: receipts, audit records, and (when the Layer-1
partner wires it) agent identity `verification_methods` all sign over the canonical JSON
hash of the object minus its signature field. Keys live under ``keys/signing/`` mirroring
the Rust ``setup`` convention for the policy circuit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agentauth.core.hash_util import hash_canonical_json

DEFAULT_KEY_DIR = Path("keys/signing")
TRUSTED_SIGNER_PUBLIC_KEYS_ENV = "AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS"
TRUSTED_SIGNER_KEY_IDS_ENV = "AGENT_RECEIPTS_TRUSTED_SIGNER_KEY_IDS"
SIGNING_KEY_PASSWORD_ENV = "AGENT_RECEIPTS_SIGNING_KEY_PASSWORD"
PRIVATE_KEY_MODE = 0o600


def _signing_payload(value: Any) -> bytes:
    """Canonical bytes signed over: the sha256 hex of the object's canonical JSON."""
    return hash_canonical_json(value).encode("utf-8")


def key_id_for_public_key_hex(public_key_hex: str) -> str:
    return hash_canonical_json({"ed25519_pub": public_key_hex})


def _split_env_list(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def trusted_signer_policy_from_env() -> dict[str, set[str]]:
    return {
        "public_keys": _split_env_list(TRUSTED_SIGNER_PUBLIC_KEYS_ENV),
        "key_ids": _split_env_list(TRUSTED_SIGNER_KEY_IDS_ENV),
    }


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 keypair with a stable hex key id (sha256 of the public key)."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def public_key_hex(self) -> str:
        return self.public_key.public_bytes_raw().hex()

    @property
    def key_id(self) -> str:
        return key_id_for_public_key_hex(self.public_key_hex)

    def sign(self, value: Any) -> dict[str, str]:
        """Sign an object (or its unsigned dict) → a signature descriptor."""
        sig = self.private_key.sign(_signing_payload(value))
        return {
            "alg": "ed25519",
            "key_id": self.key_id,
            "public_key": self.public_key_hex,
            "signature": sig.hex(),
        }


def generate_keypair() -> SigningKey:
    private_key = Ed25519PrivateKey.generate()
    return SigningKey(private_key=private_key, public_key=private_key.public_key())


def signature_key_id_matches(signature: dict[str, str]) -> bool:
    """True when ``key_id`` is the canonical hash of ``public_key``."""
    public_key = signature.get("public_key")
    key_id = signature.get("key_id")
    if not isinstance(public_key, str) or not isinstance(key_id, str):
        return False
    expected = hash_canonical_json({"ed25519_pub": public_key})
    return key_id == expected


def sign(value: Any, key: SigningKey) -> dict[str, str]:
    """Sign ``value`` with ``key`` (convenience wrapper)."""
    return key.sign(value)


def verify(value: Any, signature: dict[str, str]) -> bool:
    """Verify a signature descriptor (as produced by ``SigningKey.sign``) over ``value``."""
    if signature.get("alg") != "ed25519":
        return False
    if not signature_key_id_matches(signature):
        return False
    try:
        public_key_hex = signature["public_key"]
        if signature.get("key_id") != key_id_for_public_key_hex(public_key_hex):
            return False
        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex)
        )
        public_key.verify(bytes.fromhex(signature["signature"]), _signing_payload(value))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def trusted_signer_public_keys() -> set[str] | None:
    """Load pinned signer keys from ``AGENT_RECEIPTS_TRUSTED_SIGNERS`` (hex, comma-separated)."""
    raw = os.environ.get("AGENT_RECEIPTS_TRUSTED_SIGNERS")
    if not raw:
        return None
    keys: set[str] = set()
    for item in raw.split(","):
        normalized = item.strip().removeprefix("ed25519:")
        if normalized:
            keys.add(normalized)
    return keys or None


def _signing_key_password(
    password: bytes | str | None = None,
) -> bytes | None:
    if password is not None:
        return password.encode("utf-8") if isinstance(password, str) else password
    raw = os.environ.get(SIGNING_KEY_PASSWORD_ENV, "").strip()
    return raw.encode("utf-8") if raw else None


def _ensure_restrictive_key_permissions(path: Path) -> None:
    if not path.is_file():
        return
    try:
        mode = path.stat().st_mode & 0o777
        if mode != PRIVATE_KEY_MODE:
            path.chmod(PRIVATE_KEY_MODE)
    except OSError:
        return


def _load_pem_private_key(path: Path, *, password: bytes | None) -> Ed25519PrivateKey:
    pem = path.read_bytes()
    try:
        private_key = serialization.load_pem_private_key(pem, password=password)
    except TypeError as exc:
        if password is None:
            raise ValueError(
                f"{path} is password-protected; set {SIGNING_KEY_PASSWORD_ENV} "
                "or pass password= to load_or_create_key()"
            ) from exc
        raise ValueError(f"failed to decrypt signing key at {path}") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return private_key


def _write_private_key(
    path: Path,
    key: SigningKey,
    *,
    password: bytes | None,
) -> None:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password is not None
        else serialization.NoEncryption()
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    )
    path.chmod(PRIVATE_KEY_MODE)


def sign_bundle(
    bundle: dict[str, Any], key: SigningKey, *, role: str = "agent"
) -> dict[str, Any]:
    """Append an envelope-level signature over the bundle (minus its ``signatures``).

    Additive: returns the same bundle with ``bundle["signatures"]`` extended. Designed
    to be called after a receipt bundle is built, so it composes with an evolving
    bundle schema without touching its internal fields.
    """
    unsigned = {k: v for k, v in bundle.items() if k != "signatures"}
    descriptor = {"role": role, **key.sign(unsigned)}
    bundle.setdefault("signatures", []).append(descriptor)
    return bundle


def verify_bundle_signatures(
    bundle: dict[str, Any],
    *,
    trusted_public_keys: set[str] | None = None,
    trusted_key_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Verify bundle signatures and require trusted signers when configured."""
    unsigned = {k: v for k, v in bundle.items() if k != "signatures"}
    signatures = bundle.get("signatures", [])
    reasons: list[str] = []
    signers: list[str] = []
    trusted_signers: list[str] = []
    cryptographically_valid = True
    trusted_public_keys = set(trusted_public_keys or ())
    trusted_key_ids = set(trusted_key_ids or ())
    legacy = trusted_signer_public_keys()
    if legacy:
        trusted_public_keys |= legacy
    trust_configured = bool(trusted_public_keys or trusted_key_ids)

    for sig in signatures:
        role = sig.get("role", sig.get("key_id", "unknown"))
        public_key_hex = sig.get("public_key")
        key_id = sig.get("key_id")
        if not signature_key_id_matches(sig):
            cryptographically_valid = False
            reasons.append(f"signature key_id does not match public_key: {role}")
            continue
        if verify(unsigned, sig):
            signers.append(role)
            trusted = False
            if public_key_hex and public_key_hex in trusted_public_keys:
                trusted = True
            if key_id and key_id in trusted_key_ids:
                trusted = True
            if trust_configured:
                if trusted:
                    trusted_signers.append(role)
                else:
                    reasons.append(f"untrusted signer: {role}")
        else:
            cryptographically_valid = False
            reasons.append(f"invalid signature: {role}")

    if signatures and not trust_configured:
        reasons.append("no trusted signer policy configured")

    return {
        "valid": (
            len(signatures) > 0
            and cryptographically_valid
            and trust_configured
            and len(trusted_signers) == len(signatures)
            and not reasons
        ),
        "signed": len(signatures) > 0,
        "cryptographically_valid": len(signatures) > 0 and cryptographically_valid,
        "trust_configured": trust_configured,
        "signers": signers,
        "trusted_signers": trusted_signers,
        "reasons": reasons,
    }


def load_signing_key_from_pem(pem: str) -> SigningKey:
    """Load an Ed25519 signing key from a PEM-encoded private key string."""
    private_key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("PEM private key must be Ed25519")
    return SigningKey(private_key=private_key, public_key=private_key.public_key())


def load_or_create_key(
    path: str | Path = DEFAULT_KEY_DIR / "agent_ed25519.key",
    *,
    password: bytes | str | None = None,
    require_encryption: bool | None = None,
) -> SigningKey:
    """Load a PEM-encoded Ed25519 private key, or create and persist a new one."""
    from agentauth.core.production import is_production

    if require_encryption is None:
        require_encryption = is_production()
    dest = Path(path)
    resolved_password = _signing_key_password(password)
    if dest.is_file():
        private_key = _load_pem_private_key(dest, password=resolved_password)
        _ensure_restrictive_key_permissions(dest)
        return SigningKey(private_key=private_key, public_key=private_key.public_key())

    if require_encryption and resolved_password is None:
        raise ValueError(
            f"refusing to create unencrypted signing key at {dest}; "
            f"set {SIGNING_KEY_PASSWORD_ENV} or pass password="
        )

    key = generate_keypair()
    _write_private_key(dest, key, password=resolved_password)
    return key
