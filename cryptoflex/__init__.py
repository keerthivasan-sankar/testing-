"""
cryptoflex - a local-first crypto-agility policy engine.

Orchestrates existing, audited cryptographic primitives (classical X25519,
post-quantum ML-KEM via liboqs) behind a policy engine that picks the
right combination based on local signals only - no network calls, no
external services.

See README.md for the full design rationale.
"""

from .api import (
    DerivedRoot,
    KeySet,
    PublicBundle,
    decrypt,
    derive_root_key,
    encrypt,
    establish_keys,
    recover_root_key,
)
from .errors import DecryptionError, DowngradeError
from .header import CryptoflexHeader, HeaderParseError
from .policy import Constraint, PolicyDecision, PolicyEngine
from .profiles import PROFILES, SecurityProfile, get_profile
from .sources import (
    ClassicalSource,
    Encapsulation,
    PQCSource,
    SecuritySource,
    SourceUnavailableError,
)

__version__ = "0.2.0"

__all__ = [
    # high-level AEAD API (recommended)
    "encrypt",
    "decrypt",
    # low-level key derivation
    "establish_keys",
    "derive_root_key",
    "recover_root_key",
    # data classes
    "KeySet",
    "PublicBundle",
    "DerivedRoot",
    # header
    "CryptoflexHeader",
    "HeaderParseError",
    # policy
    "PolicyEngine",
    "PolicyDecision",
    "Constraint",
    # profiles
    "PROFILES",
    "SecurityProfile",
    "get_profile",
    # sources
    "SecuritySource",
    "ClassicalSource",
    "PQCSource",
    "Encapsulation",
    "SourceUnavailableError",
    # errors
    "DecryptionError",
    "DowngradeError",
]
