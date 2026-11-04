"""Proton guest-mode API client.

Clean-room implementation of Proton's "Continue as guest" / credentialless
login flow used by the official Android VPN app: anonymous session creation
followed by a credentialless upgrade that yields a Tier=0 VPN session bound
to a client-generated Ed25519 keypair.

Only the public API surface needed to log in, fetch the free-tier server
list, and obtain a WireGuard certificate is implemented here. The actual
tunnel bring-up is handled by the orchestrator / VPN controller.
"""

from .guest import (  # noqa: F401
    API_BASE,
    GUEST_HEADERS,
    GuestAuth,
    GuestAuthError,
    GuestCertificate,
    GuestLogicalServer,
    GuestSession,
    WG_DEFAULT_PORT,
    build_wg_quick_config,
    default_headers,
    gen_device_keypair,
    gen_x25519_keypair,
    make_challenge_payload,
)

__all__ = [
    "API_BASE",
    "GUEST_HEADERS",
    "GuestAuth",
    "GuestAuthError",
    "GuestCertificate",
    "GuestLogicalServer",
    "GuestSession",
    "WG_DEFAULT_PORT",
    "build_wg_quick_config",
    "default_headers",
    "gen_device_keypair",
    "gen_x25519_keypair",
    "make_challenge_payload",
]
