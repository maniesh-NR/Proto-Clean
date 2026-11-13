#!/usr/bin/env python3
"""Live probe of the Proton credentialless API: logicals shape + cert flow.

1. guest login (anonymous session -> credentialless upgrade)
2. GET /vpn/v2/logicals raw -> print first entry keys + Load value
3. POST /vpn/v1/certificate with the Ed25519 public key in PKIX PEM form
   (official-client shape) and with the raw X25519 key (our old, buggy shape)
4. GET /vpn/v1/loads -> load endpoint shape
"""
import asyncio
import base64
import hashlib
import json
import sys

sys.path.insert(0, "/home/z/my-project/cleanroom")

from proto_clean.proton.guest import GuestAuth, gen_device_keypair, API_BASE


def ed_pub_pem(priv_bytes: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def ed25519_seed_to_x25519_priv_b64(seed: bytes) -> str:
    return base64.b64encode(hashlib.sha512(seed).digest()[:32]).decode()


async def main() -> None:
    async with GuestAuth() as auth:
        session = await auth.login()
        print("== guest login OK, uid:", session.uid[:8], "…")

        # ---- 2. raw logicals ------------------------------------------------
        resp = await auth.client.get(
            f"{API_BASE}/vpn/v2/logicals",
            params={"WithEntriesForProtocols": "wireguard", "WithState": "true"},
            headers=auth._auth_headers(session),
        )
        resp.raise_for_status()
        data = resp.json()
        servers = data.get("LogicalServers") or []
        print(f"\n== logicals: {len(servers)} entries")
        if servers:
            first = servers[0]
            print("first entry keys:", sorted(first.keys()))
            slim = {k: first.get(k) for k in
                    ("Name", "ExitCountry", "Tier", "Load", "Score", "Status")}
            print("first entry (slim):", json.dumps(slim))
            loads = [s.get("Load") for s in servers[:8]]
            print("first 8 loads:", loads)

        # ---- 3. certificate: official shape vs old shape ---------------------
        pem = ed_pub_pem(session.device_ed25519_priv)
        print("\n== cert request (official shape: Ed25519 PKIX PEM)")
        body = {
            "ClientPublicKey": pem,
            "ClientPublicKeyMode": "EC",
            "DeviceName": "SM-S901U",
            "Mode": "session",
            "Features": [],
        }
        r = await auth.client.post(f"{API_BASE}/vpn/v1/certificate",
                                   json=body, headers=auth._auth_headers(session))
        print("status:", r.status_code)
        try:
            j = r.json()
            print("code:", j.get("Code"))
            inner = j.get("Response") or {}
            print("response keys:", sorted(inner.keys()) if inner else j)
            if inner.get("Certificate"):
                print("cert PEM head:", inner["Certificate"][:60].replace("\n", "\\n"))
                print("expires:", inner.get("ExpirationTime"))
        except Exception as e:  # noqa: BLE001
            print("body:", r.text[:300], e)

        # the WG private key that pairs with the sent Ed25519 key
        wg_priv = ed25519_seed_to_x25519_priv_b64(session.device_ed25519_priv)
        print("derived wg private key (pairs with the cert):", wg_priv[:8], "…")

        # ---- 4. loads endpoint ------------------------------------------------
        r2 = await auth.client.get(f"{API_BASE}/vpn/v1/loads",
                                   headers=auth._auth_headers(session))
        print("\n== /vpn/v1/loads status:", r2.status_code)
        if r2.status_code == 200:
            j2 = r2.json()
            entries = (j2.get("LogicalServers")
                       or (j2.get("Response") or {}).get("LogicalServers") or [])
            print("entries:", len(entries))
            if entries:
                print("first:", json.dumps(entries[0]))


asyncio.run(main())
