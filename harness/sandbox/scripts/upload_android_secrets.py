#!/usr/bin/env python3
"""Upload the Android release-keystore secrets to the Proto-Clean repo.

Uses GitHub Actions secrets API: fetch the repo public key, seal each
value with libsodium (PyNaCl), PUT the encrypted secret.
"""
import base64
import json
import os
import sys
import urllib.request

from nacl import encoding, public

REPO = "maniesh-NR/Proto-Clean"
TOKEN = os.environ["GH_TOKEN"]

KEYSTORE = "/home/z/my-project/secrets/protoclean-release.keystore"
PASSWORD_FILE = "/home/z/my-project/secrets/protoclean-keystore.password"


def api(method: str, path: str, body: dict | None = None):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/{path}",
        method=method,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        data=json.dumps(body).encode() if body is not None else None,
    )
    with urllib.request.urlopen(req) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def main() -> None:
    pk_resp = api("GET", "actions/secrets/public-key")
    pk = public.PublicKey(pk_resp["key"].encode(), encoding.Base64Encoder())
    sealed = public.SealedBox(pk)

    password = open(PASSWORD_FILE).read().strip()
    keystore_b64 = base64.b64encode(open(KEYSTORE, "rb").read()).decode()

    secrets = {
        "PROTO_ANDROID_KEYSTORE_B64": keystore_b64,
        "PROTO_ANDROID_KEYSTORE_PASSWORD": password,
        "PROTO_ANDROID_KEY_ALIAS": "protoclean",
        "PROTO_ANDROID_KEY_PASSWORD": password,
    }
    for name, value in secrets.items():
        enc = sealed.encrypt(value.encode())
        api("PUT", f"actions/secrets/{name}", {
            "encrypted_value": base64.b64encode(enc).decode(),
            "key_id": pk_resp["key_id"],
        })
        print(f"secret {name}: uploaded")


if __name__ == "__main__":
    sys.exit(main())
