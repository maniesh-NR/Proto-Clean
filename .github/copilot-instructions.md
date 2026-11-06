# Copilot code review instructions — Proto Clean

Clean-room GPL-3.0 ProtonVPN client. No Proton source, binaries or assets; every
protocol/API detail was re-derived from public API traffic and official app
behavior. Desktop app: Python 3.11 + PySide6 (`proto_clean/`). Android app:
Kotlin + Jetpack Compose (`android/app/`). Desktop tests: pytest; Android tests:
JUnit. Current baseline: all tests green (682 desktop tests).

## What to report

Real bugs only: logic errors, crashes, race conditions, resource/socket leaks,
security regressions, incorrect error handling, and mismatches with the Proton
API wire format. For each issue, explain *why* it breaks, not just that a
pattern "may be risky".

## What NOT to report

- Style, naming, or docstring suggestions on internal helpers.
- Suggesting `@pytest.mark.asyncio` or native `async def` tests: CI intentionally
  runs pytest WITHOUT the pytest-asyncio plugin. Async tests must remain sync
  wrappers using the `_aitest` decorator (see `tests/test_perf_stability.py`)
  that calls `asyncio.run`. This is a hard CI constraint.
- `proto_clean/qtcompat.py` guarded imports and shims: intentional
  PySide6/PyQt6 compatibility layer.
- Function-local imports: intentional, keeps optional dependencies optional.
- The bundled protocol tooling under `proto_clean/vpn/protocols/` intentionally
  speaks many protocols; "too many dependencies" comments are not useful.

## Intentional design (context)

- Guest mode (no account) uses Proton's credentialless session flow: a session
  token obtained via refresh token, then WireGuard certificates via
  `POST /vpn/v1/certificate`. The client public key is sent as an X25519
  SubjectPublicKeyInfo PEM (equivalent to gopenpgp `publicKeyPKIXPem()`),
  matching the official Android client's `CertInfo.publicKeyPem`. The keypair
  must be generated in one step so the private key used in the request matches
  the public key sent — this pairing was a real bug once, do not suggest
  changing it.
- Server loads come from `/vpn/v1/loads`; the UI groups logical servers by
  region with pressable headers (see `proto_clean/ui/main_window.py`,
  `proto_clean/servers/`, and `android/.../ui/ServersScreen.kt`).
- Android APKs are release-signed via `signingConfigs` in
  `android/app/build.gradle.kts` (keystore from CI secret) so sideloaded builds
  are not treated as unverified; do not suggest removing the signing config.
- The desktop UI is single-threaded Qt: worker threads must not touch QWidget
  objects; they communicate via signals and `proto_clean/ui/bridge.py`.

## Extra scrutiny welcome here

- `proto_clean/proton/guest.py` and
  `android/app/src/main/java/app/protoclean/proton/GuestApi.kt`: token refresh
  races, certificate request payload format, parsing of server loads.
- `proto_clean/ui/main_window.py` and
  `android/app/src/main/java/app/protoclean/ui/ServersScreen.kt`: region
  expand/collapse state handling and load rendering.
- Anything touching firewall/routes/killswitch (`proto_clean/vpn/killswitch.py`,
  `proto_clean/helper_win.py`, `proto_clean/platforms/`): fail-closed behavior
  is required.
