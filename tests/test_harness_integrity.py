"""Machine-checked integrity of the agent harness.

G1-iter3 (Architect major #4): every harness rule that previous gates
caught humans breaking — no pre-recording gate outcomes, ledger
discipline, record existence, the sandbox/ ignore guard — is enforced
here by CI instead of by good intentions. Also exercises the backup
script end-to-end via its documented env overrides, hermetically
(the overrides existed since G1-iter2 but were consumed by no
automated test).
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "harness"


# ------------------------------------------------------- structural rules
def test_gitignore_still_guards_harness_sandbox():
    """The v1 resurrection path: harness/sandbox/ must stay ignored on
    main so backup state can never leak into product commits."""
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert re.search(r"^harness/sandbox/\s*$", gi, re.M), (
        "the harness/sandbox/ ignore guard is missing from .gitignore")


def test_roadmap_glyphs_backed_by_gate_records():
    """Every roadmap stage marked done (☑) or active (◐) must be
    mentioned by a consensus-log record — a stage cannot claim a gate
    outcome that no record contains (the no-pre-recording rule)."""
    log_dir = HARNESS / "memory" / "consensus-log"
    records = "\n".join(p.name + "\n" + p.read_text(encoding="utf-8")
                        for p in log_dir.glob("*.md"))
    roadmap = (HARNESS / "roadmap.md").read_text(encoding="utf-8")
    for line in roadmap.splitlines():
        if ("☑" in line or "◐" in line):
            m = re.search(r"\bS(\d+)\b", line)
            if not m:
                continue  # shipped-line items without a stage id
            sid = "S" + m.group(1)
            assert sid in records, (
                f"roadmap marks {sid} as done/active but no consensus-log "
                f"record mentions it")


def test_deferred_findings_reference_real_targets():
    """Every ledger 'Gate before' value must name a roadmap stage, a
    version tag, or the explicit standing marker — nothing can be
    silently parked nowhere."""
    ledger = (HARNESS / "memory" / "deferred-findings.md").read_text(
        encoding="utf-8")
    roadmap = (HARNESS / "roadmap.md").read_text(encoding="utf-8")
    stages = set(re.findall(r"\bS\d+\b", roadmap))
    rows = re.findall(r"^\|\s*\d+\s*\|", ledger, re.M)
    assert rows, "the deferred-findings table lost its rows"
    for m in re.finditer(r"^\|\s*(\d+)\s*\|.*?\|\s*([^|]+?)\s*\|\s*$",
                         ledger, re.M):
        gate = m.group(2)
        if re.match(r"^v\d+\.\d+\.\d+", gate):    # a version tag
            continue
        if gate.startswith("—"):                    # standing marker
            continue
        assert any(t in gate for t in stages), (
            f"ledger #{m.group(1)} gate target {gate!r} names no roadmap stage")


def test_harness_doc_references_resolve():
    """Any harness/... doc reference inside the harness must point at a
    file that exists (no dangling memory records)."""
    for p in sorted(HARNESS.rglob("*.md")):
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(
                r"(?:memory|consensus-log|process|backups)/"
                r"[A-Za-z0-9_.\-/]+?\.md", text):
            ref = m.group(0)
            # refs are relative to harness/ except consensus-log/,
            # which is relative to harness/memory/
            target = (HARNESS / "memory" / ref
                      if ref.startswith("consensus-log/")
                      else HARNESS / ref)
            assert target.exists(), (
                f"{p.relative_to(ROOT)} references missing {ref}")


@pytest.mark.skipif(os.name != "posix",
                    reason="Windows runners' 'bash' is the WSL stub (no "
                            "distro installed) — POSIX legs guard the script")
def test_backup_script_syntax():
    """The backup script must stay valid bash (cheap guard, POSIX legs)."""
    script = ROOT / "scripts" / "sandbox_backup.sh"
    r = subprocess.run(["bash", "-n", str(script)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_version_strings_agree():
    """The 7 release-files' version must agree with pyproject (stale
    versions are the #1 release-runbook failure mode)."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    assert m, "pyproject version missing"
    version = m.group(1)
    init = (ROOT / "proto_clean" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{version}"' in init
    # during a release bump all files move together; outside a release
    # they must all agree
    for rel, pattern in [
        ("packaging/windows/installer.iss", r'#define AppVersion "VERSION"'),
        ("packaging/macos/Info.plist", r"<string>VERSION</string>"),
    ]:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert pattern.replace("VERSION", version) in text, (
            f"{rel} does not carry version {version}")


# ------------------------------------------------- hermetic backup cycle
@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_hermetic_cycle(tmp_path):
    """The event-driven backup script, executed end-to-end in a scratch
    clone + bare remote via the documented env overrides (G1-iter3):
    fresh-create, append, and a planted secret aborting BEFORE any
    push. The overrides were built for exactly this and are now
    consumed by CI on every push to main.

    Ambient git config is NEUTRALIZED inside the runs
    (GIT_CONFIG_GLOBAL/SYSTEM -> /dev/null): CI runners configure no
    git identity at all — the first CI execution of this test failed
    on 5/7 legs at the script's first `git commit` — so every machine
    now exercises the SAME path: the script's built-in identity
    fallback (see scripts/sandbox_backup.sh).

    NOTE: the source checkout must carry full history (CI uses
    fetch-depth: 0) — a shallow ROOT makes the scratch clone shallow
    and every push to the bare is rejected with "shallow update not
    allowed" (the second CI break, 2026-11-14)."""
    script = ROOT / "scripts" / "sandbox_backup.sh"
    repo = tmp_path / "clone"
    bare = tmp_path / "bare.git"
    home = tmp_path / "home"

    subprocess.run(["git", "clone", "-q", str(ROOT), str(repo)],
                   check=True, timeout=120)
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "set-url",
                    "origin", str(bare)], check=True)
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "ok.py").write_text("print('hi')\n")

    env = {"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
           "PC_BACKUP_PUSH_REMOTE": str(bare)}

    def run_backup(message):
        e = dict(os.environ)
        e.update(env)
        # no ambient identity/config: identical behavior on CI runners
        # (which have none) and dev machines (which do) — the script's
        # identity fallback commits on every platform
        e["GIT_CONFIG_GLOBAL"] = os.devnull
        e["GIT_CONFIG_SYSTEM"] = os.devnull
        return subprocess.run(["bash", str(script), message],
                              cwd=str(repo), env=e,
                              capture_output=True, text=True, timeout=240)

    # 1. fresh-create
    r1 = run_backup("hermetic first")
    assert r1.returncode == 0, r1.stdout + r1.stderr
    # 2. append (seq increments)
    r2 = run_backup("hermetic second")
    assert r2.returncode == 0, r2.stdout + r1.stderr
    manifest = subprocess.run(
        ["git", "-C", str(repo), "show",
         "sandbox/backups:harness/backups/manifest.json"],
        capture_output=True, text=True, check=True).stdout
    assert '"seq": 2' in manifest, "second backup must append (seq 2)"
    # 3. planted secret (built at runtime — no literal in this file).
    #    show-ref --verify: exit 1 with NO stdout when the ref is
    #    missing — a bare `rev-parse <ref>` ECHOES the unknown ref
    #    name to stdout, which once made a non-empty-output assert
    #    pass spuriously (the third CI-break layer, 2026-11-14).
    fake = "gh" + "p_" + "a" * 36
    (home / "scripts" / "leaky.py").write_text(f"t = '{fake}'\n")
    r_tip = subprocess.run(
        ["git", "-C", str(bare), "show-ref", "--verify",
         "refs/heads/sandbox/backups"],
        capture_output=True, text=True)
    assert r_tip.returncode == 0, (
        "sandbox/backups never landed in the bare although both runs "
        "exited 0 — run1 output: " + (r1.stdout + r1.stderr).strip()
        + " || run2 output: " + (r2.stdout + r2.stderr).strip())
    bare_tip = r_tip.stdout.split()[0]
    r3 = run_backup("hermetic secret")
    assert r3.returncode == 4, (r3.returncode, r3.stdout + r3.stderr)
    r_after = subprocess.run(
        ["git", "-C", str(bare), "show-ref", "--verify",
         "refs/heads/sandbox/backups"],
        capture_output=True, text=True)
    assert r_after.returncode == 0, (
        "branch vanished from the bare after the abort run: "
        + r3.stdout + r3.stderr)
    after = r_after.stdout.split()[0]
    assert after == bare_tip, "secret-bearing run must not move the remote"
    # 4. the main checkout is never dirtied
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                            capture_output=True, text=True,
                            check=True).stdout
    assert status.strip() == "", "backup must not dirty the main checkout"
