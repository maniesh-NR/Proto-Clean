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


FINAL_OUTCOME_LINE = re.compile(r"(?m)^FINAL OUTCOME: .+$")
CONSENSUS_REACHED_LINE = re.compile(r"(?m)^FINAL OUTCOME: CONSENSUS REACHED\s*$")
GATE_RULE_ADOPTION = (2026, 11, 14)


def _record_date(name, text):
    """A record's effective date: the LATER of its filename date and
    its 'Date:' header (G1-iter4: a back-dated filename must not
    escape the rules)."""
    dates = []
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})-", name)
    if m:
        dates.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    h = re.search(r"(?m)^Date: (\d{4})-(\d{2})-(\d{2})", text)
    if h:
        dates.append((int(h.group(1)), int(h.group(2)), int(h.group(3))))
    return max(dates) if dates else None


def _gate_record_violations(per_record, roadmap):
    """All machine-checkable gate-record rules; returns violation
    strings (empty list = clean). Extracted into a helper so the check
    itself can be FALSIFIED with synthetic forgeries (see
    test_final_outcome_check_cannot_be_forged) — the G1-iter4
    Architect critical proved v4's substring check was satisfied by
    the iter-3 record's own documentation prose, so a pre-recorded
    stage closure passed CI for ANY stage."""
    violations = []
    for name, text in per_record.items():
        d = _record_date(name, text)
        if d is None or d < GATE_RULE_ADOPTION:
            continue
        lines = FINAL_OUTCOME_LINE.findall(text)
        if not lines:
            violations.append(
                f"{name} is dated on/after 2026-11-14 (the FINAL OUTCOME "
                f"rule's adoption) but carries no line-anchored "
                f"'FINAL OUTCOME:' line")
        elif len(lines) > 1:
            violations.append(
                f"{name} carries {len(lines)} 'FINAL OUTCOME:' lines — "
                f"exactly one machine-parseable closure line is required")
    records = "\n".join(name + "\n" + text
                        for name, text in per_record.items())
    for line in roadmap.splitlines():
        if ("☑" in line or "◐" in line):
            m = re.search(r"\bS(\d+)\b", line)
            if not m:
                continue  # shipped-line items without a stage id
            sid = "S" + m.group(1)
            if sid not in records:
                violations.append(
                    f"roadmap marks {sid} as done/active but no "
                    f"consensus-log record mentions it")
            if "☑" in line:
                backing = [n for n, t in per_record.items()
                           if sid in t
                           and CONSENSUS_REACHED_LINE.search(t)]
                if not backing:
                    violations.append(
                        f"roadmap marks {sid} done (☑) but no record both "
                        f"names it and carries a line-anchored 'FINAL "
                        f"OUTCOME: CONSENSUS REACHED' — inline/prose "
                        f"mentions do not back closure")
    return violations


def test_roadmap_glyphs_backed_by_gate_records():
    """Every roadmap stage marked done (☑) or active (◐) must be
    mentioned by a consensus-log record — a stage cannot claim a gate
    outcome that no record contains (the no-pre-recording rule).

    Strengthened twice:
    - G1-iter3-i2: a ☑ additionally requires a record naming the
      stage and carrying a FINAL OUTCOME: CONSENSUS REACHED line.
    - G1-iter4 (Architect CRITICAL): that line must be LINE-ANCHORED
      and EXACT — v4's substring check was satisfied by the iter-3
      record's own prose describing the rule, so flipping any stage's
      glyph to ☑ passed CI at 6324a4d. Also: exactly one closure line
      per record (dated by filename OR Date: header, whichever is
      later), so a record cannot carry both a NO-CONSENSUS and a
      CONSENSUS outcome.
    """
    log_dir = HARNESS / "memory" / "consensus-log"
    per_record = {p.name: p.read_text(encoding="utf-8")
                  for p in log_dir.glob("*.md")}
    roadmap = (HARNESS / "roadmap.md").read_text(encoding="utf-8")
    violations = _gate_record_violations(per_record, roadmap)
    assert not violations, "\n".join(violations)


def test_final_outcome_check_cannot_be_forged():
    """The G1-iter4 Architect critical, locked in: v4's ☑ check was
    satisfied by the iter-3 record's own PROSE (an inline mention of
    the required phrase), so a pre-recorded stage closure passed CI
    for ANY stage. Synthetic forgeries prove the hardened check
    catches inline-only mentions, double outcome lines, back-dated
    filenames (the Date: header governs) and unbacked glyphs — and
    accepts a proper anchored closure. The check guards the check
    (canary philosophy: a self-test that can go silently blind is
    worse than none)."""
    inline_only = ("# forged record\nDate: 2026-11-15\n\nThe rule says a "
                   "roadmap checkmark requires a `FINAL OUTCOME: CONSENSUS "
                   "REACHED` record naming the stage S100 — inline only.\n")
    double = ("# forged record\nDate: 2026-11-15\n\nFINAL OUTCOME: "
              "CONSENSUS REACHED\nFINAL OUTCOME: NO CONSENSUS\n")
    backdated = ("# forged record\nDate: 2026-11-15\n\n(no closure line at "
                 "all — the filename predates the rule's adoption)\n")
    proper = ("# good record\nDate: 2026-11-16\n\nStage S103 gated; "
              "independent verdicts returned PROCEED across the board.\n\n"
              "FINAL OUTCOME: CONSENSUS REACHED\n")

    def roadmap_line(sid, glyph):
        return f"- {glyph} **{sid}.** synthetic stage"

    v = _gate_record_violations(
        {"2099-01-01-S100-forged.md": inline_only},
        roadmap_line("S100", "\u2611"))
    assert any("inline/prose" in m for m in v), v
    assert any("no line-anchored" in m for m in v), v
    v = _gate_record_violations(
        {"2099-01-01-S101-forged.md": double},
        roadmap_line("S101", "\u25d0"))
    assert any("exactly one" in m for m in v), v
    v = _gate_record_violations(
        {"2026-11-13-S102-forged.md": backdated},
        roadmap_line("S102", "\u25d0"))
    assert any("no line-anchored" in m for m in v), v
    v = _gate_record_violations(
        {"2099-01-01-S103-good.md": proper},
        roadmap_line("S103", "\u2611"))
    assert v == [], v
    v = _gate_record_violations({}, roadmap_line("S104", "\u25d0"))
    assert any("mentions it" in m for m in v), v


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
    # credential-SHAPED name with CLEAN content: must never enter the
    # pushed tree (G1-iter3-i2 Red Team minor) and state.json must
    # count the skip (never record the name — a shaped name in
    # state.json would itself trip the tree scan)
    shaped = "gh" + "p_" + "b" * 36 + ".py"
    (home / "scripts" / shaped).write_text("print('clean')\n")
    # G1-iter4 RT minor #2: the same exclusion holds on the harness/
    # REFRESH surface — v4 excluded shaped names only from the scripts
    # snapshot while the refresh rsyncs ALL of harness/ including
    # UNTRACKED files from the source checkout
    shaped_mem = "gh" + "p_" + "c" * 36 + ".md"
    (repo / "harness" / "memory" / shaped_mem).write_text("clean note\n")

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
    assert r2.returncode == 0, r2.stdout + r2.stderr
    manifest = subprocess.run(
        ["git", "-C", str(repo), "show",
         "sandbox/backups:harness/backups/manifest.json"],
        capture_output=True, text=True, check=True).stdout
    assert '"seq": 2' in manifest, "second backup must append (seq 2)"
    # 2b. shaped-name exclusion: the shaped file never entered the
    #     pushed tree, and state.json counted exactly one skip
    tree = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only",
         "sandbox/backups"], capture_output=True, text=True,
        check=True).stdout
    assert shaped not in tree, "credential-shaped filename entered the pushed tree"
    assert shaped_mem not in tree, (
        "credential-shaped filename entered the pushed tree via the "
        "harness/ refresh surface")
    state = subprocess.run(
        ["git", "-C", str(repo), "show",
         "sandbox/backups:harness/sandbox/state.json"],
        capture_output=True, text=True, check=True).stdout
    assert '"scripts_skipped_shaped_count": 1' in state, (
        "state.json must count the shaped-name skip (got: " + state + ")")
    assert '"harness_skipped_shaped_count": 2' in state, (
        "state.json must count BOTH shaped-name skips (scripts snapshot "
        "+ harness refresh surface); got: " + state)
    # the fixture is an UNTRACKED file inside the clone — remove it so
    # the final "main checkout is never dirtied" check sees a clean tree
    (repo / "harness" / "memory" / shaped_mem).unlink()
    # 3. planted secret (built at runtime — no literal in this file).
    #    show-ref --verify: non-zero rc with NO stdout when the ref is
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


# --------------------------------------------- production opt-in (v5)
@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_production_is_opt_in(tmp_path):
    """G1-iter4 RT major #1 (the incident class: two accidental
    production pushes across two gates — manifest seq 3 't5' and seq 5
    'E9c', both by agents that lost their env overrides): production
    mode must be OPT-IN. Without PC_BACKUP_ALLOW_PRODUCTION=1 the
    script refuses (exit 6) BEFORE any action; the flag combined with
    test overrides is a conflicting mode (exit 2)."""
    script = ROOT / "scripts" / "sandbox_backup.sh"

    def env_no_pc(**extra):
        e = {k: v for k, v in os.environ.items() if not k.startswith("PC_")}
        e["GIT_CONFIG_GLOBAL"] = os.devnull
        e["GIT_CONFIG_SYSTEM"] = os.devnull
        e.update(extra)
        return e

    r = subprocess.run(["bash", str(script), "must refuse by default"],
                       cwd=str(ROOT), env=env_no_pc(),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 6, (r.returncode, r.stdout + r.stderr)
    assert "PC_BACKUP_ALLOW_PRODUCTION" in r.stdout + r.stderr
    r2 = subprocess.run(["bash", str(script), "conflicting mode"],
                        cwd=str(ROOT),
                        env=env_no_pc(PC_BACKUP_REPO=str(tmp_path),
                                      PC_SANDBOX_HOME=str(tmp_path),
                                      PC_BACKUP_PUSH_REMOTE=str(tmp_path),
                                      PC_BACKUP_ALLOW_PRODUCTION="1"),
                        capture_output=True, text=True, timeout=120)
    assert r2.returncode == 2, (r2.returncode, r2.stdout + r2.stderr)


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_guard_refuses_github_spellings(tmp_path):
    """G1-iter4 RT major #2 / Architect major #3: v4's guard was a
    case-sensitive spelling grep — a case-variant decoy target was
    pushed end-to-end in scratch, and :443, //, scp, trailing-dot and
    credentialed spellings all evaded it. A TEST run must now refuse
    EVERY github target however spelled (case, default port, double
    slash, ssh, scp via a remote name, trailing dot, credentialed,
    even a different repo on github) while the local scratch bare
    still passes. Refused targets are built at runtime and could not
    accept a push even if the guard failed (no credentials here)."""
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
    fake = "gh" + "p_" + "e" * 36
    variants = [
        "https://GITHUB.com/maniesh-NR/Proto-Clean.git",        # case
        "https://github.com:443/maniesh-NR/Proto-Clean.git",    # default port
        "https://github.com//maniesh-NR/Proto-Clean",           # double slash
        "ssh://git@github.com:22/maniesh-NR/Proto-Clean",       # ssh + port
        "https://github.com./maniesh-NR/Proto-Clean.git",       # trailing dot
        "https://u:" + fake + "@github.com/maniesh-NR/Proto-Clean.git",  # credentialed
        "https://github.com/maniesh-NR/not-a-real-repo.git",    # any github repo
    ]
    subprocess.run(["git", "-C", str(repo), "remote", "add", "prodscp",
                    "git@github.com:maniesh-NR/Proto-Clean.git"], check=True)
    for target in list(variants) + ["prodscp"]:
        e = dict(os.environ)
        e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": target,
                  "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_CONFIG_SYSTEM": os.devnull})
        r = subprocess.run(["bash", str(script), "guard probe"],
                           cwd=str(repo), env=e,
                           capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        assert r.returncode == 6, (r.returncode, out)
        assert fake not in out, "a refused credentialed spelling leaked its token"
    # the local scratch bare still passes the guard (the hermetic lane)
    e = dict(os.environ)
    e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
              "PC_BACKUP_PUSH_REMOTE": str(bare),
              "GIT_CONFIG_GLOBAL": os.devnull,
              "GIT_CONFIG_SYSTEM": os.devnull})
    r = subprocess.run(["bash", str(script), "guard clean lane"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, (r.returncode, r.stdout + r.stderr)


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_alarm_survives_unreachable_remote(tmp_path):
    """G1-iter4 RT major #3: v4's branch-push streak counter was gated
    on a successful fetch, so a revoked credential or a persistent
    partition produced rc-0 runs forever with the audit trail bound
    to the machine (3 executed runs, no banner, counter frozen). Now
    the first failed-and-unreachable run records (rc 0) and the SECOND
    consecutive one alarms (exit 7 with the banner)."""
    script = ROOT / "scripts" / "sandbox_backup.sh"
    repo = tmp_path / "clone"
    home = tmp_path / "home"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(repo)],
                   check=True, timeout=120)
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "ok.py").write_text("print('hi')\n")
    unreachable = tmp_path / "nope.git"   # fetch/push fail fast, no network

    def run(msg):
        e = dict(os.environ)
        e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": str(unreachable),
                  "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_CONFIG_SYSTEM": os.devnull})
        return subprocess.run(["bash", str(script), msg], cwd=str(repo),
                              env=e, capture_output=True, text=True,
                              timeout=240)

    r1 = run("unreachable 1")
    assert r1.returncode == 0, (r1.returncode, r1.stdout + r1.stderr)
    r2 = run("unreachable 2")
    out = r2.stdout + r2.stderr
    assert r2.returncode == 7, (r2.returncode, out)
    assert "BRANCH-PUSH-ALARM" in out, out
