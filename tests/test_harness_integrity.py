"""Machine-checked integrity of the agent harness.

G1-iter3 (Architect major #4): every harness rule that previous gates
caught humans breaking — no pre-recording gate outcomes, ledger
discipline, record existence, the sandbox/ ignore guard — is enforced
here by CI instead of by good intentions. Also exercises the backup
script end-to-end via its documented env overrides, hermetically
(the overrides existed since G1-iter2 but were consumed by no
automated test).
"""

import json
import os
import re
import subprocess
import threading
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
CONSENSUS_REACHED_LINE = re.compile(r"(?m)^FINAL OUTCOME: CONSENSUS REACHED[ \t]*$")
GATE_RULE_ADOPTION = (2026, 11, 14)          # closure-line rules
STAGE_DECLARATION_ADOPTION = (2026, 11, 16)  # Stage: header requirement


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


def _strip_fences(text):
    """Fenced code blocks are DOCUMENTATION: the format examples they
    contain are prose, never machine-readable closure lines
    (G1-iter4-i2 RT critical #2 / Architect major #1: a fenced example
    at column 0 both satisfied the exactly-one rule and backed a ☑)."""
    out, fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if not fence:
            out.append(line)
    return "\n".join(out)


def _declared_stages(text):
    """The stages this record GATES, per its explicit 'Stage: S<n>'
    declaration lines — never prose mentions (G1-iter4-i2: incidence-
    based backing let a record for S1 bless a ☑ for S2/S6 it merely
    mentioned in passing, an S20 record back S2, and an undated note
    back anything)."""
    return set(re.findall(r"(?m)^Stage:\s*(S\d+)\s*$", text))


def _last_line(text):
    """The record's last non-empty line — the only position a closure
    line may occupy (G1-iter4-i2: a mid-record closure line is prose
    that happens to start at column 0, not the gate's outcome)."""
    lines = [l for l in text.splitlines() if l.strip()]
    return lines[-1] if lines else ""


def _gate_record_violations(per_record, roadmap):
    """All machine-checkable gate-record rules; returns violation
    strings (empty list = clean). Extracted into a helper so the check
    itself can be FALSIFIED with synthetic forgeries (see
    test_final_outcome_check_cannot_be_forged) — the G1-iter4
    Architect critical proved v4's substring check was satisfied by
    the iter-3 record's own documentation prose, and the G1-iter4-i2
    Red Team + Architect proved the v4.1 hardening was STILL
    incidence-based: cross-stage prose, substring stage ids, undated
    records and fenced examples all silently backed an unbacked ☑.
    Backing now requires a record that DECLARES the stage, is dated,
    and closes with a line-anchored CONSENSUS REACHED as its last
    non-empty line."""
    violations = []
    declared, backs_consensus = {}, {}
    for name, text in per_record.items():
        body = _strip_fences(text)
        d = _record_date(name, text)
        declared[name] = _declared_stages(body)
        if d is not None and d >= GATE_RULE_ADOPTION:
            outcome_lines = FINAL_OUTCOME_LINE.findall(body)
            if not outcome_lines:
                violations.append(
                    f"{name} is dated on/after 2026-11-14 (the FINAL OUTCOME "
                    f"rule's adoption) but carries no line-anchored "
                    f"'FINAL OUTCOME:' line")
            elif len(outcome_lines) > 1:
                violations.append(
                    f"{name} carries {len(outcome_lines)} 'FINAL OUTCOME:' lines — "
                    f"exactly one machine-parseable closure line is required")
            elif outcome_lines[0] != _last_line(body):
                violations.append(
                    f"{name}: the FINAL OUTCOME line must be the LAST "
                    f"non-empty line of the record (mid-record closure "
                    f"lines and fenced examples do not count)")
        if (d is not None and d >= STAGE_DECLARATION_ADOPTION
                and not declared[name]):
            violations.append(
                f"{name} is dated on/after 2026-11-16 but declares no "
                f"'Stage: S<n>' line — a record must name the stage(s) it "
                f"gates (prose mentions do not back closure)")
        m = CONSENSUS_REACHED_LINE.search(body)
        backs_consensus[name] = (
            d is not None and m is not None
            and m.group(0).rstrip() == _last_line(body).rstrip())
    records = "\n".join(name + "\n" + text
                        for name, text in per_record.items())
    for line in roadmap.splitlines():
        if ("☑" in line or "◐" in line):
            m = re.search(r"\bS(\d+)\b", line)
            if not m:
                continue  # shipped-line items without a stage id
            sid = "S" + m.group(1)
            mentioned = any(re.search(rf"\b{re.escape(sid)}\b", t)
                            for t in per_record.values())
            if not mentioned:
                violations.append(
                    f"roadmap marks {sid} as done/active but no "
                    f"consensus-log record mentions it")
            if "☑" in line:
                backing = [n for n in per_record
                           if sid in declared[n] and backs_consensus[n]]
                if not backing:
                    violations.append(
                        f"roadmap marks {sid} done (☑) but no record both "
                        f"DECLARES it (a 'Stage: {sid}' line) and closes "
                        f"with a line-anchored 'FINAL OUTCOME: CONSENSUS "
                        f"REACHED' as its last line — prose mentions, "
                        f"fenced examples, substring stage ids and undated "
                        f"records do not back closure")
    return violations


def test_roadmap_glyphs_backed_by_gate_records():
    """Every roadmap stage marked done (☑) or active (◐) must be
    mentioned by a consensus-log record — a stage cannot claim a gate
    outcome that no record contains (the no-pre-recording rule).

    Strengthened three times:
    - G1-iter3-i2: a ☑ additionally requires a record naming the
      stage and carrying a FINAL OUTCOME: CONSENSUS REACHED line.
    - G1-iter4 (Architect CRITICAL): that line must be LINE-ANCHORED
      and EXACT — v4's substring check was satisfied by the iter-3
      record's own prose describing the rule, so flipping any stage's
      glyph to ☑ passed CI at 6324a4d. Also: exactly one closure line
      per record (dated by filename OR Date: header, whichever is
      later), so a record cannot carry both a NO-CONSENSUS and a
      CONSENSUS outcome.
    - G1-iter4-i2 (Red Team CRITICAL #2 / Architect MAJOR #1):
      backing is no longer incidence-based — a record backs a ☑ only
      when it DECLARES the stage ('Stage: S<n>' lines), is dated, and
      carries its closure as the LAST non-empty line after fenced
      code blocks are stripped; word-boundary mention matching
      replaced substring matching (an S20 record no longer mentions
      S2). Records dated on/after 2026-11-16 must declare their
      stage(s).
    """
    log_dir = HARNESS / "memory" / "consensus-log"
    per_record = {p.name: p.read_text(encoding="utf-8")
                  for p in log_dir.glob("*.md")}
    roadmap = (HARNESS / "roadmap.md").read_text(encoding="utf-8")
    violations = _gate_record_violations(per_record, roadmap)
    assert not violations, "\n".join(violations)


def test_final_outcome_check_cannot_be_forged():
    """The G1-iter4 Architect critical, locked in — and RE-extended
    after the G1-iter4-i2 Red Team + Architect proved the hardened
    check was still forgeable four ways (executed silent pytest PASSES
    with an unbacked glyph flip): v4's ☑ check was satisfied by prose
    incidence; the fix made the line exact but left backing
    incidence-based. Synthetic forgeries now prove the check catches
    every class: inline-only mentions, double outcome lines,
    back-dated filenames (the Date: header governs), unbacked glyphs,
    fenced format examples, undated records, cross-stage prose
    mentions, substring stage ids (S20 ≠ S2), non-terminal closure
    lines, and missing stage declarations — and accepts a proper
    declared, dated, terminal closure. The check guards the check
    (canary philosophy: a self-test that can go silently blind is
    worse than none)."""
    inline_only = ("# forged record\nDate: 2026-11-15\n\nThe rule says a "
                   "roadmap checkmark requires a `FINAL OUTCOME: CONSENSUS "
                   "REACHED` record naming the stage S100 — inline only.\n")
    double = ("# forged record\nDate: 2026-11-15\n\nFINAL OUTCOME: "
              "CONSENSUS REACHED\nFINAL OUTCOME: NO CONSENSUS\n")
    backdated = ("# forged record\nDate: 2026-11-15\n\n(no closure line at "
                 "all — the filename predates the rule's adoption)\n")
    fenced = ("# forged record\nDate: 2026-11-15\nStage: S105\n\nprose.\n\n"
              "```\nFINAL OUTCOME: CONSENSUS REACHED\n```\n")
    undated = ("# forged record\nStage: S106\n\nno date anywhere in "
               "filename or header\n\nFINAL OUTCOME: CONSENSUS REACHED\n")
    cross_stage = ("# record gating another stage\nDate: 2026-11-16\n"
                   "Stage: S107\n\nThis gate examined S108's plan in "
                   "passing.\n\nFINAL OUTCOME: CONSENSUS REACHED\n")
    substring = ("# forged record\nDate: 2026-11-16\nStage: S1090\n\n"
                 "FINAL OUTCOME: CONSENSUS REACHED\n")
    not_last = ("# forged record\nDate: 2026-11-16\nStage: S110\n\n"
                "FINAL OUTCOME: CONSENSUS REACHED\n\n"
                "post-outcome prose line\n")
    undeclared = ("# record for S111 with no declaration\nDate: "
                  "2026-11-16\n\nS111 gated.\n\n"
                  "FINAL OUTCOME: NO CONSENSUS — x\n")
    proper = ("# good record\nDate: 2026-11-16\nStage: S103\n\n"
              "independent verdicts returned PROCEED across the board.\n\n"
              "FINAL OUTCOME: CONSENSUS REACHED\n")

    def roadmap_line(sid, glyph):
        return f"- {glyph} **{sid}.** synthetic stage"

    v = _gate_record_violations(
        {"2099-01-01-S100-forged.md": inline_only},
        roadmap_line("S100", "\u2611"))
    assert any("no line-anchored" in m for m in v), v
    v = _gate_record_violations(
        {"2099-01-01-S101-forged.md": double},
        roadmap_line("S101", "\u25d0"))
    assert any("exactly one" in m for m in v), v
    v = _gate_record_violations(
        {"2026-11-13-S102-forged.md": backdated},
        roadmap_line("S102", "\u25d0"))
    assert any("no line-anchored" in m for m in v), v
    # fenced example: stripped — the record carries NO closure line
    v = _gate_record_violations(
        {"2099-01-01-S105-forged.md": fenced},
        roadmap_line("S105", "\u2611"))
    assert any("no line-anchored" in m for m in v), v
    assert any("S105" in m for m in v), v
    # undated: exempt from the must-carry rule but can never BACK
    v = _gate_record_violations(
        {"notes-S106-forged.md": undated},
        roadmap_line("S106", "\u2611"))
    assert any("S106" in m and "DECLARES" in m for m in v), v
    # cross-stage prose mention: only the DECLARED stage is backed
    v = _gate_record_violations(
        {"2099-01-01-S107-forged.md": cross_stage},
        roadmap_line("S108", "\u2611"))
    assert any("S108" in m for m in v), v
    # the same record legitimately backs its own declared stage
    v2 = _gate_record_violations(
        {"2099-01-01-S107-forged.md": cross_stage},
        roadmap_line("S107", "\u2611"))
    assert v2 == [], v2
    # substring stage id: S1090 does not declare S109
    v = _gate_record_violations(
        {"2099-01-01-S109-forged.md": substring},
        roadmap_line("S109", "\u2611"))
    assert any("S109" in m for m in v), v
    # non-terminal closure line
    v = _gate_record_violations(
        {"2099-01-01-S110-forged.md": not_last},
        roadmap_line("S110", "\u25d0"))
    assert any("LAST non-empty line" in m for m in v), v
    # dated record without a Stage: declaration
    v = _gate_record_violations(
        {"2099-01-01-S111-forged.md": undeclared},
        roadmap_line("S111", "\u25d0"))
    assert any("Stage:" in m for m in v), v
    # proper closure still passes
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
    any repo on github — and, since G1-iter4-i2, ANY github SUBDOMAIN:
    gist. / www. / api. / education., plain or credentialed, direct
    or via a remote name — www.github.com was verified a live git
    endpoint returning production HEAD anonymously) while the local
    scratch bare still passes. Refused targets are built at runtime
    and could not accept a push even if the guard failed (no
    credentials here)."""
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
        # G1-iter4-i2 RT critical #1: github SUBDOMAINS are live git
        # endpoints that sailed through v5's enumerated host list —
        # `git ls-remote https://www.github.com/<the production repo>`
        # returned production HEAD anonymously (301 to github.com),
        # and gist.github.com answered the git smart-http backend
        "https://gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git",
        "https://www.github.com/maniesh-NR/Proto-Clean.git",
        "https://api.github.com/repos/maniesh-NR/Proto-Clean",
        "https://education.github.com/x",
        "https://" + fake + "@gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git",  # credentialed subdomain
    ]
    subprocess.run(["git", "-C", str(repo), "remote", "add", "prodscp",
                    "git@github.com:maniesh-NR/Proto-Clean.git"], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "gistscp",
                    "git@gist.github.com:aa11bb22cc33dd44ee55ff6677aabbcc.git"], check=True)
    for target in list(variants) + ["prodscp", "gistscp"]:
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


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_overrides_all_or_none(tmp_path):
    """G1-iter4-i2 RT major #2 / Architect major #2: overrides must be
    ALL-THREE or NONE. A partial set is the exact accident shape of
    the seq-3 't5' / seq-5 'E9c' incidents (a broken && chain loses
    SOME overrides): v5 entered TEST mode on any single override, so
    a lone PC_BACKUP_PUSH_REMOTE committed a test checkpoint onto the
    PRODUCTION checkout's local sandbox/backups — which the next
    production run then pushed to github (executed end-to-end in
    scratch by the Red Team). A TEST run must also refuse the
    production checkout itself, however the path is spelled."""
    script = ROOT / "scripts" / "sandbox_backup.sh"

    def run(**extra):
        e = {k: v for k, v in os.environ.items() if not k.startswith("PC_")}
        e["GIT_CONFIG_GLOBAL"] = os.devnull
        e["GIT_CONFIG_SYSTEM"] = os.devnull
        e.update(extra)
        return subprocess.run(["bash", str(script), "override probe"],
                              cwd=str(ROOT), env=e,
                              capture_output=True, text=True, timeout=120)

    # 1 of 3 and 2 of 3 → exit 2 before any action
    for partial in (
        {"PC_BACKUP_PUSH_REMOTE": str(tmp_path)},
        {"PC_BACKUP_REPO": str(tmp_path)},
        {"PC_SANDBOX_HOME": str(tmp_path)},
        {"PC_BACKUP_REPO": str(tmp_path),
         "PC_BACKUP_PUSH_REMOTE": str(tmp_path)},
        {"PC_SANDBOX_HOME": str(tmp_path),
         "PC_BACKUP_PUSH_REMOTE": str(tmp_path)},
        {"PC_BACKUP_REPO": str(tmp_path),
         "PC_SANDBOX_HOME": str(tmp_path)},
    ):
        r = run(**partial)
        out = r.stdout + r.stderr
        assert r.returncode == 2, (partial, r.returncode, out)
        assert "partial overrides" in out, out

    # a TEST run (all three) whose PC_BACKUP_REPO is the production
    # checkout — however spelled — refuses exit 6 before touching it
    # (the literal compare catches file:// and trailing-slash forms on
    # any machine; the canonicalized compare additionally catches
    # relative/symlink spellings where the path exists)
    prod = "/home/z/my-project/cleanroom"
    for spelling in (prod, "file://" + prod, prod + "/"):
        r = run(PC_BACKUP_REPO=spelling, PC_SANDBOX_HOME=str(tmp_path),
                PC_BACKUP_PUSH_REMOTE=str(tmp_path))
        out = r.stdout + r.stderr
        assert r.returncode == 6, (spelling, r.returncode, out)
        assert "production checkout" in out, out


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_refusal_never_echoes_target(tmp_path):
    """G1-iter4-i2 Architect minor #2: v5's not-a-configured-remote
    refusal printed the RAW push target — a credentialed scp-syntax
    spelling was echoed verbatim. The refusal must redact (userinfo
    and token-shape) whatever it prints."""
    script = ROOT / "scripts" / "sandbox_backup.sh"
    # a real scratch clone: the remote-plumbing check runs after the
    # repo validation, so a non-repo path would exit 2 first
    repo = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(repo)],
                   check=True, timeout=120)
    fake = "gh" + "p_" + "z" * 36
    e = {k: v for k, v in os.environ.items() if not k.startswith("PC_")}
    e.update({"PC_BACKUP_REPO": str(repo),
              "PC_SANDBOX_HOME": str(tmp_path),
              "PC_BACKUP_PUSH_REMOTE": f"{fake}@dead.example.com:x.git",
              "GIT_CONFIG_GLOBAL": os.devnull,
              "GIT_CONFIG_SYSTEM": os.devnull})
    r = subprocess.run(["bash", str(script), "echo probe"],
                       cwd=str(repo), env=e, capture_output=True,
                       text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 6, (r.returncode, out)
    assert fake not in out, "the refusal echoed the credential-shaped target"
    assert "[REDACTED]" in out, out


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_mainpush_redaction_and_trace_hygiene(tmp_path):
    """G1-iter4-i2 RT major #1 / Steward major #1: v5 left the MAIN
    push inline (userinfo-only scrub, no token-shape rule — the README
    and gate record claimed parity with _push_branch) and the legacy
    alias GIT_CURL_VERBOSE unneutralized, so a failing credentialed
    main push printed the raw token twice in an executed probe. Every
    push now goes through a guarded helper, and trace/config env is
    neutralized by PATTERN — including git's env-based config
    injection (GIT_CONFIG_KEY*/VALUE*/COUNT), which could re-enable
    http.verbose the same way."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    script = ROOT / "scripts" / "sandbox_backup.sh"
    repo = tmp_path / "clone"
    bare = tmp_path / "bare.git"
    home = tmp_path / "home"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(repo)],
                   check=True, timeout=120)
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "set-url",
                    "origin", str(bare)], check=True)
    # seed the remote with main so the remote-tracking ref exists
    subprocess.run(["git", "-C", str(repo), "push", "-q", str(bare),
                    "main"], check=True, timeout=120)
    (home / "scripts").mkdir(parents=True)
    (home / "scripts" / "ok.py").write_text("print('hi')\n")

    class _401(BaseHTTPRequestHandler):
        def _deny(self):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"no")
        do_GET = _deny
        do_POST = _deny
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _401)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def run_backup(message, push_remote=None, **extra):
        e = {k: v for k, v in os.environ.items()
             if not k.startswith("PC_") and k.lower() not in
             ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy")}
        e.update({"PC_BACKUP_REPO": str(repo),
                  "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": push_remote or str(bare),
                  "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_CONFIG_SYSTEM": os.devnull,
                  "GIT_TERMINAL_PROMPT": "0",
                  "NO_PROXY": "*", "no_proxy": "*"})
        e.update(extra)
        return subprocess.run(["bash", str(script), message],
                              cwd=str(repo), env=e,
                              capture_output=True, text=True, timeout=240)

    # run 1 against the good bare: creates the remote-tracking refs
    r1 = run_backup("seed")
    assert r1.returncode == 0, r1.stdout + r1.stderr
    # a commit on main the remote lacks → the next run pushes main
    subprocess.run(["git", "-C", str(repo), "commit", "-q",
                    "--allow-empty", "-m", "ahead"], check=True)

    fake = "gh" + "p_" + "f" * 36
    url = f"http://user:{fake}@127.0.0.1:{srv.server_port}/x.git"
    # the exact hostile ambient env the Red Team used, plus the env
    # config injection that could re-enable http.verbose
    r2 = run_backup("leak probe", push_remote=url,
                    GIT_CURL_VERBOSE="1", GIT_TRACE2="1", GIT_TRACE="1",
                    GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.verbose",
                    GIT_CONFIG_VALUE_0="true")
    out = r2.stdout + r2.stderr
    try:
        srv.shutdown()
    except Exception:
        pass
    assert fake not in out, "the raw credential leaked through a push path"
    assert "Issue another request" not in out, (
        "GIT_CURL_VERBOSE output was not neutralized")
    assert "Server auth using Basic" not in out, (
        "curl verbose output was not neutralized")
    assert "credentials redacted" in out, (
        "the guarded main push must label its redacted stderr")
    assert r2.returncode == 0, (r2.returncode, out)


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_union_scrubs_dict_keys(tmp_path):
    """G1-iter4-i2 RT minor #1: the divergence-union scrub covered
    string VALUES only — a token in a dict KEY rode the union, was
    caught by the pre-commit re-scan (correct exit-8 abort, nothing
    pushed), but the divergence could then never self-heal: every
    future run died exit 8 until a human repaired the remote
    manifest. Keys are scrubbed too, so a poisoned KEY is neutralized
    and the branch heals on the spot; the manifest note is also
    normalized (G1-iter4-i2 Steward minor #2 — the live branch's
    note still said 'keyed by seq')."""
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

    def run_backup(message, push_remote=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("PC_")}
        e.update({"PC_BACKUP_REPO": str(repo),
                  "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": push_remote or str(bare),
                  "GIT_CONFIG_GLOBAL": os.devnull,
                  "GIT_CONFIG_SYSTEM": os.devnull})
        return subprocess.run(["bash", str(script), message],
                              cwd=str(repo), env=e,
                              capture_output=True, text=True, timeout=240)

    # 1. healthy run — branch created and pushed
    r1 = run_backup("key scrub 1")
    assert r1.returncode == 0, r1.stdout + r1.stderr
    # 2. poison the remote from a second clone taken AT the pushed
    #    tip: the remote gains a commit the LOCAL branch lacks (that
    #    is what makes the next push a true divergence, not a
    #    fast-forward) — an append-only entry whose KEY is
    #    credential-shaped (rides values-only scrubbing)
    clone2 = tmp_path / "clone2"
    subprocess.run(["git", "clone", "-q", "--branch", "sandbox/backups",
                    str(repo), str(clone2)], check=True, timeout=120)
    fake = "gh" + "p_" + "k" * 36
    man = clone2 / "harness" / "backups" / "manifest.json"
    doc = json.loads(man.read_text(encoding="utf-8"))
    doc["backups"].append(
        {"seq": 99, "timestamp": "2030-01-01T00:00:00Z",
         "trigger": "event", "message": "poison from remote",
         fake: "innocuous value", "git_head": "deadbee",
         "git_branch": "main", "main_push": "ok"})
    man.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(clone2), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(clone2), "-c", "user.name=x",
                    "-c", "user.email=x@y.z", "commit", "-q", "-m",
                    "poison"], check=True)
    subprocess.run(["git", "-C", str(clone2), "push", "-q", str(bare),
                    "sandbox/backups"], check=True, timeout=120)
    # 3. unreachable remote — the checkpoint stays local (the local
    #    branch is now ahead of BOTH the stale tracking ref and the
    #    poisoned remote tip)
    r2 = run_backup("key scrub 2",
                    push_remote=str(tmp_path / "missing.git"))
    assert r2.returncode == 0, r2.stdout + r2.stderr
    # 4. harness change → a new checkpoint → push is non-FF →
    #    divergence union must scrub the poisoned KEY and heal
    (repo / "harness" / "memory" / "note-keyscrub.md").write_text(
        "key-scrub probe\n", encoding="utf-8")
    r3 = run_backup("key scrub 3")
    assert r3.returncode == 0, r3.stdout + r3.stderr
    pushed = subprocess.run(
        ["git", "-C", str(bare), "show",
         "refs/heads/sandbox/backups:harness/backups/manifest.json"],
        capture_output=True, text=True, check=True).stdout
    assert fake not in pushed, "the poisoned KEY rode the union merge"
    assert "[REDACTED]" in pushed, (
        "a scrubbed key marker must replace the poisoned KEY")
    assert '"seq": 99' in pushed, "append-only: the remote entry survived"
    assert '"seq": 3' in pushed, "the local entries survived the union"
    assert "triple" in pushed, (
        "the stale 'keyed by seq' note was not normalized")
    # 5. the branch healed — the next run appends cleanly
    (repo / "harness" / "memory" / "note-keyscrub2.md").write_text(
        "again\n", encoding="utf-8")
    r4 = run_backup("key scrub 4")
    assert r4.returncode == 0, r4.stdout + r4.stderr
