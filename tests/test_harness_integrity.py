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
    escape the rules). G1-iter6 RT critical #6b: multiple 'Date:'
    headers are a MALFORMATION, not a date — first-match parsing let
    a pre-adoption first header shield a future second one; the
    caller flags the record instead of trusting either date."""
    dates = []
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})-", name)
    if m:
        dates.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    headers = re.findall(r"(?m)^Date: (\d{4})-(\d{2})-(\d{2})", text)
    if len(headers) > 1:
        return None  # malformed — _gate_record_violations flags it
    if headers:
        y, mo, d = (int(x) for x in headers[0])
        dates.append((y, mo, d))
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
    declared, backs_consensus, rec_date = {}, {}, {}
    for name, text in per_record.items():
        body = _strip_fences(text)
        # G1-iter6 RT critical #6b: multiple Date: headers are a
        # malformation — first-match parsing let a forged record pick
        # which date the rules see
        if len(re.findall(r"(?m)^Date: ", text)) > 1:
            violations.append(
                f"{name} carries multiple 'Date:' headers — exactly one is "
                f"required (first-match date parsing is forgeable)")
        d = _record_date(name, text)
        rec_date[name] = d
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
            else:
                # G1-iter6 RT critical #6f: the closure line must also
                # be the last NON-BLANK line of the RAW text — fence
                # stripping let a fenced addendum after the closure
                # hide a human-visible retraction from the machine
                raw_last = _last_line(text)
                if outcome_lines[0] != raw_last:
                    violations.append(
                        f"{name}: non-blank content (a fenced addendum?) "
                        f"follows the FINAL OUTCOME line — post-closure "
                        f"fences are auditable forgeries, not formatting")
        if (d is not None and d >= STAGE_DECLARATION_ADOPTION
                and not declared[name]):
            violations.append(
                f"{name} is dated on/after 2026-11-16 but declares no "
                f"'Stage: S<n>' line — a record must name the stage(s) it "
                f"gates (prose mentions do not back closure)")
        m = CONSENSUS_REACHED_LINE.search(body)
        # G1-iter6 RT critical #6a: BACKING requires the declaration-
        # bound authority's adoption date — a backdated record (pre-
        # 2026-11-16 filename or Date: header) carrying a Stage: line
        # and a terminal closure used to machine-back a ☑ although the
        # declaration rules it exploits did not exist yet
        backs_consensus[name] = (
            d is not None and d >= STAGE_DECLARATION_ADOPTION
            and m is not None
            and m.group(0).rstrip() == _last_line(body).rstrip())
    records = "\n".join(name + "\n" + text
                        for name, text in per_record.items())
    section = ""
    for line in roadmap.splitlines():
        if line.startswith("## "):
            section = line[3:].strip().lower()
            continue
        # G1-iter6 RT critical #6d: done-claims made with LOOKALIKE
        # glyphs (✅ ✔ ✓) are invisible to every ☑ rule — the legend
        # defines exactly ☐ ◐ ☑, and no roadmap line legitimately
        # carries the substitutes
        if re.search(r"[\u2705\u2714\u2713]", line):
            violations.append(
                f"roadmap line carries a done-claim lookalike glyph "
                f"(\u2705/\u2714/\u2713) — the status legend defines exactly "
                f"\u2610/\u25d0/\u2611: {line.strip()!r}")
        if ("☑" in line or "◐" in line):
            # G1-iter6 RT critical #6c: EVERY stage id on the line is
            # checked — v8 verified only the first, so a
            # '☑ S310 (subsumes S311 and S312)' line rode two free
            # done-claims
            ids = re.findall(r"\bS(\d+)\b", line)
            if not ids:
                # G1-iter5 RT minor #2: only the retro-assessed
                # "Shipped" section may carry id-less done lines —
                # anywhere else a ☑ bullet without a stage id skipped
                # the check entirely (an unbacked done-claim lane).
                # G1-iter6 RT critical #6e extends the rule to ◐: an
                # id-less in-gate claim is equally unauditable.
                # Non-bullet lines (the status legend, wrapped prose)
                # never count.
                if (line.lstrip().startswith("- ")
                        and not (section.startswith("shipped")
                                 and "retrospectively assessed" in section)):
                    violations.append(
                        f"roadmap marks work done/active (glyph) with no "
                        f"stage id outside the 'Shipped' section: "
                        f"{line.strip()!r}")
                continue  # shipped-line items without a stage id
            for sid_num in ids:
                sid = "S" + sid_num
                mentioned = any(re.search(rf"\b{re.escape(sid)}\b",
                                          _strip_fences(t))
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
                    else:
                        # G1-iter5 RT minor #1 (stale consensus): a NEWER
                        # record declaring the stage that does not close
                        # with CONSENSUS REACHED withdraws the backing —
                        # a failed re-gate must retract a ☑ machine-green
                        # (proven by synthetic execution at G1-iter5; same-
                        # date ties withdraw on any non-consensus record —
                        # fail-safe under ambiguous ordering)
                        recs = sorted(
                            ((rec_date[n], n) for n in per_record
                             if sid in declared[n] and rec_date[n] is not None),
                            key=lambda t: (t[0], t[1]))
                        if recs:
                            latest_date = recs[-1][0]
                            withdrawn = [n for d, n in recs
                                         if d == latest_date
                                         and not backs_consensus[n]]
                            if withdrawn:
                                violations.append(
                                    f"roadmap marks {sid} done (☑), but the "
                                    f"latest record(s) declaring it "
                                    f"({', '.join(sorted(withdrawn))}) do not "
                                    f"close with 'FINAL OUTCOME: CONSENSUS "
                                    f"REACHED' — a newer non-consensus record "
                                    f"withdraws the backing (a failed re-gate "
                                    f"retracts the glyph)")
    return violations


def _prod_checkout():
    """G1-iter6 Architect major #1: lanes DERIVE the guarded identity
    from the script under test instead of hand-copying it. The seq-10
    and seq-1'/2'/13 incidents both fired because test lanes
    referenced the real production path independently of the guard's
    PROD_CHECKOUT constant — a mutation probe that patches the
    constant then repoints the lanes automatically (a one-sided
    patch neutralized the guard for every unpatched real-path lane).
    """
    src = (ROOT / "scripts" / "sandbox_backup.sh").read_text(
        encoding="utf-8")
    m = re.search(r'(?m)^PROD_CHECKOUT="(.+)"$', src)
    assert m, "PROD_CHECKOUT constant not found in the backup script"
    return m.group(1)


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
    - G1-iter5 (Red Team minors #1+#2): a NEWER record declaring the
      stage that closes NON-consensus withdraws a ☑ (a failed re-gate
      retracts the glyph — stale consensus), and a ☑ bullet with no
      stage id OUTSIDE the 'Shipped' section is a violation (id-less
      done-claims previously skipped the check entirely).
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
    declared, dated, terminal closure. Extended at G1-iter5: stale-
    consensus withdrawal and the id-less-☑-outside-Shipped class.
    The check guards the check (canary philosophy: a self-test that
    can go silently blind is worse than none)."""
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
    # G1-iter5 RT minor #1 (stale consensus): a newer record declaring
    # the stage that closes NON-consensus withdraws the ☑ — a failed
    # re-gate must retract the glyph machine-green (undated filenames,
    # dated headers: effective dates 11-17 and 11-20)
    older_consensus = ("# older record\nDate: 2026-11-17\nStage: S112\n\n"
                       "verdicts returned PROCEED.\n\n"
                       "FINAL OUTCOME: CONSENSUS REACHED\n")
    newer_no_consensus = ("# newer record\nDate: 2026-11-20\nStage: S112\n\n"
                          "verdicts returned BLOCK.\n\n"
                          "FINAL OUTCOME: NO CONSENSUS — x\n")
    v = _gate_record_violations(
        {"notes-S112-old.md": older_consensus,
         "notes-S112-new.md": newer_no_consensus},
        roadmap_line("S112", "\u2611"))
    assert any("withdraws the backing" in m for m in v), v
    # the inverse — an older NO-CONSENSUS, a newer CONSENSUS — backs
    # (the re-gate that reached consensus supersedes the earlier miss)
    older_no_consensus = ("# older record\nDate: 2026-11-17\nStage: S112\n\n"
                          "verdicts returned BLOCK.\n\n"
                          "FINAL OUTCOME: NO CONSENSUS — x\n")
    newer_consensus = ("# newer record\nDate: 2026-11-20\nStage: S112\n\n"
                       "verdicts returned PROCEED.\n\n"
                       "FINAL OUTCOME: CONSENSUS REACHED\n")
    v = _gate_record_violations(
        {"notes-S112-old.md": older_no_consensus,
         "notes-S112-new.md": newer_consensus},
        roadmap_line("S112", "\u2611"))
    assert v == [], v
    # G1-iter5 RT minor #2: a ☑ bullet with no stage id outside the
    # 'Shipped' section skipped the check entirely — now a violation
    v = _gate_record_violations(
        {}, "## Near term\n\n- \u2611 everything shipped, trust us\n")
    assert any("outside the 'Shipped' section" in m for m in v), v
    # ...while the retro-assessed Shipped section may carry id-less
    # done lines (by design), and the status legend (non-bullet) never
    # counts as a done-claim
    v = _gate_record_violations(
        {}, "## Shipped (retrospectively assessed)\n\n"
            "- \u2611 legacy line, no id\n\n"
            "Status legend: \u2611 done.\n")
    assert v == [], v
    # G1-iter5-i2 RT minor #2: a `## Shipped*`-prefixed header
    # smuggled anywhere else ("Shipped something else") exempted
    # id-less ☑ bullets from the done-claim check — the exemption now
    # requires the section's full signature
    v = _gate_record_violations(
        {}, "## Shipped something else\n\n- \u2611 smuggled done-claim\n")
    assert any("outside the 'Shipped' section" in m for m in v), v
    # G1-iter5-i2 RT minor #5: a fenced stage mention no longer
    # satisfies the ◐ mention rule (the raw-text scan used to count
    # documentation examples inside fences)
    fenced_mention = ("# record\nDate: 2026-11-20\nStage: S113\n\n"
                      "```\nS114 mentioned only in a fence\n```\n\n"
                      "FINAL OUTCOME: NO CONSENSUS — x\n")
    v = _gate_record_violations(
        {"2099-01-01-S113-forged.md": fenced_mention},
        roadmap_line("S114", "\u25d0"))
    assert any("mentions it" in m for m in v), v
    # G1-iter6 RT critical #6a: a BACKDATED record (pre-2026-11-16
    # filename or Date: header) carrying a Stage: line and a terminal
    # closure used to machine-back a ☑ — backing now requires the
    # declaration-bound authority's adoption date
    backdated_backing = ("# forged record\nDate: 2026-11-13\nStage: S115\n\n"
                         "FINAL OUTCOME: CONSENSUS REACHED\n")
    v = _gate_record_violations(
        {"2026-11-13-S115-forged.md": backdated_backing},
        roadmap_line("S115", "\u2611"))
    assert any("S115" in m and "DECLARES" in m for m in v), v
    # G1-iter6 RT critical #6b: multiple Date: headers — first-match
    # parsing let a forged record pick which date the rules see
    multi_date = ("# forged record\nDate: 2026-11-13\nDate: 2099-01-01\n"
                  "Stage: S116a\n\nFINAL OUTCOME: CONSENSUS REACHED\n")
    v = _gate_record_violations(
        {"2099-01-01-S116a-forged.md": multi_date},
        roadmap_line("S116a", "\u25d0"))
    assert any("multiple 'Date:' headers" in m for m in v), v
    # G1-iter6 RT critical #6c: EVERY stage id on a glyph line is
    # checked — '☑ S116 (subsumes S117)' used to ride a free done-claim
    # for S117 on the first-id-only check
    subsuming = ("# record\nDate: 2026-11-20\nStage: S116\n\n"
                 "verdicts returned PROCEED.\n\n"
                 "FINAL OUTCOME: CONSENSUS REACHED\n")
    v = _gate_record_violations(
        {"2099-01-01-S116-forged.md": subsuming},
        "- \u2611 **S116.** shipped (subsumes S117 and S118)")
    assert any("S117" in m for m in v), v
    assert any("S118" in m for m in v), v
    # ...but the same record still legitimately backs its own id
    v2 = _gate_record_violations(
        {"2099-01-01-S116-forged.md": subsuming},
        roadmap_line("S116", "\u2611"))
    assert v2 == [], v2
    # G1-iter6 RT critical #6d: done-claims made with LOOKALIKE glyphs
    # (✅ ✔ ✓) were invisible to every ☑ rule
    v = _gate_record_violations({}, "- \u2705 **S119.** done, honest\n")
    assert any("lookalike glyph" in m for m in v), v
    v = _gate_record_violations({}, "- \u2714 **S119.** done, honest\n")
    assert any("lookalike glyph" in m for m in v), v
    # G1-iter6 RT critical #6e: an id-less ◐ bullet outside Shipped is
    # as unauditable as an id-less ☑
    v = _gate_record_violations(
        {}, "## Near term\n\n- \u25d0 actively in gate, trust us\n")
    assert any("outside the 'Shipped' section" in m for m in v), v
    # G1-iter6 RT critical #6f: a fenced addendum AFTER the closure
    # line hid a human-visible retraction from the machine while the
    # ☑ stayed backed — the closure must be the last non-blank line of
    # the RAW text too
    fenced_addendum = ("# forged record\nDate: 2026-11-20\nStage: S120\n\n"
                       "FINAL OUTCOME: CONSENSUS REACHED\n\n"
                       "```\nADDENDUM: this gate actually FAILED —\n"
                       "the consensus above was forged\n```\n")
    v = _gate_record_violations(
        {"2099-01-01-S120-forged.md": fenced_addendum},
        roadmap_line("S120", "\u2611"))
    assert any("follows the FINAL OUTCOME" in m for m in v), v


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

    # G1-iter6 Architect minor #2: the canonical CURRENT-baseline
    # statements (fix-cycle checklist items a/b/c) must AGREE — the
    # numbers drifted three gates running because four docs carry them
    # and only manual refreshing kept them current. Historical as-of
    # mentions (release-history tables, gate narratives, records) are
    # exempt; only the canonical statements are compared.
    canonical = [
        ("process doc (baseline parenthetical)",
         HARNESS / "process" / "adversarial-consensus.md",
         "current test baseline"),
        ("project state (Test baseline bullet)",
         HARNESS / "memory" / "00-project-state.md",
         "Test baseline"),
        ("lessons (Baseline line)",
         HARNESS / "memory" / "02-lessons.md",
         "- Baseline ("),
    ]
    pairs = {}
    for doc, path, marker in canonical:
        text = path.read_text(encoding="utf-8")
        i = text.find(marker)
        assert i >= 0, f"{doc}: canonical baseline marker missing"
        window = text[i:i + 250]
        m = (re.search(r"(\d+)\s*passed\s*\+\s*(\d+)\s*skipped", window)
             or re.search(r"(\d+)\s*\+\s*(\d+)\s*local", window))
        assert m, f"{doc}: no baseline pair near the canonical marker"
        pairs.setdefault((int(m.group(1)), int(m.group(2))),
                         []).append(doc)
    assert len(pairs) == 1, (
        f"the local test baseline disagrees across the living docs — "
        f"the fix-cycle checklist refreshes them in the SAME commit: "
        f"{pairs}")


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

    Ambient git config is NEUTRALIZED inside the runs by pointing
    HOME at an empty dir (G1-iter5: the script scrubs
    GIT_CONFIG_GLOBAL/SYSTEM from its own environment, so the old
    os.devnull trick no longer reaches it): CI runners configure no
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
        # ambient config neutralized via an empty HOME (G1-iter5 —
        # the script now scrubs GIT_CONFIG_GLOBAL/SYSTEM itself, so
        # the old os.devnull trick no longer reaches it; identical
        # identity-fallback path on CI runners and dev machines)
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e["HOME"] = str(empty_home)
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
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e["HOME"] = str(empty_home)
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
        # G1-iter5 RT critical #1: empty-credential apex spellings
        # parsed past v6's normalization — the @-strip needed ≥1 char
        # before the @, the port strips needed content after the :,
        # and all four sailed past the guard end-to-end in TEST mode
        # (the scp variant via a configured remote name attempted a
        # real git-receive-pack against git@github.com in the Red
        # Team's probe, blocked only by a fake ssh)
        "https://@github.com/maniesh-NR/Proto-Clean.git",      # empty userinfo
        "https://github.com:/maniesh-NR/Proto-Clean.git",      # empty port
        "https://@github.com:/maniesh-NR/Proto-Clean.git",     # both
        "git@github.com:/maniesh-NR/Proto-Clean.git",          # scp, empty path
        "https://@gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git",  # empty userinfo, subdomain
        # G1-iter5-i2 RT critical #2: the EMPTY-AUTHORITY family —
        # https:///github.com/… collapsed the host away in v7's
        # normalization while git/curl still connected to github.com
        # (raw ls-remote through a proxy: CONNECT github.com:443)
        "https:///github.com/maniesh-NR/Proto-Clean.git",
        "http:///github.com/maniesh-NR/Proto-Clean.git",
        "https:///gist.github.com/aa11bb22cc33dd44ee55ff6677aabbcc.git",
        # G1-iter5-i2 RT major #1: multi-@ ssh userinfo — the @-strip
        # removed only the FIRST segment while OpenSSH parses the
        # LAST @ (host=github.com); executed past the guard with the
        # ssh handoff verified (final socket hop modeled — no ssh
        # binary on the runners)
        "ssh://user@evil.com@github.com/maniesh-NR/Proto-Clean",
        "user@evil.com@github.com:maniesh-NR/Proto-Clean.git",
        # G1-iter6 RT critical #4: PERCENT-ENCODED hosts — curl decodes
        # the host before connecting (%67ithub.com and github%2ecom both
        # emitted CONNECT github.com:443 at a local sink) while the
        # normalizer compares the raw spelling
        "https://%67ithub.com/maniesh-NR/Proto-Clean.git",
        "https://github%2ecom/maniesh-NR/Proto-Clean.git",
        # G1-iter6 RT critical #5: helper TRANSPORTS — ext::/fd::
        # execute an arbitrary command as the push itself (a remote
        # named ext::git-receive-pack <path> landed a checkpoint by
        # running it)
        "ext::git-receive-pack /tmp/nowhere.git",
        "fd::17,/tmp/nowhere.git",
        # G1-iter6 RT major #1: the scp double-colon PORT spelling —
        # the greedy host cut read git@github.com:22:repo as host
        # github.com:22 (suffix-matches nothing) while the ssh handoff
        # reached github.com
        "git@github.com:22:maniesh-NR/Proto-Clean.git",
        # G1-iter6 RT minor #1: multi-trailing-dot hosts — only one
        # trailing dot used to be collapsed
        "github.com..",
        "https://gist.github.com../aa11bb22cc33dd44ee55ff6677aabbcc.git",
        # G1-iter6 RT minor #3: raw-IP hosts — the suffix denylist is a
        # NAME check; github's own IP spelled directly never matched
        # (loopback is exempt by design — the redaction lane's local
        # http sink)
        "https://140.82.121.4/maniesh-NR/Proto-Clean.git",
    ]
    subprocess.run(["git", "-C", str(repo), "remote", "add", "prodscp",
                    "git@github.com:maniesh-NR/Proto-Clean.git"], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "gistscp",
                    "git@gist.github.com:aa11bb22cc33dd44ee55ff6677aabbcc.git"], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "prodscpempty",
                    "git@github.com:/maniesh-NR/Proto-Clean.git"], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "doublescp",
                    "user@evil.com@github.com:maniesh-NR/Proto-Clean.git"], check=True)
    # G1-iter6 RT major #1 (remote-name side): the :22: scp spelling
    # via a configured remote — the direct form is caught by the
    # not-a-remote layer, the remote-carried form reached github
    subprocess.run(["git", "-C", str(repo), "remote", "add", "scp22",
                    "git@github.com:22:maniesh-NR/Proto-Clean.git"], check=True)
    # G1-iter6 RT critical #5 (remote-name side): the ext:: transport
    # via a configured remote (protocol.ext.allow defaults to never —
    # the guard must refuse on the SPELLING, before any transport
    # could run)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "extrans",
                    "ext::git-receive-pack /tmp/nowhere.git"], check=True)
    # G1-iter6 RT critical #2 (remote-name side): a remote whose URL
    # is RELATIVE with an interior .. — no ./ or ../ prefix, so v8's
    # prefix-shaped refusal and the absolute-only path compare both
    # skipped it; the push resolved at the temporary worktree base
    subprocess.run(["git", "-C", str(repo), "remote", "add", "relhide",
                    "harness/../../nowhere.git"], check=True)
    for target in list(variants) + ["prodscp", "gistscp", "prodscpempty",
                                    "doublescp", "scp22", "extrans",
                                    "relhide"]:
        e = dict(os.environ)
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": target,
                  "HOME": str(empty_home)})
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
              "HOME": str(empty_home)})
    r = subprocess.run(["bash", str(script), "guard clean lane"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, (r.returncode, r.stdout + r.stderr)

    # G1-iter5 Architect major #1 / RT critical #2: the push TARGET
    # must refuse the production checkout too — v6 checked only the
    # REPO operand, so a PC_BACKUP_PUSH_REMOTE pointing at the
    # production path wrote a test checkpoint onto its local
    # sandbox/backups, which the next production run propagated to
    # github (executed end-to-end in scratch). Literal spellings
    # refuse on any machine; filesystem-dependent spellings (symlink,
    # //) need the checkout to exist and run where it does.
    prod = _prod_checkout()
    prod_spellings = [prod, "file://" + prod, prod + "/", prod + "/.git"]
    if Path(prod).exists():
        tlink = tmp_path / "prod-target-link"
        tlink.symlink_to(prod)
        prod_spellings += [str(tlink), "//" + prod.lstrip("/")]
    for target in prod_spellings:
        e = dict(os.environ)
        e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": target,
                  "HOME": str(empty_home)})
        r = subprocess.run(["bash", str(script), "push-target probe"],
                           cwd=str(repo), env=e,
                           capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        assert r.returncode == 6, (target, r.returncode, out)
        assert "production checkout" in out, (target, out)

    # G1-iter5-i2 RT critical #1 / Architect major #1: RELATIVE push
    # targets are refused outright — the guard judges the operand at
    # the REPO's cwd while the push executes from the temporary
    # worktree under /tmp, so a relative target resolves somewhere
    # the guard never judged (executed E2E by two agents
    # independently: a ../../-chain from the worktree delivered a
    # test checkpoint onto a "production" stand-in's local branch)
    for target in ("../bare.git", "./bare.git",
                   "../../" + _prod_checkout()):
        e = dict(os.environ)
        e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": target,
                  "HOME": str(empty_home)})
        r = subprocess.run(["bash", str(script), "relative-target probe"],
                           cwd=str(repo), env=e,
                           capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        assert r.returncode == 6, (target, r.returncode, out)
        assert "RELATIVE" in out, (target, out)

    # G1-iter5-i2 Architect major #2: the pushurl-aware resolution
    # (`get-url --push`) is mutation-covered — a remote whose FETCH
    # url is an innocent local bare but whose pushurl is github must
    # be refused (v6's fetch-URL resolution never saw the divergence;
    # reverting --push to plain get-url must fail THIS lane)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "urlpush",
                    str(bare)], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "set-url", "--push",
                    "urlpush",
                    "https://github.com/maniesh-NR/Proto-Clean.git"], check=True)
    e = dict(os.environ)
    e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
              "PC_BACKUP_PUSH_REMOTE": "urlpush",
              "HOME": str(empty_home)})
    r = subprocess.run(["bash", str(script), "pushurl probe"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 6, (r.returncode, r.stdout + r.stderr)

    # G1-iter5 RT major #1: url.*.insteadOf rewrites live in config
    # FILES — v6 inspected the raw operand, so an innocent
    # local-looking push target was rewritten to a github host at
    # push time (executed in scratch with a real receive-pack
    # attempt). The guard now resolves the operand the way git does
    # (git ls-remote --get-url applies insteadOf), so the REWRITE is
    # what gets judged.
    subprocess.run(["git", "-C", str(repo), "config",
                    "url.https://github.com/maniesh-NR/Proto-Clean.git.insteadOf",
                    str(tmp_path / "innocent-local")], check=True)
    e = dict(os.environ)
    e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
              "PC_BACKUP_PUSH_REMOTE": str(tmp_path / "innocent-local"),
              "HOME": str(empty_home)})
    r = subprocess.run(["bash", str(script), "insteadOf probe"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 6, (r.returncode, r.stdout + r.stderr)

    # ...and env-injected config FILES are INERT: the scrub unsets
    # GIT_CONFIG_GLOBAL before any git call, so an insteadOf injected
    # that way never applies — the push goes to the local bare it was
    # addressed to (no github rewrite, no push failures)
    evil = tmp_path / "evil-gitconfig"
    evil.write_text("[url \"git@github.com:/maniesh-NR/Proto-Clean.git\"]\n"
                    "\tinsteadOf = " + str(bare) + "\n", encoding="utf-8")
    e = dict(os.environ)
    e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
              "PC_BACKUP_PUSH_REMOTE": str(bare),
              "HOME": str(empty_home),
              "GIT_CONFIG_GLOBAL": str(evil)})
    r = subprocess.run(["bash", str(script), "config-inert probe"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=240)
    out = r.stdout + r.stderr
    assert r.returncode == 0, (r.returncode, out)
    assert "push failed" not in out, (
        "the env-injected insteadOf was not inert — the push did not "
        "go to the local bare it was addressed to")

    # G1-iter6 RT critical #3: url.*.pushInsteadOf rewrites DIRECT
    # push operands at push time (executed E2E: the typed operand
    # …/innocent.git landed the checkpoint in a reconfigured bare) —
    # the guard resolves fetch-side, so ANY pushInsteadOf key in
    # visible config refuses the run outright (fail-closed)
    other_bare = tmp_path / "rewrite-target.git"
    subprocess.run(["git", "init", "-q", "--bare", str(other_bare)],
                   check=True)
    subprocess.run(["git", "-C", str(repo), "config",
                    "url." + str(other_bare) + ".pushInsteadOf",
                    str(bare)], check=True)
    e = dict(os.environ)
    e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
              "PC_BACKUP_PUSH_REMOTE": str(bare),
              "HOME": str(empty_home)})
    r = subprocess.run(["bash", str(script), "pushInsteadOf probe"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    assert r.returncode == 6, (r.returncode, out)
    assert "pushInsteadOf" in out, out
    assert "refs/heads/sandbox/backups" not in subprocess.run(
        ["git", "--git-dir", str(other_bare), "for-each-ref",
         "refs/heads/sandbox/backups"],
        capture_output=True, text=True).stdout, (
        "the pushInsteadOf probe reached the rewrite target")
    subprocess.run(["git", "-C", str(repo), "config", "--unset",
                    "url." + str(other_bare) + ".pushInsteadOf"],
                   check=True)

    # G1-iter6 RT critical #1: the git-dir IDENTITY — a subdirectory
    # or a linked worktree of ANOTHER checkout shares that checkout's
    # .git (git discovery walks UP / the common dir points elsewhere),
    # so the REPO path compares pass while every git operation runs on
    # the other checkout's git state (executed E2E on a stand-in: a
    # full test checkpoint + self-heal merge landed inside it). Both
    # shapes refuse on ANY machine (scratch stand-ins, no production
    # dependency).
    sub_repo = tmp_path / "standin"          # a scratch "other" checkout
    subprocess.run(["git", "clone", "-q", str(ROOT), str(sub_repo)],
                   check=True, timeout=120)
    subprocess.run(["git", "-C", str(sub_repo), "remote", "set-url",
                    "origin", str(bare)], check=True)
    for operand, label in [
            (sub_repo / "harness", "subdirectory (discovery walks up)"),
            (tmp_path / "standin-wt", "linked worktree (shared .git)")]:
        if "worktree" in label:
            subprocess.run(["git", "-C", str(sub_repo), "worktree", "add",
                            "--quiet", "--detach",
                            str(operand)], check=True, timeout=120)
        e = dict(os.environ)
        e.update({"PC_BACKUP_REPO": str(operand),
                  "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": str(bare),
                  "HOME": str(empty_home)})
        r = subprocess.run(["bash", str(script), "identity probe"],
                           cwd=str(sub_repo), env=e,
                           capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
        assert r.returncode == 6, (label, r.returncode, out)
        assert "git dir is not its own" in out, (label, out)

    # ...and the GIT_DIR env redirection is scrubbed with its family:
    # with GIT_DIR exported at another checkout, the run must behave
    # EXACTLY as if it were unset (the intended repo's own git state)
    e = dict(os.environ)
    e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
              "PC_BACKUP_PUSH_REMOTE": str(bare),
              "HOME": str(empty_home),
              "GIT_DIR": str(sub_repo) + "/.git"})
    r = subprocess.run(["bash", str(script), "gitdir-scrub probe"],
                       cwd=str(repo), env=e,
                       capture_output=True, text=True, timeout=240)
    assert r.returncode == 0, (r.returncode, r.stdout + r.stderr)
    assert "refs/heads/sandbox/backups" not in subprocess.run(
        ["git", "--git-dir", str(sub_repo) + "/.git", "for-each-ref",
         "refs/heads/sandbox/backups"],
        capture_output=True, text=True).stdout, (
        "the GIT_DIR export redirected the run into the stand-in")


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
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e.update({"PC_BACKUP_REPO": str(repo), "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": str(unreachable),
                  "HOME": str(empty_home)})
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
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e["HOME"] = str(empty_home)
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
    # any machine; the PHYSICAL canonicalized compare (cd + pwd -P)
    # additionally catches relative/symlink spellings where the path
    # exists)
    prod = _prod_checkout()
    for spelling in (prod, "file://" + prod, prod + "/"):
        r = run(PC_BACKUP_REPO=spelling, PC_SANDBOX_HOME=str(tmp_path),
                PC_BACKUP_PUSH_REMOTE=str(tmp_path))
        out = r.stdout + r.stderr
        assert r.returncode == 6, (spelling, r.returncode, out)
        assert "production checkout" in out, out
    # G1-iter5 RT critical #2: SYMLINKED and // spellings of the
    # production checkout sailed past the LOGICAL-pwd canonicalized
    # compare (executed end-to-end in scratch) — the compare is now
    # PHYSICAL. These spellings need the checkout to exist (dev
    # sandbox); CI legs keep the literal spellings above.
    if Path(prod).exists():
        rlink = tmp_path / "prod-repo-link"
        rlink.symlink_to(prod)
        plink = tmp_path / "prod-parent-link"
        plink.symlink_to(Path(prod).parent)
        for spelling in (str(rlink), str(rlink) + "/",
                         str(plink / Path(prod).name),
                         "//" + prod.lstrip("/")):
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
    empty_home = tmp_path / "home-env"
    empty_home.mkdir(exist_ok=True)
    e = {k: v for k, v in os.environ.items() if not k.startswith("PC_")}
    e.update({"PC_BACKUP_REPO": str(repo),
              "PC_SANDBOX_HOME": str(tmp_path),
              "PC_BACKUP_PUSH_REMOTE": f"{fake}@dead.example.com:x.git",
              "HOME": str(empty_home)})
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
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e.update({"PC_BACKUP_REPO": str(repo),
                  "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": push_remote or str(bare),
                  "HOME": str(empty_home),
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
    # (inline identity: CI runners configure no ambient git identity
    # — the G1-iter3 lesson, re-learned at G1-iter4-i2 when this very
    # line broke 4 POSIX legs with exit 128)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=probe",
                    "-c", "user.email=probe@invalid", "commit", "-q",
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

    # G1-iter5 Architect major #2 (the mutation-covering scrub
    # signal): the marker asserts above are calibrated to this git's
    # 401 behavior and can go vacuous on other versions — this lane is
    # the platform-independent signal. With the pattern scrub present,
    # a hostile GIT_TRACE=1 clean-lane run emits ZERO git trace lines
    # (removing the scrub made 26 leak through unredirected git stderr
    # in the Architect's mutation probe — the test must fail then).
    r3 = run_backup("trace probe", GIT_TRACE="1", GIT_TRACE2="1",
                    GIT_CURL_VERBOSE="1")
    out3 = r3.stdout + r3.stderr
    assert r3.returncode == 0, (r3.returncode, out3)
    assert "trace:" not in out3, (
        "GIT_TRACE output leaked through the script — the pattern env "
        "scrub did not neutralize it")


@pytest.mark.skipif(os.name != "posix", reason="backup script is POSIX")
def test_backup_script_index_rescan_positions():
    """G1-iter5 RT minor #3 (scan→add TOCTOU): the checkpoint commit
    must be preceded by an INDEX scan (`git grep --cached`) of exactly
    what will be committed — the index IS the commit content, so
    scanning it after the add closes the race window structurally
    (anything committed was staged; anything staged was scanned; the
    live window is sub-100 ms and needs a concurrent writer — outside
    the accident threat model). HONEST LABEL: this is a structural
    position check, not a behavioral one — no deterministic behavioral
    lane exists against the real script's timing (7 timed single-shot
    races by the G1-iter5 Red Team all missed the window); the
    behavioral surfaces are the planted-secret lanes (exit 4, both
    scans exercised) and the widened-window probe in
    harness/backups/matrices/verify_backup_v7.sh (E18)."""
    src = (ROOT / "scripts" / "sandbox_backup.sh").read_text(encoding="utf-8")
    lines = src.splitlines()
    # normal path: add → index scan → commit
    a = next(i for i, l in enumerate(lines)
             if l.strip() == "git add -f harness/sandbox harness/backups")
    c = next(i for i, l in enumerate(lines)
             if "[sandbox-backup] $MSG" in l and i > a)
    assert any("git grep --cached" in l for l in lines[a + 1:c]), (
        "the index re-scan (git grep --cached) must sit between the "
        "git add and the checkpoint commit")
    # divergence path: manifest add → index scan → merge commit
    a2 = next(i for i, l in enumerate(lines)
              if l.strip() == "git add harness/backups/manifest.json")
    c2 = next(i for i, l in enumerate(lines)
              if l.strip() == "git commit --no-edit -q" and i > a2)
    assert any("git grep --cached" in l for l in lines[a2 + 1:c2]), (
        "the index re-scan must also sit between the merged manifest "
        "add and the merge commit")


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
        empty_home = tmp_path / "home-env"
        empty_home.mkdir(exist_ok=True)
        e.update({"PC_BACKUP_REPO": str(repo),
                  "PC_SANDBOX_HOME": str(home),
                  "PC_BACKUP_PUSH_REMOTE": push_remote or str(bare),
                  "HOME": str(empty_home)})
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
