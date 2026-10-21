#!/usr/bin/env bash
# po-gate — Polype's gates as plain file checks, so any tool (or CI) can enforce them.
#
#   po-gate plan-validated <id>   0 when the plan's frontmatter says `validated: yes`
#   po-gate ship-allowed <id>     0 when the review's last `Ship allowed:` line says yes, the `Review status:`
#                                 of that same review and the file's last one say complete, and its `Reviewed tree:`
#                                 still matches HEAD outside docs/
#   po-gate verif-current <id>    0 when the verification record is complete, matches HEAD, and every check its
#                                 `## Checks` table declares has a passing `po-run` row on the recorded code
#   po-gate qa-current <id>       0 when the committed QA report's last `QA status:` says complete and its `Tree:`
#                                 matches HEAD; ignored files do not count (ADR-0044)
#   po-gate pre-commit [<base>]   non-zero, on every branch, when a staged environment file or an added line holding
#                                 a private key or a known token is staged, or a CLAUDE.md or CLAUDE.local.md is
#                                 added or modified at any depth unless Project CLAUDE file is kept; and on a code
#                                 commit to story/<id> whose plan is not approved; the diff is taken against <base>
#                                 when given, else HEAD
#   po-gate findings-shape <id>  0 when ## Findings of the last review holds no line that names a severity outside the
#                                 shape /po-ship reads; 1 with each such line quoted as `<path>:<line>: <text>`;
#                                 2 when it cannot run (no id, no review, no verdict block)
#   po-gate floor-guard <id> <base>  scans `git diff <base>...story/<id>` for what lowers the bar of the checks:
#                                 0 nothing, 1 one `<path>:<line>: <rule>: <detail>` per flag, 2 cannot verify
#
# A story lands through a pull request the forge rebuilds (ADR-0080, ADR-0081), which no local hook sees; put
# `po-gate ship-allowed <id>` in CI, on a checkout of the story branch tip, never a merge ref: it compares against HEAD.
set -euo pipefail

# The commit the staged diff is read against; empty means HEAD.
DIFF_BASE=""

top() { git rev-parse --show-toplevel 2>/dev/null || pwd; }
refuse() { echo "po-gate: $*" >&2; return 1; }

frontmatter() { awk 'NR==1 && $0=="---" {on=1; next} on && $0=="---" {exit} on' "$1"; }

plan_validated() {
  local plan; plan="$(top)/docs/plans/$1.md"
  [ -f "$plan" ] || refuse "$1 has no plan yet (docs/plans/$1.md) — /po-plan $1" || return 1
  frontmatter "$plan" | grep -qE '^validated:[[:space:]]*yes[[:space:]]*$' \
    || refuse "the plan of $1 is not approved: its frontmatter lacks 'validated: yes' — /po-plan $1"
}

# The value of the block closed by the last line matching the verdict ERE: the last `<label>:` line since the previous
# verdict, so stacked reports pair each verdict with its own tree. A leading `- ` or `* ` is read away.
paired_value() {
  awk -v label="$1" -v verdict="$2" '
    { line = $0; if (line ~ /^[-*] /) line = substr(line, 3) }
    index(line, label ":") == 1 { cand = substr(line, length(label) + 2); sub(/^[[:space:]]+/, "", cand) }
    $0 ~ verdict { final = cand; cand = ""; closed = 1 }
    END { if (closed) print final }
  ' "$3"
}

# 40 hex alone or followed by a blank and a remark; abbreviations would resolve in git, so they are refused.
paired_hash() {
  local final h; final="$(paired_value "$@")"
  h="${final:0:40}"
  if [[ "$h" =~ ^[0-9a-f]{40}$ ]] && { [ ${#final} -eq 40 ] || [[ "${final:40:1}" =~ [[:space:]] ]]; }; then
    echo "$h"
  fi
  return 0
}

tree_exists() { git -C "$(top)" cat-file -e "$1^{tree}" 2>/dev/null; }

# docs/ is left out of the comparison: the record, the ticked plan and the review are written after the code they judge.
code_matches() { git -C "$(top)" diff --quiet "$1" HEAD -- . ':(exclude)docs'; }

# Only the last verdict line counts: a report may quote an earlier verdict before giving its own.
ship_allowed() {
  local review verdict tree pstatus lstatus; review="$(top)/docs/reviews/$1.md"
  [ -f "$review" ] || refuse "$1 has not been reviewed (docs/reviews/$1.md) — /po-review $1" || return 1
  verdict="$(grep -E '^([-*] )?Ship allowed:' "$review" | tail -n 1 | sed 's/^[-*] //' || true)"
  [[ "$verdict" =~ ^Ship\ allowed:[[:space:]]*yes[[:space:]]*$ ]] \
    || refuse "the review of $1 does not allow shipping (last verdict: ${verdict:-none})" || return 1
  pstatus="$(paired_value 'Review status' '^([-*] )?Ship allowed:' "$review")"
  lstatus="$(grep -E '^([-*] )?Review status:' "$review" | tail -n 1 | sed -E 's/^([-*] )?Review status:[[:space:]]*//' || true)"
  { [[ "$pstatus" =~ ^complete[[:space:]]*$ ]] && [[ "$lstatus" =~ ^complete[[:space:]]*$ ]]; } \
    || refuse "the review of $1 has no 'Review status: complete' line for its last verdict — /po-review $1" || return 1
  tree="$(paired_hash 'Reviewed tree' '^([-*] )?Ship allowed:' "$review")"
  [ -n "$tree" ] || refuse "the review of $1 has no usable 'Reviewed tree:' hash — /po-review $1" || return 1
  { tree_exists "$tree" && code_matches "$tree"; } \
    || refuse "the code of $1 changed after its review (tree $tree); the verdict no longer applies — /po-review $1"
}

# What /po-ship step 3.2 can file is a list item opening with its severity; anything else naming a severity there
# would be dropped or only reach the person, so it is refused while the reviewer can still be asked again (ADR-0094).
# The accepted motif is exactly the one step 3.2 opens: lowercase severity, then its separator (ADR-0096).
# Exit of the awk: 0 shape kept, 1 lines refused (printed), 2 no `## Findings` in the last block.
shape_unreadable() { echo "po-gate: cannot check the findings of ${1:-<id>}: $2" >&2; exit 2; }
findings_shape() {
  local review rel out rc=0
  [ -n "${1:-}" ] || shape_unreadable "" "usage: po-gate findings-shape <id>"
  rel="docs/reviews/$1.md"; review="$(top)/$rel"
  [ -f "$review" ] || shape_unreadable "$1" "$1 has not been reviewed ($rel)"
  grep -qE '^([-*] )?Ship allowed:' "$review" \
    || shape_unreadable "$1" "the review has no verdict block (no 'Ship allowed:' line)"
  out="$(awk -v rel="$rel" '
    function names(s) { return tolower(s) ~ /(^|[^a-z0-9_])(critical|major|minor)([^a-z0-9_]|$)/ }
    function ships(s) { return s ~ /^([-*] |[0-9]+\. )(\*\*(critical|major|minor):\*\*|((critical|major|minor)|\*\*(critical|major|minor)\*\*) *(—|:|-))/ }
    function first(s) { sub(/^[^A-Za-z]+/, "", s); return tolower(s) ~ /^(critical|major|minor)([^a-z0-9_]|$)/ }
    { text[NR] = $0 }
    /^([-*] )?Ship allowed:/ { prev = last; last = NR }
    END {
      for (n = prev + 1; n < last; n++) {
        l = text[n]
        if (!on) { if (l ~ /^## Findings[[:space:]]*$/) { on = 1; seen = 1 } ; continue }
        if (l ~ /^## /) break
        if (l ~ /^#/) bad = names(l)
        else if (l == "" || l ~ /^[ \t]/) bad = 0
        else if (l ~ /^([-*] |[0-9]+\. )/) { item = l; sub(/^([-*] |[0-9]+\. )/, "", item); bad = names(item) && !ships(l) }
        else bad = first(l)
        if (bad) { print rel ":" n ": " l; refused = 1 }
      }
      if (!seen) exit 2
      exit refused ? 1 : 0
    }
  ' "$review")" || rc=$?
  [ "$rc" -ne 2 ] || refuse "the last review of $1 has no '## Findings' section — the shape of templates/review.md" || return 1
  [ "$rc" -eq 0 ] && return 0
  [ "$rc" -eq 1 ] || shape_unreadable "$1" "could not read the findings (awk exit $rc)"
  while IFS= read -r line; do refuse "$line" || true; done <<< "$out"
  refuse "the findings of $1 are not in the shape of templates/review.md — each finding is one list item opening with its severity, never a heading"
}

verif_current() {
  local record tree; record="$(top)/docs/verif/$1.md"
  [ -f "$record" ] || refuse "$1 has no verification record (docs/verif/$1.md)" || return 1
  grep -qE '^Verification status:[[:space:]]*complete[[:space:]]*$' "$record" \
    || refuse "the verification record of $1 is not marked complete" || return 1
  tree="$(paired_hash 'Tree' '^Verification status:' "$record")"
  [ -n "$tree" ] || refuse "the verification record of $1 has no usable 'Tree:' hash" || return 1
  tree_exists "$tree" \
    || refuse "tree $tree from the record of $1 does not exist in this repository" || return 1
  code_matches "$tree" \
    || refuse "the code of $1 changed after its checks ran; the record no longer matches HEAD" || return 1
  grep -q '^## Checks$' "$record" \
    || refuse "the verification record of $1 has no Checks table — rebuild it from templates/verification-record.md" || return 1
  runs_cover_checks "$1" "$record" "$tree"
}

# One line per declared check (C, label, command), per unreadable Checks row (E, line number, row) and per run row
# (R, label, command, exit, tree), fields split by \037.
# Run rows are read from both ends so a `|` inside a command cannot shift the exit, tree or time cells.
record_rows() {
  awk '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function unquote(s) { s = trim(s); if (length(s) >= 2 && substr(s, 1, 1) == "`" && substr(s, length(s), 1) == "`") s = substr(s, 2, length(s) - 2); return s }
    function separator(   i) { for (i = 1; i <= n; i++) if (cell[i] !~ /^[[:space:]]*:?-+:?[[:space:]]*$/) return 0; return 1 }
    function middle(from, to,   i, s) { s = cell[from]; for (i = from + 1; i <= to; i++) s = s "|" cell[i]; return s }
    /^## / { section = $0; rows = 0; next }
    section != "## Checks" && section != "## Runs" { next }
    !/^[[:space:]]*\|/ { next }
    {
      line = trim($0); sub(/^\|/, "", line); sub(/\|$/, "", line)
      n = split(line, cell, "|"); rows++
      if (rows == 1) next
      if (section == "## Runs" && line ~ /^[[:space:]]*:?-+/) next
    }
    section == "## Checks" && rows == 2 && separator() { next }
    section == "## Checks" && (n < 3 || trim(cell[1]) ~ /^:?-+/) { printf "E\037%d\037%s\n", NR, $0; next }
    section == "## Checks" {
      label = trim(cell[1]); command = unquote(middle(2, n - 1))
      if (command != "—") printf "C\037%s\037%s\n", label, command
      next
    }
    section == "## Runs" && n >= 5 {
      label = trim(cell[1]); tree = trim(cell[n - 1]); code = trim(cell[n - 2]); command = unquote(middle(2, n - 3))
      if (length(tree) == 40 && tree ~ /^[0-9a-f]+$/ && code ~ /^[0-9]+$/)
        printf "R\037%s\037%s\037%s\037%s\n", label, command, code, tree
    }
  ' "$1"
}

# A declared check counts only through rows with its label and command whose tree holds the recorded code outside
# docs/; the last of those decides, so a failure on the final code is not hidden by a success on earlier code.
runs_cover_checks() {
  local id="$1" record="$2" tree="$3" rows kind label command kind_r label_r command_r code run_tree last found
  local q="'\\''" ql qc
  rows="$(record_rows "$record")" || refuse "could not read the tables of the verification record of $id" || return 1
  while IFS=$'\037' read -r kind label command; do
    [ "$kind" = E ] || continue
    refuse "the Checks table of the verification record of $id has a row it cannot read (line $label): $command — rebuild it from templates/verification-record.md" \
      || return 1
  done <<< "$rows"
  while IFS=$'\037' read -r kind label command; do
    [ "$kind" = C ] || continue
    found=0 last=""
    while IFS=$'\037' read -r kind_r label_r command_r code run_tree; do
      [ "$kind_r" = R ] && [ "$label_r" = "$label" ] && [ "$command_r" = "$command" ] || continue
      tree_exists "$run_tree" && git -C "$(top)" diff --quiet "$run_tree" "$tree" -- . ':(exclude)docs' || continue
      found=1 last="$code"
    done <<< "$rows"
    ql="'${label//\'/$q}'" qc="'${command//\'/$q}'"
    [ "$found" -eq 1 ] \
      || refuse "check '$label' of $id has no po-run row on the recorded code — po-run --story $id --label $ql -- $qc" \
      || return 1
    [ "$last" = 0 ] || refuse "check '$label' of $id last exited $last on the recorded code" || return 1
  done <<< "$rows"
}

# Like the review's verdict, only the last status line counts: a report may quote an earlier one.
qa_current() {
  local report status tree repo dirty hint=""; repo="$(top)"; report="$repo/docs/qa/$1/report.md"
  [ -f "$report" ] || refuse "$1 has no QA report (docs/qa/$1/report.md) — /po-qa $1" || return 1
  status="$(grep -E '^QA status:' "$report" | tail -n 1 || true)"
  [[ "$status" =~ ^QA\ status:[[:space:]]*complete[[:space:]]*$ ]] \
    || refuse "the QA report of $1 is not complete (last status: ${status:-none}) — /po-qa $1" || return 1
  tree="$(paired_hash 'Tree' '^QA status:' "$report")"
  [ -n "$tree" ] || refuse "the QA report of $1 has no usable 'Tree:' hash — /po-qa $1" || return 1
  tree_exists "$tree" \
    || refuse "tree $tree from the QA report of $1 does not exist in this repository — /po-qa $1" || return 1
  code_matches "$tree" \
    || refuse "the code of $1 changed after its QA walk; the report no longer matches HEAD — /po-qa $1" || return 1
  { git -C "$repo" cat-file -e "HEAD:docs/qa/$1/report.md" 2>/dev/null \
    && dirty="$(git -C "$repo" status --porcelain --untracked-files=all -- "docs/qa/$1/")" \
    && [ -z "$dirty" ]; } \
    || {
      git -C "$repo" check-ignore -q -- "docs/qa/$1/report.md" \
        && hint=" (report.md is ignored by git: un-ignore it first)"
      refuse "the QA report of $1 is current but docs/qa/$1/ is not committed$hint — commit it alone: git commit -m \"$1: QA evidence\" -- docs/qa/$1/ (/po-qa $1)"
    }
}

# --- secret scan ---------------------------------------------------------------
# One entry per line: <rule>|<min length>|<POSIX ERE>, matched against every line a commit adds, on any branch.
# A new format is one more line. The minimum length stands in for {n} (see the floor guard's patterns below). A match
# that starts with [A-Za-z0-9_] does not count when the character before it is one too, so `desk_live_...` is not a
# Stripe key; a match starting with any other character (the PEM header's dashes) counts after anything, `\n` included.
SECRET_PATTERNS='private-key|0|-----BEGIN[A-Z ]*PRIVATE KEY
aws-access-key|20|(AKIA|ASIA)[0-9A-Z]+
github-token|40|gh[pousr]_[A-Za-z0-9]+
github-token|40|github_pat_[A-Za-z0-9_]+
stripe-secret-key|24|(sk|rk)_(live|test)_[A-Za-z0-9]+
anthropic-key|40|sk-ant-[A-Za-z0-9_-]+'

# Prints one line per hit on stdout, never the matched text; returns 1 only when the index cannot be read.
secret_scan() {
  local paths path base diff out rc=0
  # --diff-filter=d: unstaging a tracked .env is the fix, so a staged deletion passes.
  paths="$(git -c core.quotePath=false diff --cached --name-only --no-renames --diff-filter=d -z ${DIFF_BASE:+"$DIFF_BASE"} | tr '\0' '\n')" \
    || refuse "could not list the staged files; refusing the commit" || return 1
  while IFS= read -r path; do
    base="${path##*/}"
    case "$base" in
      .env.example) ;;
      .env|.env.*) echo "po-gate: $path: environment file staged — unstage it and list it in .gitignore" ;;
    esac
  done <<< "$paths"
  diff="$(git -c core.quotePath=false diff --cached --no-color --no-ext-diff --no-textconv --no-renames \
    --src-prefix=a/ --dst-prefix=b/ -U0 ${DIFF_BASE:+"$DIFF_BASE"})" \
    || refuse "could not read the staged diff; refusing the commit" || return 1
  [ -n "$diff" ] || return 0
  out="$(SECRET_PATTERNS="$SECRET_PATTERNS" awk '
    function header_path(s, pre) {
      sub(/\t$/, "", s)
      if (s ~ /^".*"$/) s = substr(s, 2, length(s) - 2)
      if (substr(s, 1, 2) == pre) s = substr(s, 3)
      return s
    }
    function hit(s, i,   rest, pos, before) {
      rest = s; pos = 0
      while (match(rest, pat[i])) {
        before = pos + RSTART - 1 > 0 ? substr(s, pos + RSTART - 1, 1) : ""
        if ((before !~ /[A-Za-z0-9_]/ || substr(rest, RSTART, 1) !~ /[A-Za-z0-9_]/) && RLENGTH >= plen[i]) return 1
        pos += RSTART + RLENGTH - 1; rest = substr(rest, RSTART + RLENGTH)
        if (RLENGTH == 0) return 0
      }
      return 0
    }
    function added(s,   i, seen) {
      split("", seen)
      for (i = 1; i <= np; i++) if (!(prule[i] in seen) && hit(s, i)) { seen[prule[i]] = 1; print "po-gate: " file ":" line ": " prule[i] " (value not shown)" }
    }
    BEGIN {
      n = split(ENVIRON["SECRET_PATTERNS"], rows, "\n")
      for (i = 1; i <= n; i++) {
        if (rows[i] == "") continue
        p1 = index(rows[i], "|"); rest = substr(rows[i], p1 + 1); p2 = index(rest, "|")
        np++; prule[np] = substr(rows[i], 1, p1 - 1); plen[np] = substr(rest, 1, p2 - 1) + 0; pat[np] = substr(rest, p2 + 1)
      }
    }
    remold > 0 || remnew > 0 {
      c = substr($0, 1, 1)
      if (c == "-" && remold > 0) { remold--; next }
      if (c == "+" && remnew > 0) { remnew--; added(substr($0, 2)); line++; next }
      if (c == "\\") next
      bad = 1; remold = 0; remnew = 0
    }
    /^diff --git / { file = ""; next }
    /^\+\+\+ / { s = substr($0, 5); file = (s == "/dev/null") ? "" : header_path(s, "b/"); next }
    /^@@ / {
      o = substr($2, 2); w = substr($3, 2)
      if (index(o, ",")) { split(o, t, ","); remold = t[2] + 0 } else remold = 1
      if (index(w, ",")) { split(w, t, ","); line = t[1] + 0; remnew = t[2] + 0 } else { line = w + 0; remnew = 1 }
      next
    }
    END { if (bad) exit 3 }
  ' <<< "$diff")" || rc=$?
  [ "$rc" -eq 0 ] || refuse "could not scan the staged diff for secrets (awk exit $rc); refusing the commit" || return 1
  [ -z "$out" ] || printf '%s\n' "$out"
}

# Claude Code reads AGENTS.md only while no CLAUDE.md exists (ADR-0086); deleting one is the fix, so it passes.
# Only the exact value kept lets them through (ADR-0089): a missing line or a typo refuses as before.
claude_md_check() {
  local paths path found=no keep
  keep="$(sed -n 's/^Project CLAUDE file:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' "$(top)/AGENTS.local.md" 2>/dev/null | head -n 1)"
  [ "$keep" = kept ] && return 0
  paths="$(git -c core.quotePath=false diff --cached --name-only --no-renames --diff-filter=d -z ${DIFF_BASE:+"$DIFF_BASE"} | tr '\0' '\n')" \
    || refuse "could not list the staged files; refusing the commit" || return 1
  while IFS= read -r path; do
    case "${path##*/}" in
      CLAUDE.md|CLAUDE.local.md)
        refuse "$path: CLAUDE.md staged — Claude Code reads AGENTS.md only while none exists; put its notes in AGENTS.local.md" \
          || found=yes ;;
    esac
  done <<< "$paths"
  [ "$found" = no ]
}

pre_commit() {
  local branch staged path code=no hits count
  if [ -n "${1:-}" ]; then
    DIFF_BASE="$(git rev-parse --verify --quiet "$1^{commit}")" \
      || refuse "cannot read base $1; refusing the commit" || return 1
  fi
  hits="$(secret_scan)" || return 1
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" >&2
    count="$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
    refuse "refusing the commit: $count staged secret(s); the values are not shown" || return 1
  fi
  claude_md_check || return 1
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  [[ "$branch" == story/* ]] || return 0
  # --no-renames: moving code into docs/ must count as touching code.
  staged="$(git diff --cached --name-only --no-renames ${DIFF_BASE:+"$DIFF_BASE"})" \
    || refuse "could not list the staged files; refusing the commit" || return 1
  while IFS= read -r path; do
    case "$path" in ''|docs/*) ;; *) code=yes ;; esac
  done <<< "$staged"
  [ "$code" = yes ] || return 0
  plan_validated "${branch#story/}" \
    || refuse "no code commit on $branch before its plan is approved (commits touching only docs/ are fine)"
}

# --- floor guard ---------------------------------------------------------------
# One entry per line: <extensions>|<rule>|<POSIX ERE>, matched against the lines a story adds to a file with one
# of those extensions. A new language is new lines: its extensions, then one ERE per directive. POSIX classes
# only ([[:space:]], never \s or \b, no {n}) so the awk of macOS and mawk read them as gawk does.
FLOOR_PATTERNS='ts tsx js jsx mjs cjs mts cts|typecheck-ignored|@ts-(ignore|nocheck|expect-error)
ts tsx js jsx mjs cjs mts cts|lint-disabled|eslint-disable|biome-ignore
ts tsx js jsx mjs cjs mts cts|coverage-excluded|(istanbul|c8|v8) ignore
ts tsx js jsx mjs cjs mts cts|test-skipped|(^|[^A-Za-z0-9_$.])(it|test|describe|suite|context)\.skip([^A-Za-z0-9_$]|$)
ts tsx js jsx mjs cjs mts cts|test-skipped|(^|[^A-Za-z0-9_$.])x(it|test|describe)[[:space:]]*\(
ts tsx js jsx mjs cjs mts cts|test-only|(^|[^A-Za-z0-9_$.])(it|test|describe|suite|context)\.only([^A-Za-z0-9_$]|$)
ts tsx js jsx mjs cjs mts cts|test-only|(^|[^A-Za-z0-9_$.])f(it|describe)[[:space:]]*\(
ts tsx js jsx mjs cjs mts cts|empty-catch|catch[[:space:]]*(\([^)]*\))?[[:space:]]*\{[[:space:]]*\}
ts tsx js jsx mjs cjs mts cts|empty-catch|\.catch\([[:space:]]*(\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)?[[:space:]]*=>[[:space:]]*\{[[:space:]]*\}[[:space:]]*\)
py pyi|typecheck-ignored|#[[:space:]]*(type|pyright):[[:space:]]*ignore
py pyi|lint-disabled|#[[:space:]]*(noqa|pylint:[[:space:]]*disable|ruff:[[:space:]]*noqa)
py pyi|coverage-excluded|#[[:space:]]*pragma:[[:space:]]*no[[:space:]]*cover
py pyi|test-skipped|pytest\.mark\.(skip|skipif|xfail)|pytest\.skip\(|unittest\.skip|skipTest\(
py pyi|empty-catch|^[[:space:]]*except([^A-Za-z0-9_][^:]*)?:[[:space:]]*(pass|\.\.\.)[[:space:]]*(#.*)?$'

# A test file is a path matching one of these EREs.
FLOOR_TEST_PATHS='(^|/)(tests?|__tests__|specs?)/
(^|/)[^/]*\.(test|spec)\.[^/]*$
(^|/)test_[^/]*\.py$
(^|/)[^/]*_test\.py$'

unverifiable() { echo "po-gate: cannot verify the floor of ${1:-<id>}: $2" >&2; exit 2; }

# Reads only the story's diff; every failure path exits 2, because under `set -e` it would otherwise read as 1 (flags).
floor_guard() {
  local id="$1" base="$2" repo diff status out rc=0 count
  [ -n "$id" ] && [ -n "$base" ] || unverifiable "$id" "usage: po-gate floor-guard <id> <base>"
  repo="$(top)"
  git -C "$repo" rev-parse --verify --quiet "story/$id^{commit}" >/dev/null \
    || unverifiable "$id" "branch story/$id does not resolve"
  git -C "$repo" rev-parse --verify --quiet "$base^{commit}" >/dev/null \
    || unverifiable "$id" "base $base does not resolve"
  git -C "$repo" merge-base "$base" "story/$id" >/dev/null 2>&1 \
    || unverifiable "$id" "story/$id and $base share no merge base"
  # Options pinned so user config (prefixes, quoting, colour, external diff, renames) cannot change the format.
  diff="$(git -C "$repo" -c core.quotePath=false diff --no-color --no-ext-diff --no-textconv --find-renames \
    --src-prefix=a/ --dst-prefix=b/ -U0 "$base...story/$id")" \
    || unverifiable "$id" "git diff $base...story/$id failed"
  status="$(git -C "$repo" -c core.quotePath=false diff --no-color --name-status --find-renames "$base...story/$id")" \
    || unverifiable "$id" "git diff --name-status $base...story/$id failed"
  [ -n "$diff" ] || exit 0
  out="$(FLOOR_PATTERNS="$FLOOR_PATTERNS" FLOOR_TEST_PATHS="$FLOOR_TEST_PATHS" FLOOR_STATUS="$status" awk '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function flag(p, l, rule, detail) { print p ":" l ": " rule ": " detail }
    function is_test(p,   i) { for (i = 1; i <= ntp; i++) if (tp[i] != "" && p ~ tp[i]) return 1; return 0 }
    function header_path(s, pre) {
      sub(/\t$/, "", s)
      if (s ~ /^".*"$/) s = substr(s, 2, length(s) - 2)
      if (substr(s, 1, 2) == pre) s = substr(s, 3)
      return s
    }
    function threshold(s, side, l,   rest, m, k, v, key) {
      rest = s
      while (match(rest, /(^|[^A-Za-z0-9_])(branches|functions|lines|statements|fail[-_]under)["\047]?[[:space:]]*[:=][[:space:]]*[0-9]+(\.[0-9]+)?/)) {
        m = substr(rest, RSTART, RLENGTH); rest = substr(rest, RSTART + RLENGTH)
        v = m; sub(/.*[^0-9.]/, "", v)
        k = m; sub(/^[^A-Za-z]/, "", k); match(k, /^[a-z]+([-_]under)?/); k = substr(k, 1, RLENGTH); sub(/-/, "_", k)
        key = file SUBSEP k
        if (!(key in tseen)) { tseen[key] = 1; tord[++nt] = key }
        if (side == "-") { nrem[key]++; rval[key, nrem[key]] = v; rline[key, nrem[key]] = l }
        else { nadd[key]++; aval[key, nadd[key]] = v; aline[key, nadd[key]] = l }
      }
    }
    function assertion(side, l) {
      if (!(file in aseen)) { aseen[file] = 1; aord[++na] = file }
      if (side == "-") { if (!arem[file]) apos[file] = l; arem[file]++ } else aadd[file]++
    }
    function removed(s) {
      if (thr) threshold(s, "-", rpos)
      if (testfile && !gone && s ~ /expect\(|assert/) assertion("-", rpos)
    }
    function added(s,   i, t) {
      t = trim(s)
      if (ext != "") for (i = 1; i <= np; i++) if (index(pext[i], " " ext " ") && s ~ pat[i]) flag(file, line, prule[i], t)
      if (pend_catch && t == "}") flag(file, pend_catch, "empty-catch", pend_text)
      if (pend_except && t ~ /^(pass|\.\.\.)[[:space:]]*(#.*)?$/) flag(file, pend_except, "empty-catch", pend_text)
      pend_catch = 0; pend_except = 0
      if (js && s ~ /catch[[:space:]]*(\([^)]*\))?[[:space:]]*\{[[:space:]]*$/) { pend_catch = line; pend_text = t }
      if (py && s ~ /^[[:space:]]*except([^A-Za-z0-9_][^:]*)?:[[:space:]]*(#.*)?$/) { pend_except = line; pend_text = t }
      if (tsconfig && s ~ /"(strict|noImplicitAny|strictNullChecks|strictFunctionTypes|strictBindCallApply|strictPropertyInitialization|noImplicitThis|alwaysStrict|useUnknownInCatchVariables|noUncheckedIndexedAccess|exactOptionalPropertyTypes)"[[:space:]]*:[[:space:]]*false/) flag(file, line, "strict-off", t)
      if (thr) threshold(s, "+", line)
      if (testfile && s ~ /expect\(|assert/) assertion("+", line)
    }
    function ext_of(p,   b, e) { b = p; sub(/.*\//, "", b); e = ""; if (b ~ /\./) { e = b; sub(/.*\./, "", e) }; return e }
    function same_language(a, b,   i) {
      if (a == "" || b == "") return 0
      for (i = 1; i <= np; i++) if (index(pext[i], " " a " ") && index(pext[i], " " b " ")) return 1
      return 0
    }
    function open_file(p,   b) {
      file = p; b = p; sub(/.*\//, "", b)
      ext = ""; if (b ~ /\./) { ext = b; sub(/.*\./, "", ext) }
      js = index(" ts tsx js jsx mjs cjs mts cts ", " " ext " ") && ext != ""
      py = (ext == "py" || ext == "pyi")
      tsconfig = (b ~ /^tsconfig.*\.json$/)
      thr = (b ~ /^(jest|vitest|vite)\.config\./ || b == "pyproject.toml" || b == ".coveragerc")
      testfile = is_test(p)
    }
    BEGIN {
      n = split(ENVIRON["FLOOR_PATTERNS"], rows, "\n")
      for (i = 1; i <= n; i++) {
        if (rows[i] == "") continue
        p1 = index(rows[i], "|"); rest = substr(rows[i], p1 + 1); p2 = index(rest, "|")
        np++; pext[np] = " " substr(rows[i], 1, p1 - 1) " "; prule[np] = substr(rest, 1, p2 - 1); pat[np] = substr(rest, p2 + 1)
      }
      ntp = split(ENVIRON["FLOOR_TEST_PATHS"], tp, "\n")
      ns = split(ENVIRON["FLOOR_STATUS"], st, "\n")
      for (i = 1; i <= ns; i++) {
        if (st[i] ~ /^D\t/ && is_test(substr(st[i], 3))) flag(substr(st[i], 3), 0, "test-file-deleted", "deleted by the story")
        if (st[i] ~ /^R[0-9]*\t/) {
          split(st[i], rn, "\t")
          # The guard reads no runner config: an extension change counts as ignored unless one language list holds both.
          if (is_test(rn[2]) && (!is_test(rn[3]) || (ext_of(rn[2]) != ext_of(rn[3]) && !same_language(ext_of(rn[2]), ext_of(rn[3])))))
            flag(rn[2], 0, "test-file-deleted", "renamed to " rn[3])
        }
      }
    }
    remold > 0 || remnew > 0 {
      c = substr($0, 1, 1)
      if (c == "-" && remold > 0) { remold--; removed(substr($0, 2)); next }
      if (c == "+" && remnew > 0) { remnew--; added(substr($0, 2)); line++; next }
      if (c == "\\") next
      bad = 1; remold = 0; remnew = 0
    }
    /^\\/ { next }
    /^diff --git a\// { blocks++; file = ""; next }
    /^--- / { oldpath = header_path(substr($0, 5), "a/"); next }
    /^\+\+\+ / {
      s = substr($0, 5); headers++
      if (s == "/dev/null") { open_file(oldpath); gone = 1 } else { open_file(header_path(s, "b/")); gone = 0 }
      next
    }
    /^@@ / {
      if (file == "") { bad = 1; next }
      o = substr($2, 2); w = substr($3, 2)
      if (index(o, ",")) { split(o, t, ","); remold = t[2] + 0 } else remold = 1
      if (index(w, ",")) { split(w, t, ","); start = t[1] + 0; remnew = t[2] + 0 } else { start = w + 0; remnew = 1 }
      line = start
      rpos = gone ? 0 : (remnew == 0 && start == 0 ? 1 : start)
      pend_catch = 0; pend_except = 0
      next
    }
    END {
      if (bad || remold > 0 || remnew > 0 || (NR > 0 && blocks == 0 && headers == 0)) exit 3
      for (i = 1; i <= na; i++) {
        f = aord[i]
        if (arem[f] > aadd[f]) flag(f, apos[f], "assertions-dropped", arem[f] " removed, " (aadd[f] + 0) " added")
      }
      for (i = 1; i <= nt; i++) {
        key = tord[i]; split(key, kk, SUBSEP)
        for (j = 1; j <= nrem[key]; j++) {
          if (j <= nadd[key]) { if (aval[key, j] + 0 < rval[key, j] + 0) flag(kk[1], aline[key, j], "threshold-lowered", kk[2] " " rval[key, j] " → " aval[key, j]) }
          else flag(kk[1], rline[key, j], "threshold-removed", kk[2] " " rval[key, j])
        }
      }
    }
  ' <<< "$diff")" || rc=$?
  [ "$rc" -ne 3 ] || unverifiable "$id" "the diff of $base...story/$id is in a format this guard cannot read"
  [ "$rc" -eq 0 ] || unverifiable "$id" "awk failed with exit $rc while reading the diff"
  [ -n "$out" ] || exit 0
  printf '%s\n' "$out"
  count="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  echo "po-gate: $count flag(s) lower the bar of $id against $base" >&2
  exit 1
}

case "${1:-}" in
  floor-guard)    floor_guard "${2:-}" "${3:-}" ;;
  plan-validated) plan_validated "${2:?story id required}" ;;
  ship-allowed)   ship_allowed "${2:?story id required}" ;;
  findings-shape) findings_shape "${2:-}" ;;
  verif-current)  verif_current "${2:?story id required}" ;;
  qa-current)     qa_current "${2:?story id required}" ;;
  pre-commit)     pre_commit "${2:-}" ;;
  *) echo "po-gate: unknown subcommand '${1:-}' (see the header of this script)" >&2; exit 2 ;;
esac
