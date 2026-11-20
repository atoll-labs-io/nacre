#!/usr/bin/env bash
# po-session: the SessionStart hook of a Polype project. It prints what `po state` returns and
# changes nothing: no write, no git lock, no remote. Outside a Polype project, or inside a story
# worktree, it says nothing. At session start it never fails: a missing po or jq is one line.
set -u
export GIT_OPTIONAL_LOCKS=0

dir="${CLAUDE_PROJECT_DIR:-$PWD}"
top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$top" ] || exit 0
top="$(cd "$top" 2>/dev/null && pwd -P)" || exit 0
[ -f "$top/AGENTS.local.md" ] || [ -f "$top/.polype/version" ] || exit 0
case "$(git -C "$top" rev-parse --abbrev-ref HEAD 2>/dev/null)" in story/*) exit 0 ;; esac
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
  echo "po-session: bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]} found, bash 4.2 or newer needed; project state not read (on macOS: brew install bash)"
  exit 0
fi

local_md="$top/AGENTS.local.md"
po="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/polype/po"

echo "Polype project lead — state read from disk and git by po-session; nothing was run or changed."

if [ ! -x "$po" ]; then
  echo "po-session: po not found at $po; project state not read → polype install lays it down"
  exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "po-session: jq not found; project state not shown → install jq, or run $po state for the JSON"
  exit 0
fi
rc=0
json="$(cd "$top" && "$po" state 2>/dev/null)" || rc=$?
if [ "$rc" -ne 0 ] || ! jq -e .contract >/dev/null 2>&1 <<< "$json"; then
  echo "po-session: po state failed (exit $rc); project state not read → polype update . rebuilds po"
  exit 0
fi

setting() {
  sed -n "s/^$1:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*\$/\1/p" "$local_md" 2>/dev/null | head -n 1
}

claude_md="$(setting 'Project CLAUDE file')"
parallel=missing
[[ "$(setting 'Parallel')" =~ ^[0-9]+$ ]] && parallel=set

# Each line is tagged: P printed as is, W a "Waiting for a human" item, S the setup line that ends the report.
mapfile -t tagged < <(jq -r --arg parallel "$parallel" '
  def stop($id):
    if .code == "root-cause-not-found" then "\($id): root cause not found (\(.file))"
    elif .code == "technical-choice" then "\($id): technical choice waiting for a human (\(.file)) → \(.command)"
    elif .code == "qa-blocked" then "\($id): QA blocked (\(.file))"
    elif .code == "max-attempts" then "\($id): Max attempts reached (Fix loop: \(.fix_loop), Max attempts: \(.max_attempts))"
    elif .code == "merge-waiting" then "\($id): pull request presumed waiting for a human merge (\(.branch) pushed; the forge was not asked)"
    else "\($id): \(.code)" end;
  ["Target branch", "Entry mode", "Worktree root", "Max attempts", "Merge mode", "Ship confirmation"] as $named
  | ((.warnings // [])[] | select(.code == "method-version-mismatch") | "P\tpo warning: \(tojson)"),
    if .framing.stage == "setup" then "S\tFraming: setup missing → /po-setup"
    else
      (if .framing != null then
         "P\tFraming: \(.framing.items // [] | map("\(.item | gsub("-"; " ")) \(.state)") | join(" · "))",
         "P\tFraming next: \(.framing.next // "none — framing done")"
       else empty end),
      ((.warnings // [])[] | select(.code == "missing-setting" or .code == "unreadable-setting")
         | .setting as $s | select(any($named[]; . == $s)) | "P\tUnreadable setting: \($s)"),
      "P\tReady stories: \(
         if .ready == null then
           (if $parallel == "set" then "not read by po" else "not computed — Parallel is missing or unreadable in AGENTS.local.md" end)
         elif (.ready | length) == 0 then "none"
         else .ready | join(", ") end)",
      (if .lanes != null then
         "P\tLanes in flight: \(if (.lanes | length) == 0 then "none" else .lanes | map("\(.story) (\(.path))") | join(", ") end)"
       else empty end),
      "P\tDecisions answered, not consumed: \(
         if .answered == null then "not read by po"
         elif (.answered | length) == 0 then "none"
         else "\(.answered | length) → po inbox --answered" end)",
      ((.waiting // [])[] | "W\t\(.): decision pending → po inbox \(.)"),
      ((.lanes // [])[] | .story as $id | (.stops // [])[] | "W\t\(stop($id))"),
      ((.warnings // [])[] | select(.code == "orphan-worktree") | "W\t\(.path): orphan worktree (\(.branch // "detached HEAD"))")
    end' <<< "$json")

lines=()
for t in ${tagged[@]+"${tagged[@]}"}; do
  case "$t" in
    S$'\t'*) echo "${t#S$'\t'}"; exit 0 ;;
    P$'\t'*) echo "${t#P$'\t'}" ;;
    W$'\t'*) lines+=("${t#W$'\t'}") ;;
  esac
done

claude_md_hint() {
  local name
  # Same rule as the installer's recorded_mode: on an init project, advise `polype init .`, which
  # also repairs an inflated one; elsewhere `polype update .`.
  local again="polype update ." recorded=""
  [ -f "$top/.polype/mode" ] && recorded="$(head -n1 "$top/.polype/mode")"
  if [ "$recorded" = init ] || { [ "$recorded" != project ] && [ -f "$top/.polype/manifest" ] \
      && ! grep -q '^\.claude/commands/' "$top/.polype/manifest"; }; then
    again="polype init ."
  fi
  for name in CLAUDE.md CLAUDE.local.md; do
    [ -f "$top/$name" ] || continue
    case "$claude_md" in
      absorbed) lines+=("$name: Claude Code reads it instead of AGENTS.md → $again moves it into AGENTS.local.md") ;;
      kept) ;;
      *) lines+=("$name: Claude Code reads it instead of AGENTS.md → set Project CLAUDE file to absorbed or kept in AGENTS.local.md") ;;
    esac
  done
}
claude_md_hint

if [ ${#lines[@]} -eq 0 ]; then
  echo "Waiting for a human: nothing"
else
  echo "Waiting for a human:"
  printf -- '- %s\n' "${lines[@]}"
fi
exit 0
