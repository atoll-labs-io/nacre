#!/usr/bin/env bash
# po-session: the SessionStart hook of a Polype project. It runs at every session start, so it
# stays fast, and it is read-only: it reads files and git refs, writes nothing, takes no git lock,
# never asks a remote. Outside a Polype project, or inside a story worktree, it says nothing.
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
id_re='s[0-9]+-[a-z0-9-]+'

echo "Polype project lead — state read from disk and git by po-session; nothing was run or changed."

if [ ! -f "$local_md" ]; then
  echo "Framing: setup missing → /po-setup"
  exit 0
fi

setting() {
  sed -n "s/^$1:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*\$/\1/p" "$local_md" | head -n 1
}

target="$(setting 'Target branch')"
entry="$(setting 'Entry mode')"
wtroot="$(setting 'Worktree root')"
max_attempts="$(setting 'Max attempts')"
merge_mode="$(setting 'Merge mode')"
confirmation="$(setting 'Ship confirmation' | sed -E 's/[[:space:]]*\((forge|chosen)\)$//')"
claude_md="$(setting 'Project CLAUDE file')"

unreadable() { echo "Unreadable setting: $1"; }

on_target() { git -C "$top" show "$target:$1" 2>/dev/null; }
on_target_exists() { git -C "$top" cat-file -e "$target:$1" 2>/dev/null; }

# The last `Name:` value of a file, first word only.
last_value() {
  [ -f "$2" ] || return 0
  grep "^$1:" "$2" 2>/dev/null | tail -n 1 | sed "s/^$1:[[:space:]]*//" | awk '{print $1}'
}

frontmatter_status() {
  awk 'NR==1 && $0=="---" {inside=1; next} inside && $0=="---" {exit} inside && /^status:/ {sub(/^status:[[:space:]]*/, ""); print; exit}'
}

# --- Framing --------------------------------------------------------------------------------

# True when stories exist, each has a Surface line and none says screen; a story without one may have a screen (Law 1).
no_story_has_a_screen() {
  on_target docs/stories.md | awk -v re="$id_re" '
    function flush() { if (id != "") { n++; if (!surf) unknown = 1; if (scr) screen = 1 } id = ""; surf = 0; scr = 0 }
    /^##+ / { flush(); line = $0; sub(/^##+ /, "", line); if (match(line, "^" re)) id = substr(line, 1, RLENGTH); next }
    id != "" && /^- \*\*Surface\*\*/ {
      surf = 1; v = tolower($0); sub(/^[^:]*:/, "", v)
      if (v ~ /(^|[^a-z])screen([^a-z]|$)/) scr = 1
    }
    END { flush(); exit !(n > 0 && !unknown && !screen) }'
}

framing() {
  local scope_file="" scope_cmd="" scope stories review arch ds next ready_value
  case "$entry" in
    replace|adapt) scope_file="docs/prd.md" scope_cmd="/po-prd" ;;
    new) scope_file="docs/brief.md" scope_cmd="/po-brief" ;;
    —) ;;
    *) unreadable "Entry mode"; return ;;
  esac
  if [ -z "$scope_file" ]; then
    scope="by hand"
  elif on_target_exists "$scope_file"; then
    if [ "$(on_target "$scope_file" | frontmatter_status)" = approved ]; then scope=approved; else scope="in progress"; fi
  else
    scope=missing
  fi
  if on_target_exists docs/stories.md; then stories=present; else stories=missing; fi
  ready_value="$(on_target docs/reviews/stories.md | grep '^Stories ready:' | tail -n 1 | sed 's/^Stories ready:[[:space:]]*//' | awk '{print tolower($1)}')"
  case "$ready_value" in
    "") review=none ;;
    yes*) review=yes ;;
    *) review=no ;;
  esac
  if on_target_exists docs/architecture.md; then arch=present; else arch=missing; fi
  if on_target_exists docs/design-system.md; then ds=present; else ds=missing; fi
  if [ "$ds" = missing ] && [ "$stories" = present ] && no_story_has_a_screen; then ds="not needed"; fi
  echo "Framing: scope $scope · stories $stories · stories review $review · architecture $arch · design system $ds"

  if [ -n "$scope_file" ] && [ "$scope" != approved ]; then next="$scope_cmd"
  elif [ "$stories" = missing ]; then next=/po-stories
  elif [ "$review" != yes ]; then next=/po-stories-review
  elif [ "$arch" = missing ]; then next=/po-architect
  elif [ "$ds" = missing ]; then next=/po-design-system
  else next="none — framing done"
  fi
  echo "Framing next: $next"
}

# --- Worktrees ------------------------------------------------------------------------------

# LANES: id -> path relative to top, for a worktree at <top>/<Worktree root><id> on story/<id>.
declare -A LANES=()
ORPHANS=()
lane_order=()

read_worktrees() {
  local prefix path="" branch="" line
  case "$wtroot" in /*) prefix="$wtroot" ;; *) prefix="$top/$wtroot" ;; esac
  classify() {
    [ -n "$path" ] || return 0
    local name rel shown
    [ "$path" = "$top" ] && return 0
    case "$path" in "$top"/*) rel="${path#"$top"/}" ;; *) rel="$path" ;; esac
    shown="${branch:-detached HEAD}"
    case "$path" in
      "$prefix"*)
        name="${path#"$prefix"}"
        if [ "$branch" = "story/$name" ]; then
          LANES["$name"]="$rel"; lane_order+=("$name")
        else
          ORPHANS+=("$rel: orphan worktree ($shown)")
        fi ;;
      *)
        case "$branch" in story/*) ORPHANS+=("$rel: orphan worktree ($shown)") ;; esac ;;
    esac
  }
  while IFS= read -r line; do
    case "$line" in
      "worktree "*) classify; path="${line#worktree }" branch="" ;;
      "branch refs/heads/"*) branch="${line#branch refs/heads/}" ;;
    esac
  done < <(git -C "$top" worktree list --porcelain 2>/dev/null)
  classify
}

# --- Shipped and ready ----------------------------------------------------------------------

declare -A SHIPPED=()
declare -A SHORT_SHIPPED=()

# A story is shipped under its full id, or under its bare number ("s01:") when no commit carries the id.
is_shipped() { [ -n "${SHIPPED[$1]-}" ] || [ -n "${SHORT_SHIPPED[${1%%-*}]-}" ]; }

read_shipped() {
  local refs=("$target") id
  git -C "$top" rev-parse --verify -q "refs/remotes/origin/$target" >/dev/null 2>&1 && refs+=("origin/$target")
  local subjects
  subjects="$(git -C "$top" log --format=%s "${refs[@]}" -- 2>/dev/null)"
  while IFS= read -r id; do
    SHIPPED["${id%:}"]=1
  done < <(grep -oE "^$id_re:" <<< "$subjects")
  while IFS= read -r id; do
    SHORT_SHIPPED["${id%:}"]=1
  done < <(grep -oE '^s[0-9]+:' <<< "$subjects")
}

ready_stories() {
  local id deps dep ready=() ok
  while read -r id deps; do
    [ -n "$id" ] || continue
    is_shipped "$id" && continue
    [ -n "${LANES[$id]-}" ] && continue
    ok=yes
    for dep in $deps; do is_shipped "$dep" || ok=no; done
    [ "$ok" = yes ] && ready+=("$id")
  done < <(on_target docs/stories.md | awk -v re="$id_re" '
    function flush() { if (id != "") print id, deps; id = ""; deps = "" }
    /^##+ / {
      flush()
      line = $0; sub(/^##+ /, "", line)
      if (match(line, "^" re)) id = substr(line, 1, RLENGTH)
      next
    }
    id != "" && /^- \*\*(Depends on|Dépend de)\*\*/ {
      v = $0; sub(/^[^:]*:/, "", v)
      while (match(v, re)) { deps = deps " " substr(v, RSTART, RLENGTH); v = substr(v, RSTART + RLENGTH) }
    }
    END { flush() }')
  if [ ${#ready[@]} -eq 0 ]; then
    echo "Ready stories: none"
  else
    local joined
    joined="$(printf '%s, ' "${ready[@]}")"
    echo "Ready stories: ${joined%, } (Owns not checked: /po-drive decides)"
  fi
}

lanes_in_flight() {
  if [ ${#lane_order[@]} -eq 0 ]; then echo "Lanes in flight: none"; return; fi
  local id out=()
  for id in "${lane_order[@]}"; do out+=("$id (${LANES[$id]})"); done
  local joined
  joined="$(printf '%s, ' "${out[@]}")"
  echo "Lanes in flight: ${joined%, }"
}

# --- Waiting for a human --------------------------------------------------------------------

waiting_for_a_human() {
  local lines=() id wt research plan qa review ship status next loop name
  for id in ${lane_order[@]+"${lane_order[@]}"}; do
    wt="$top/${LANES[$id]}"
    research="$wt/docs/research/$id.md" plan="$wt/docs/plans/$id.md"
    qa="$wt/docs/qa/$id/report.md" review="$wt/docs/reviews/$id.md"
    if [ -f "$research" ] && grep -qx 'Root cause: not found' "$research" 2>/dev/null \
       && ! { [ -f "$plan" ] && grep -qx 'validated: yes' "$plan" 2>/dev/null; }; then
      lines+=("$id: root cause not found (docs/research/$id.md)")
    fi
    if [ -f "$plan" ] && grep -qx 'Technical choice: waiting for a human' "$plan" 2>/dev/null \
       && ! grep -qx 'validated: yes' "$plan" 2>/dev/null; then
      lines+=("$id: technical choice waiting for a human (docs/plans/$id.md) → /po-plan $id")
    fi
    if [ "$(last_value 'QA status' "$qa")" = blocked ]; then
      lines+=("$id: QA blocked (docs/qa/$id/report.md)")
    fi
    ship="$(last_value 'Ship allowed' "$review")"
    if [ "$ship" = no ] && [ -n "$max_attempts" ]; then
      status="$(last_value 'Review status' "$review")"
      next="$(grep '^- Next action:' "$review" 2>/dev/null | tail -n 1)"
      loop="$(last_value 'Fix loop' "$review")"
      if ! { [ "$status" = blocked ] && [[ "$next" =~ /po-qa|QA\ evidence ]]; } \
         && [[ "$loop" =~ ^[0-9]+$ ]] && [[ "$max_attempts" =~ ^[0-9]+$ ]] && [ "$loop" -ge "$max_attempts" ]; then
        lines+=("$id: Max attempts reached (Fix loop: $loop, Max attempts: $max_attempts)")
      fi
    fi
    if [ "$ship" = yes ] && [ "$merge_mode" = pr ] && [ "$confirmation" = human ] \
       && ! is_shipped "$id" \
       && git -C "$top" rev-parse --verify -q "refs/remotes/origin/story/$id" >/dev/null 2>&1; then
      lines+=("$id: pull request presumed waiting for a human merge (story/$id pushed; the forge was not asked)")
    fi
  done
  lines+=(${ORPHANS[@]+"${ORPHANS[@]}"})
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
  if [ ${#lines[@]} -eq 0 ]; then
    echo "Waiting for a human: nothing"
  else
    echo "Waiting for a human:"
    printf -- '- %s\n' "${lines[@]}"
  fi
}

# --- Report ---------------------------------------------------------------------------------

if [ -z "$target" ]; then unreadable "Target branch"; else framing; fi
[ -n "$wtroot" ] || unreadable "Worktree root"
[ -n "$max_attempts" ] || unreadable "Max attempts"
[ -n "$merge_mode" ] || unreadable "Merge mode"
[ -n "$confirmation" ] || unreadable "Ship confirmation"

[ -n "$wtroot" ] && read_worktrees
if [ -n "$target" ] && [ -n "$wtroot" ]; then
  read_shipped
  ready_stories
fi
[ -n "$wtroot" ] && lanes_in_flight
[ -n "$wtroot" ] && waiting_for_a_human
exit 0
