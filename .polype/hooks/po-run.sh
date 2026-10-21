#!/usr/bin/env bash
# po-run — launches one check inside a story worktree and appends its row to the verification record.
#
#   po-run --story <id> --label <check> -- <command…>
#
# A single argument after `--` runs through `bash -c` and is recorded as given; several run as argv and are
# recorded joined by spaces. The command's output and exit code pass through untouched. The row written under
# `## Runs` of docs/verif/<id>.md holds the label, the command, the exit code, the tree of the working copy
# (`git add -A` + `git write-tree` on a copy of the index) and the UTC time — never the output.
# Exit 125 means po-run itself refused or failed, and then the command did not run or its row is missing.
set -euo pipefail

refuse() { echo "po-run: $*" >&2; exit 125; }

story="" label="" have_label=0
while [ $# -gt 0 ]; do
  case "$1" in
    --story) [ $# -ge 2 ] || refuse "--story needs a value"; story="$2"; shift 2 ;;
    --label) [ $# -ge 2 ] || refuse "--label needs a value"; label="$2"; have_label=1; shift 2 ;;
    --) shift; break ;;
    *) refuse "unexpected argument '$1' (usage: po-run --story <id> --label <check> -- <command…>)" ;;
  esac
  [ $# -gt 0 ] || refuse "missing '--' and the command to run"
done

[ -n "$story" ] || refuse "missing --story <id>"
[ "$have_label" -eq 1 ] || refuse "missing --label <check>"
[ $# -gt 0 ] || refuse "missing the command to run after '--'"
[[ "$story" =~ ^s[0-9]+-[a-z0-9][a-z0-9-]*$ ]] || refuse "'$story' is not a story id (s<number>-<slug>)"
[ -n "$label" ] || refuse "the label is empty"
case "$label" in *'|'* | *'`'* | *$'\n'*) refuse "the label may not hold '|', a backtick or a newline" ;; esac

if [ $# -eq 1 ]; then command_text="$1"; else command_text="$*"; fi
case "$command_text" in *$'\n'*) refuse "the command may not hold a newline" ;; esac

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || refuse "not inside a git work tree"
branch="$(git symbolic-ref --short -q HEAD || true)"
[ "$branch" = "story/$story" ] || refuse "HEAD is '${branch:-detached}', not story/$story; run checks from the story worktree"

top="$(git rev-parse --show-toplevel)" || refuse "cannot find the top of the work tree"
index="$(git rev-parse --path-format=absolute --git-path index)" || refuse "cannot locate the git index"
scratch="$(mktemp -d)" || refuse "cannot create a temporary directory"
trap 'rm -rf "$scratch"' EXIT
# A copy of the index, so the tree covers untracked files without staging anything the user did not choose.
if [ -f "$index" ]; then cp "$index" "$scratch/index" || refuse "cannot copy the git index"; fi
tree="$(GIT_INDEX_FILE="$scratch/index" git -C "$top" add -A >/dev/null \
  && GIT_INDEX_FILE="$scratch/index" git -C "$top" write-tree)" || refuse "cannot compute the tree of the working copy"
mkdir -p "$top/docs/verif" || refuse "cannot create docs/verif"
record="$top/docs/verif/$story.md"

set +e
if [ $# -eq 1 ]; then bash -c "$1"; else "$@"; fi
code=$?
set -e

append() {
  if ! grep -q '^## Runs$' "$record" 2>/dev/null; then
    if [ -s "$record" ] && [ -n "$(tail -c 1 "$record")" ]; then echo; fi
    printf '## Runs\n\n| Check | Command | Exit | Tree | Time (UTC) |\n| --- | --- | --- | --- | --- |\n'
  fi
  printf '| %s | `%s` | %s | %s | %s |\n' "$label" "$command_text" "$code" "$tree" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
append >> "$record" || refuse "the check exited $code but its row could not be appended to $record"
exit "$code"
