#!/usr/bin/env bash
# po-intake — runs a scheduled check from the repository root and files its failure in `Issue tracker`.
#
#   po-intake --label <name> [--sensitive] -- '<command>'
#
# The argument after `--` runs through `bash -c`; its output and exit code pass through, and po-intake's own
# messages go to stderr. A failing check files one issue titled `<name>: <fingerprint>`, scrubbed by
# `po-gate redact` and of the values of environment variables named TOKEN, KEY, SECRET or PASSWORD; an open issue
# with that title gets a comment instead. A --sensitive failure is never filed: its raw report stays in a private
# temporary folder whose path is printed. Exit 125: refused before running the command.
set -euo pipefail

say() { echo "po-intake: $*" >&2; }
refuse() { say "$*"; exit 125; }

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/po-gate.sh"
LABEL_NAME=polype-intake

label="" have_label=0 sensitive=0
while [ $# -gt 0 ]; do
  case "$1" in
    --label) [ $# -ge 2 ] || refuse "--label needs a value"; label="$2"; have_label=1; shift 2 ;;
    --sensitive) sensitive=1; shift ;;
    --) shift; break ;;
    *) refuse "unexpected argument '$1' (usage: po-intake --label <name> [--sensitive] -- '<command>')" ;;
  esac
  [ $# -gt 0 ] || refuse "missing '--' and the command to run"
done

[ "$have_label" -eq 1 ] || refuse "missing --label <name>"
[ -n "$label" ] || refuse "the label is empty"
case "$label" in *$'\n'*) refuse "the label may not hold a newline" ;; esac
[ $# -eq 1 ] || refuse "expected exactly one command argument after '--', got $#"
command_text="$1"
[ -n "$command_text" ] || refuse "the command is empty"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || refuse "not inside a git work tree"
top="$(git rev-parse --show-toplevel)" || refuse "cannot find the top of the work tree"
cd "$top" || refuse "cannot enter $top"

work="$(mktemp -d)" || refuse "cannot create a temporary directory"
trap 'rm -rf "$work"' EXIT
mkfifo "$work/out.fifo" "$work/err.fifo" || refuse "cannot create the capture pipes"
: > "$work/capture"

# Both streams append to one capture so the fingerprint is found in output order, each still going to its own stream.
tee -a "$work/capture" < "$work/out.fifo" &
tee_out=$!
tee -a "$work/capture" < "$work/err.fifo" >&2 &
tee_err=$!
set +e
bash -c "$command_text" > "$work/out.fifo" 2> "$work/err.fifo"
code=$?
wait "$tee_out" "$tee_err"
set -e

[ "$code" -eq 0 ] && exit 0

sha="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

if [ "$sensitive" -eq 1 ]; then
  report_dir="$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/po-intake.XXXXXX")" \
    || { say "check '$label' failed (exit $code); it is sensitive and its report could not be written"; exit "$code"; }
  report="$report_dir/report.md"
  (
    umask 077
    {
      printf '# po-intake report\n\nCheck: %s\nCommand: %s\nCommit: %s\nExit code: %s\n\n````\n' \
        "$label" "$command_text" "$sha" "$code"
      cat "$work/capture"
      [ ! -s "$work/capture" ] || [ -z "$(tail -c 1 "$work/capture")" ] || echo
      printf '````\n'
    } > "$report"
  ) && chmod 600 "$report" \
    || { say "check '$label' failed (exit $code); it is sensitive and its report could not be written"; exit "$code"; }
  say "check '$label' failed (exit $code); not filed, since it is sensitive: its raw report is for the person, at $report"
  exit "$code"
fi

# Copies $1 to $2 with every secret po-gate knows and every secret-named environment value replaced by [redacted].
scrub() {
  bash "$GATE" redact "$1" > "$work/scrub.tmp" || return 1
  awk '
    BEGIN {
      for (k in ENVIRON) {
        if (toupper(k) !~ /TOKEN|KEY|SECRET|PASSWORD/) continue
        m = split(ENVIRON[k], parts, "\n")
        for (j = 1; j <= m; j++) if (length(parts[j]) >= 8) vals[++nv] = parts[j]
      }
    }
    {
      line = $0
      for (v = 1; v <= nv; v++) {
        out = ""; rest = line
        while ((p = index(rest, vals[v])) > 0) {
          out = out substr(rest, 1, p - 1) "[redacted]"; rest = substr(rest, p + length(vals[v]))
        }
        line = out rest
      }
      print line
    }
  ' "$work/scrub.tmp" > "$2"
}

if ! scrub "$work/capture" "$work/scrubbed"; then
  say "check '$label' failed (exit $code), but its output could not be scrubbed of secrets: nothing filed"
  exit "$code"
fi

awk -v code="$code" '
  function trim(s) { sub(/[ \t\r]+$/, "", s); return s }
  {
    s = trim($0); f = ""
    if (s ~ /^not ok [0-9]+ /) { f = s; sub(/^not ok [0-9]+ /, "", f) }
    else if (s ~ /^FAILED /) { f = substr(s, 8); sub(/ - .*/, "", f) }
    else if (s ~ /^test .+ \.\.\. FAILED$/) f = substr(s, 6, length(s) - 16)
    else if (s ~ /^  FAIL  /) f = substr(s, 9)
    f = trim(f)
    if (f != "") { printf "%s", f; found = 1; exit }
  }
  END { if (!found) printf "%s", code }
' "$work/scrubbed" > "$work/fingerprint"

d="$work/issue"
mkdir "$d"
{ printf '%s: ' "$label"; cat "$work/fingerprint"; } > "$d/title.raw"
{
  printf 'Check: %s\nCommand: %s\nCommit: %s\nExit code: %s\n\n````\n' "$label" "$command_text" "$sha" "$code"
  tail -n 200 "$work/scrubbed"
  printf '````\n'
} > "$d/body.raw"
printf 'Failed again.\n\nCommit: %s\nDate: %s\nExit code: %s\n' "$sha" "$(date -u +%FT%TZ)" "$code" > "$d/comment"
# The label and the command are the caller's, and may hold a secret too.
if ! scrub "$d/title.raw" "$d/title.lines" || ! scrub "$d/body.raw" "$d/body"; then
  say "check '$label' failed (exit $code), but its report could not be scrubbed of secrets: nothing filed"
  exit "$code"
fi
awk '{ sub(/[ \t\r]+$/, ""); printf "%s", $0; exit }' "$d/title.lines" \
  | LC_ALL=C.UTF-8 sed -E 's/^(.{80}).*/\1/; s/ +$//' > "$d/title"

report() { { cat "$d/title"; echo; echo; cat "$d/body"; } >&2; }
not_filed() { say "$* — nothing filed; the report follows"; report; }

file_github() {
  local url path list number
  url="$(git remote get-url origin 2>/dev/null || true)"
  case "$url" in
    https://github.com/*) path="${url#https://github.com/}" ;;
    git@github.com:*) path="${url#git@github.com:}" ;;
    ssh://git@github.com/*) path="${url#ssh://git@github.com/}" ;;
    *) not_filed "origin is not on github.com"; return 0 ;;
  esac
  path="${path%/}"; path="${path%.git}"
  [[ "$path" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { not_filed "cannot read owner/repo from origin"; return 0; }
  local repo="github.com/$path"
  command -v gh >/dev/null 2>&1 || { not_filed "gh is not installed"; return 0; }
  gh auth status --hostname github.com >/dev/null 2>&1 || { not_filed "gh is not logged in to github.com"; return 0; }
  list="$d/open"
  if ! gh issue list --repo "$repo" --state open --limit 1000 --json number,title \
      --jq '.[] | "\(.number)\t\(.title)"' > "$list" 2> "$d/list.err"; then
    cat "$d/list.err" >&2
    not_filed "the listing of open issues failed, so a duplicate cannot be ruled out"; return 0
  fi
  if [ "$(wc -l < "$list" | tr -d ' ')" -ge 1000 ]; then
    not_filed "$repo has 1000 open issues or more, too many to rule out a duplicate"; return 0
  fi
  number="$(awk 'NR == FNR { t = $0; next }
    { p = index($0, "\t"); if (p > 0 && substr($0, p + 1) == t) { print substr($0, 1, p - 1); exit } }' "$d/title" "$list")"
  if [ -n "$number" ]; then
    [[ "$number" =~ ^[0-9]+$ ]] || { not_filed "the listing gave an unreadable issue number"; return 0; }
    if gh issue comment "$number" --repo "$repo" --body-file "$d/comment" >&2; then
      say "issue #$number is already open with this title: commented on it"
    else
      not_filed "commenting on the open issue #$number failed"
    fi
    return 0
  fi
  gh label list --repo "$repo" --limit 1000 --json name --jq '.[].name' > "$d/labels" 2>/dev/null || : > "$d/labels"
  if ! grep -qx "$LABEL_NAME" "$d/labels"; then
    gh label create "$LABEL_NAME" --repo "$repo" --description "Failure of a scheduled check (po-intake)" >&2 \
      || say "could not create the label $LABEL_NAME"
  fi
  if gh issue create --repo "$repo" --title "$(cat "$d/title")" --body-file "$d/body" --label "$LABEL_NAME" >&2; then
    say "filed the failure of '$label' on $repo"
  else
    not_filed "gh issue create failed"
  fi
}

file_taskwarrior() {
  local url name common uuid uuids desc found=""
  command -v task >/dev/null 2>&1 || { not_filed "task is not installed"; return 0; }
  url="$(git remote get-url origin 2>/dev/null || true)"
  if [ -n "$url" ]; then
    name="${url%/}"; name="${name##*/}"; name="${name##*:}"; name="${name%.git}"
  else
    common="$(git rev-parse --path-format=absolute --git-common-dir)"
    name="$(basename "$(dirname "$common")")"
  fi
  [ -n "$name" ] || { not_filed "cannot name the taskwarrior project"; return 0; }
  if ! uuids="$(task "project:$name" +issue status:pending _uuids < /dev/null 2> "$d/list.err")"; then
    cat "$d/list.err" >&2
    not_filed "the listing of pending tasks failed, so a duplicate cannot be ruled out"; return 0
  fi
  while IFS= read -r uuid; do
    [[ "$uuid" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || continue
    desc="$(task _get "$uuid.description" < /dev/null 2>/dev/null)" || continue
    [ "$desc" = "$(cat "$d/title")" ] && { found="$uuid"; break; }
  done <<< "$uuids"
  if [ -n "$found" ]; then
    if task "$found" annotate -- "$(cat "$d/comment")" < /dev/null >&2; then
      say "task $found is already pending with this title: annotated it"
    else
      not_filed "annotating the pending task $found failed"
    fi
    return 0
  fi
  if ! task rc.verbose=new-uuid add "project:$name" +issue "+$LABEL_NAME" -- "$(cat "$d/title")" \
      < /dev/null > "$d/add.out" 2>&1; then
    cat "$d/add.out" >&2
    not_filed "task add failed"; return 0
  fi
  uuid="$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$d/add.out" | head -n 1 || true)"
  [ -n "$uuid" ] || { say "task add printed no uuid: the task holds the title but not the report"; report; return 0; }
  task "$uuid" annotate -- "$(cat "$d/body")" < /dev/null >&2 \
    || { say "the task $uuid was created but annotating it with the report failed"; report; return 0; }
  say "filed the failure of '$label' as task $uuid in project:$name"
}

tracker="$(sed -n 's/^Issue tracker:[[:space:]]*\(.*[^[:space:]]\)[[:space:]]*$/\1/p' "$top/AGENTS.local.md" 2>/dev/null \
  | head -n 1 || true)"
case "$tracker" in
  github) file_github ;;
  taskwarrior) file_taskwarrior ;;
  —) say "check '$label' failed (exit $code); Issue tracker is —, so nothing is filed: the report follows"; report ;;
  '') not_filed "the setting Issue tracker is missing from AGENTS.local.md" ;;
  *) not_filed "the setting Issue tracker holds '$tracker', not github, taskwarrior or —" ;;
esac
exit "$code"
