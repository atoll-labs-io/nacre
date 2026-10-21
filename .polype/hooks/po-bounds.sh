#!/usr/bin/env bash
# po-bounds — a Claude Code PreToolUse hook that keeps a subagent inside its story's bounds.
#
#   po-bounds.sh implementer   reads the hook input (JSON) on stdin.
#                              Write/Edit: the path must lie in docs/ or in the Owns of the story
#                              whose linked story/<id> worktree holds it, read in docs/stories.md at
#                              the story's fork point (ADR-0038); entries follow the syntax of the
#                              stories template, anything else is refused.
#                              Bash: no git switch, stash, push, worktree add or update-ref, no git
#                              branch -f/--force/-D/-M/-C, and no commit, reset, merge, rebase,
#                              cherry-pick, revert, am or pull outside a story/<id> worktree. git
#                              checkout only in a throwaway repo of the temp dir (as for the reviewer),
#                              where every path the call names and each redirection target must stay
#                              under the temp dir too (ADR-0072). In that repo --git-dir, --work-tree,
#                              a -c or --config-env setting core.worktree, and a word starting with
#                              GIT_DIR=, GIT_WORK_TREE=, GIT_CONFIG_PARAMETERS= or GIT_CONFIG_COUNT=
#                              are refused, as for the reviewer.
#   po-bounds.sh qa            Write: the path must lie in docs/qa/<id>/ of the story whose linked
#                              story/<id> worktree holds it; the rest of docs/ is refused too.
#                              Bash: every git call must use a reading verb of an allowlist
#                              (ADR-0026); an unknown verb, or none, is refused, and so are any
#                              --output and a symbolic-ref given a target or a writing option.
#                              Edit is refused.
#   po-bounds.sh reviewer      two zones (ADR-0047, ADR-0051). A story worktree (as for the implementer,
#                              its story holding an Owns line at the fork point): Write/Edit anywhere
#                              but .git; git reading verbs of the qa allowlist only, plus git checkout
#                              -- <path> and git restore [-q|-W|--worktree] [--] <path>. The temp dir,
#                              physical ${TMPDIR:-/tmp}, refused when it is / or missing: Write/Edit
#                              anywhere under it, git any verb but push, in no repository or in one
#                              whose common git dir and top level lie under it too, and every path the
#                              call names after its verb (a word, --opt=value, -o<value>) resolving
#                              under it as well; so does each redirection target of that call, read
#                              from the shell's dir, unless it is /dev/null, /dev/stdout,
#                              /dev/stderr, /dev/fd/1 or /dev/fd/2 (ADR-0053). A git call runs where the cds and every chained -C
#                              lead; a word holding a substitution, $ or a leading ~, a bare cd and
#                              cd -<x> make that directory unknown, and git there is refused.
#                              Everywhere: git push and send-pack, --git-dir, --work-tree, a -c or
#                              --config-env setting core.worktree in any case, and an unquoted or
#                              quoted word starting with GIT_DIR=, GIT_WORK_TREE=,
#                              GIT_CONFIG_PARAMETERS= or GIT_CONFIG_COUNT= are refused, and so is git
#                              outside both zones.
#
# Bash commands are read the way bash splits them (ADR-0050): text inside quotes or in a
# here-document body is never taken for a git call, but the substitutions bash would run there are,
# and so are a quoted command word (env "git", even past a wrapper's option: env -u X "git"), the
# quoted arguments of sh -c, eval or watch, and a here-document a shell reads. An unquoted one is
# rendered as bash renders it (\$, \`, \\) before that reading, and its outer substitutions are
# read too. A shell fed by a pipe or handed a substitution, nested backquotes and any command the
# lexer cannot read are refused. A redirection, its fd number or {name} included, is not a word of the command.
#
# The hook guards against an agent's mistakes; it is no barrier against a deliberate bypass, and
# the known ones are listed and accepted in ADR-0052.
#
# Exit 0 allows the call, exit 2 refuses it with the reason on stderr. Claude Code lets any other
# code through, so every failure ends in a refusal. Reads no setting; needs jq (ADR-0024).
set -uo pipefail

# Set by git_env_word: the variable name of the last word it recognised.
ENV_WORD=""

# The lexer marks a substitution with \036; no refusal may print that byte (ADR-0072).
deny() { local msg="$*" m=$'\036'; echo "po-bounds: ${msg//$m/<substitution>}" >&2; exit 2; }

# An unbound variable or any stray status must not become a non-blocking error.
trap 'rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ] || { echo "po-bounds: internal failure ($rc)" >&2; exit 2; }' EXIT

# Sets TOP and STORY from an existing directory inside a linked story/<id> worktree, or returns 1.
try_story_of_dir() {
  local dir="$1" gitdir common branch
  TOP="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || return 1
  gitdir="$(git -C "$dir" rev-parse --absolute-git-dir 2>/dev/null)" || return 1
  common="$(git -C "$dir" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || return 1
  [ "$gitdir" != "$common" ] || return 1
  branch="$(git -C "$dir" symbolic-ref --short -q HEAD 2>/dev/null)" || return 1
  case "$branch" in story/?*) ;; *) return 1 ;; esac
  STORY="${branch#story/}"
}

# Sets TOP and STORY from an existing directory, or denies with "$1".
story_of_dir() { try_story_of_dir "$2" || deny "$1"; }

# Sets TMP_ROOT to the physical ${TMPDIR:-/tmp}, or empty when it is relative, missing or /.
temp_root() {
  local t="${TMPDIR:-/tmp}"
  TMP_ROOT=""
  case "$t" in /*) ;; *) return 0 ;; esac
  TMP_ROOT="$(cd -P "$t" 2>/dev/null && pwd -P)" || TMP_ROOT=""
  [ "$TMP_ROOT" != / ] || TMP_ROOT=""
}

under_temp() { [ -n "$TMP_ROOT" ] && { [ "$1" = "$TMP_ROOT" ] || [[ "$1" == "$TMP_ROOT"/* ]]; }; }

# Whether existing directory $1 lies under TMP_ROOT, in no repository or in one whose common git dir
# and top level lie there too: a linked worktree of a real repository placed in the temp dir does not.
in_temp_zone() {
  local phys common top
  phys="$(cd -P "$1" 2>/dev/null && pwd -P)" || return 1
  under_temp "$phys" || return 1
  if common="$(git -C "$phys" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; then
    common="$(cd -P "$common" 2>/dev/null && pwd -P)" || return 1
    under_temp "$common" || return 1
  fi
  if top="$(git -C "$phys" rev-parse --show-toplevel 2>/dev/null)"; then
    top="$(cd -P "$top" 2>/dev/null && pwd -P)" || return 1
    under_temp "$top" || return 1
  fi
  return 0
}

# Sets RESOLVED (physical absolute path, the target may not exist yet) and NEAREST (its deepest
# existing directory). Not realpath -m: macOS lacks it.
resolve_path() {
  local path="$1" dir tail="" base phys
  case "$path" in /*) ;; *) deny "not an absolute path: $path" ;; esac
  [ ! -L "$path" ] || deny "$path is a symbolic link"
  dir="$path"
  while [ ! -d "$dir" ]; do
    base="${dir##*/}"
    case "$base" in .|..) deny "$path holds a . or .. component that does not exist yet" ;; esac
    [ -z "$base" ] || tail="/$base$tail"
    dir="$(dirname "$dir")"
  done
  phys="$(cd -P "$dir" 2>/dev/null && pwd -P)" || deny "cannot resolve $path"
  NEAREST="$phys"
  RESOLVED="${phys%/}$tail"
  [ -z "$tail" ] || [ ! -L "$RESOLVED" ] || deny "$path is a symbolic link"
}

# Sets BASE and BASE_FROM: the commit story/<id> in worktree $1 forked from, i.e. its merge base with
# the main worktree's branch and that branch's upstream (ADR-0038); or denies.
story_base() {
  local list first up
  local -a refs=()
  list="$(git -C "$1" worktree list --porcelain 2>/dev/null)" || list=""
  first="$(awk '
    NF == 0 { exit }
    $1 == "detached" || $1 == "bare" { print $1; exit }
    /^branch refs\/heads\// { sub(/^branch refs\/heads\//, ""); print "branch " $0; exit }
  ' <<< "$list")"
  case "$first" in
    "branch "?*) BASE_FROM="${first#branch }" ;;
    detached|bare) deny "cannot find the branch story $STORY started from: the main worktree is $first" ;;
    *) deny "cannot find the branch story $STORY started from: the main worktree is on no branch" ;;
  esac
  refs=("refs/heads/$BASE_FROM")
  # Not refs/heads/<b>@{upstream}: git does not resolve that form.
  up="$(git -C "$1" for-each-ref --format='%(upstream)' "refs/heads/$BASE_FROM" 2>/dev/null)" || up=""
  if [ -n "$up" ] && git -C "$1" rev-parse --verify -q "$up^{commit}" >/dev/null 2>&1; then
    refs+=("$up")
  fi
  BASE="$(git -C "$1" merge-base HEAD "${refs[@]}" 2>/dev/null)" && [ -n "$BASE" ] \
    || deny "story/$STORY shares no commit with $BASE_FROM, the branch of the main worktree"
}

# Sets OWNS_LINE to the Owns line of story $2 in docs/stories.md as committed at the story's fork
# point, so that a commit of the story cannot widen its own bounds, and OWNS_AT to that place; or denies.
owns_line() {
  local stories line short
  story_base "$1"
  short="$(git -C "$1" rev-parse --short "$BASE" 2>/dev/null)" || short="$BASE"
  OWNS_AT="at $short (where story/$2 started from $BASE_FROM)"
  stories="$(git -C "$1" show "$BASE:docs/stories.md" 2>/dev/null)" || deny "no committed docs/stories.md $OWNS_AT"
  line="$(awk -v id="$2" '
    /^#/ {
      if (on) exit
      h = $0
      if (h ~ /^#+ /) { sub(/^#+ /, "", h); if (h == id || index(h, id " ") == 1) { on = 1; found = 1 } }
      next
    }
    on && /^[-*] \*\*Owns\*\*[[:space:]]*:/ { print "OWNS " $0; exit }
    END { if (found) print "FOUND" }
  ' <<< "$stories")"
  case "$line" in
    "OWNS "*) ;;
    FOUND) deny "story $2 has no **Owns** line in docs/stories.md $OWNS_AT" ;;
    *) deny "story $2 is not in docs/stories.md $OWNS_AT" ;;
  esac
  line="${line%$'\n'FOUND}"
  OWNS_LINE="${line#OWNS }"
}

check_write() {
  local path="$1" line rel entry allowed=no
  resolve_path "$path"
  story_of_dir "$path is not inside a story worktree (a linked worktree on a story/<id> branch)" "$NEAREST"
  case "$RESOLVED" in "$TOP"/*) ;; *) deny "$path is not inside a file of worktree $TOP" ;; esac
  rel="${RESOLVED#"$TOP"/}"
  case "$rel" in docs/*) exit 0 ;; esac
  owns_line "$TOP" "$STORY"
  line="$OWNS_LINE"
  parse_owns "$line"
  [ "${#OWNS[@]}" -gt 0 ] || deny "the **Owns** line of $STORY lists no path: $line"
  # Every entry is checked before any match: one unreadable entry refuses the whole line.
  for entry in "${OWNS[@]}"; do check_entry "$entry" "$line"; done
  for entry in "${OWNS[@]}"; do
    if entry_matches "$entry" "$rel"; then allowed=yes; break; fi
  done
  [ "$allowed" = yes ] || deny "$RESOLVED is outside the Owns of $STORY read $OWNS_AT — $line"
  exit 0
}

unreadable() { deny "the **Owns** line of $STORY holds an entry po-bounds cannot read: $1 — $2"; }

# Sets OWNS to the backticked entries of Owns line $1: entries separated by commas, nothing else.
parse_owns() {
  local line="$1" rest entry
  OWNS=()
  rest="${line#*'**Owns**'}"
  rest="${rest#"${rest%%[![:space:]]*}"}"
  rest="${rest#:}"
  rest="${rest#"${rest%%[![:space:]]*}"}"
  [ -n "$rest" ] || return 0
  while :; do
    case "$rest" in '`'*'`'*) ;; *) unreadable "$rest" "$line" ;; esac
    rest="${rest#\`}"
    entry="${rest%%\`*}"
    rest="${rest#*\`}"
    OWNS+=("$entry")
    rest="${rest#"${rest%%[![:space:]]*}"}"
    [ -n "$rest" ] || return 0
    case "$rest" in ,*) rest="${rest#,}" ;; *) unreadable "$rest" "$line" ;; esac
    rest="${rest#"${rest%%[![:space:]]*}"}"
    [ -n "$rest" ] || unreadable "a comma followed by no entry" "$line"
  done
}

# Refuses entry $1 unless it is a relative path, a folder ending in /, or a * / ** glob (ADR-0038).
check_entry() {
  local e="$1" line="$2" s seg
  case "$e" in
    '') unreadable '`` (empty)' "$line" ;;
    /*) unreadable "\`$e\` (absolute)" "$line" ;;
    *[[:space:]]*|*'?'*|*'['*|*']'*|*'{'*|*'}'*) unreadable "\`$e\` (whitespace, ?, [, ], { or })" "$line" ;;
  esac
  s="${e%/}/"
  while [ -n "$s" ]; do
    seg="${s%%/*}"
    s="${s#*/}"
    case "$seg" in
      ''|.|..) unreadable "\`$e\` (an empty, . or .. segment)" "$line" ;;
      '**') ;;
      *'**'*) unreadable "\`$e\` (** must be a whole segment)" "$line" ;;
    esac
  done
}

# Whether relative path $2 lies in entry $1. A glob becomes an anchored ERE built segment by segment.
entry_matches() {
  local e="$1" rel="$2" body s seg re="" i c
  case "$e" in
    *'*'*) ;;
    */) [ "$rel" = "${e%/}" ] || [[ "$rel" == "${e%/}"/* ]]; return ;;
    *) [ "$rel" = "$e" ]; return ;;
  esac
  body="${e%/}"
  s="$body/"
  while [ -n "$s" ]; do
    seg="${s%%/*}"
    s="${s#*/}"
    if [ "$seg" = '**' ]; then
      if [ -n "$s" ]; then re+='([^/]+/)*'; else re+='.*'; fi
      continue
    fi
    for ((i = 0; i < ${#seg}; i++)); do
      c="${seg:i:1}"
      case "$c" in
        '*') re+='[^/]*' ;;
        .|+|'('|')'|'|'|'^'|'$'|'\') re+="\\$c" ;;
        *) re+="$c" ;;
      esac
    done
    [ -z "$s" ] || re+='/'
  done
  [ "$body" = "$e" ] || re+='/.+'
  re="^$re\$"
  [[ $rel =~ $re ]]
}

# Not check_write: its docs/ shortcut belongs to the implementer.
check_write_qa() {
  local path="$1" rel
  resolve_path "$path"
  story_of_dir "$path is not inside a story worktree (a linked worktree on a story/<id> branch)" "$NEAREST"
  case "$RESOLVED" in "$TOP"/*) ;; *) deny "$path is not inside a file of worktree $TOP" ;; esac
  rel="${RESOLVED#"$TOP"/}"
  case "$rel" in "docs/qa/$STORY/"?*) exit 0 ;; esac
  deny "$RESOLVED is outside docs/qa/$STORY/, the only folder mode qa writes to"
}

# The reviewer is not bound to Owns: the bite proof may disable a rule in any file of the worktree.
check_write_reviewer() {
  local path="$1" rel
  resolve_path "$path"
  if try_story_of_dir "$NEAREST"; then
    case "$RESOLVED" in "$TOP"/*) ;; *) deny "$path is not inside a file of worktree $TOP" ;; esac
    rel="${RESOLVED#"$TOP"/}"
    case "$rel" in .git|.git/*) deny "$path lies in the .git of worktree $TOP" ;; esac
    owns_line "$TOP" "$STORY"
    exit 0
  fi
  temp_root
  if under_temp "$RESOLVED" && in_temp_zone "$NEAREST"; then exit 0; fi
  deny "$path is outside a story worktree and outside the temp dir (${TMP_ROOT:-no usable temp dir})"
}

join_dir() { case "$2" in /*) printf '%s' "$2" ;; *) printf '%s' "${1%/}/$2" ;; esac; }

readable() { local m=$'\036'; printf '%s' "${1//$m/<substitution>}"; }

# Prints the directory reached from $1 by cd $2 or git -C $2; empty means unknown. A word bash
# would expand (substitution, $, ~) is unknown, and so is a relative step from an unknown dir.
step_dir() {
  case "$2" in *$'\036'*|*'$'*|'~'*) return 0 ;; /*) printf '%s' "$2"; return 0 ;; esac
  [ -n "$1" ] || return 0
  join_dir "$1" "$2"
  return 0
}

QA_GIT_VERBS=" status diff log show rev-parse ls-files ls-tree cat-file merge-base grep blame describe symbolic-ref shortlog "

# Prints the simple commands of the Bash command read on stdin, one per line, words separated by
# \037, each word prefixed with c (the command word), q (some part quoted), u (neither) or r (the
# target of a redirection; the operator and its fd number are dropped); a word that held a $(…),
# `…`, $((…)), <(…) or >(…) carries a \036 byte where the substitution stood; a line !<reason> means
# the command cannot be read (ADR-0050). POSIX awk only: BWK awk and mawk must run it too.
lex_command() {
  awk '
    function fail(r) { if (!failed) print "!" r; failed = 1 }
    function push(type) {
      sp++; t[sp] = type; pd[sp] = 0; inw[sp] = 0; wv[sp] = ""; wq[sp] = 0; ws[sp] = 0
      nw[sp] = 0; piped[sp] = 0; cid[sp] = ++cseq; rd[sp] = 0
    }
    # A double quote writes into the word of the command around it.
    function owner() { return t[sp] == "dq" ? sp - 1 : sp }
    function app(ch,   f) { if (t[sp] == "hd") return; f = owner(); wv[f] = wv[f] ch; inw[f] = 1 }
    function quoted(   f) { f = owner(); wq[f] = 1; inw[f] = 1 }
    function opensub(type,   f) { if (t[sp] != "hd") { f = owner(); inw[f] = 1; ws[f] = 1; wv[f] = wv[f] SM } push(type) }
    function inbq(   x) { for (x = sp; x >= 1; x--) if (t[x] == "bq") return 1; return 0 }
    # rd: 1 after a redirection to a file, 2 after <& or >&, whose fd number or - is no word.
    function endword(f) {
      if (!inw[f]) return
      if (rd[f] == 2 && !wq[f] && !ws[f] && wv[f] ~ /^([0-9]+-?|-)$/) {
        wv[f] = ""; inw[f] = 0; rd[f] = 0; return
      }
      nw[f]++; W[f, nw[f]] = wv[f]; Q[f, nw[f]] = wq[f]; S[f, nw[f]] = ws[f]; R[f, nw[f]] = (rd[f] > 0)
      wv[f] = ""; wq[f] = 0; ws[f] = 0; inw[f] = 0; rd[f] = 0
    }
    # Fills CP with the positions that may name the command, past assignments, options, counts and
    # wrappers (env, time…), and returns the first. The word after an option of a wrapper may be
    # the value of that option or the command: both readings count (ADR-0050).
    function cmdpos(f,   k, v, b, wr, po, first) {
      split("", CP); wr = 0; po = 0; first = 0
      for (k = 1; k <= nw[f]; k++) {
        if (R[f, k]) continue
        v = W[f, k]; b = v; sub(/.*\//, "", b)
        if (v ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { po = 0; continue }
        if (v ~ /^-/ || v ~ /^[0-9][0-9.]*[smhd]?$/ || (b in WRAP)) {
          if (b in WRAP) wr = 1
          po = wr && v ~ /^-/ && v !~ /=/
          continue
        }
        CP[k] = 1; if (!first) first = k
        if (po) { po = 0; continue }
        return first
      }
      return first
    }
    # Words are typed c (the command word), q (some part quoted) or u. An interpreter (sh -c, eval,
    # watch) gets its quoted words read as commands; a shell gets its here-documents read as commands,
    # and is refused when it reads a pipe or is handed a substitution bash would expand.
    # code: 1 the command feeds a pipe, 2 a newline or a parenthesis, 0 any other separator.
    function endcmd(f, code,   k, cp, line, v, b, ip, si, hc, sb, x) {
      endword(f)
      if (nw[f] > 0) {
        cp = cmdpos(f); line = ""; ip = 0; si = 0; hc = 0; sb = 0
        for (k = 1; k <= nw[f]; k++) {
          v = W[f, k]; gsub(/\n/, " ", v)
          line = line (k > 1 ? US : "") (R[f, k] ? "r" : (k in CP) ? "c" : Q[f, k] ? "q" : "u") v
          b = W[f, k]; sub(/.*\//, "", b)
          if (!R[f, k] && (!Q[f, k] || (k in CP)) && (b in INTERP)) ip = 1
          if (!R[f, k] && (k in CP) && (b in SHELLS)) si = 1
          if (si && k > cp && W[f, k] ~ /^-[A-Za-z]*c[A-Za-z]*$/) hc = 1
          if (S[f, k]) sb = 1
        }
        print line
        if (ip && sb) fail("a substitution handed to an interpreter")
        if (si && piped[f] && !hc) fail("a shell reading its commands from a pipe")
        if (ip) for (k = 1; k <= nw[f]; k++) if (Q[f, k] && !R[f, k]) work[++wn] = W[f, k]
        if (si) for (x = 1; x <= qn; x++) if (qc[x] == cid[f]) qi[x] = 1
      }
      if (!(nw[f] == 0 && code == 2)) piped[f] = (code == 1)
      nw[f] = 0; cid[f] = ++cseq; rd[f] = 0
    }
    # Reads the delimiter after << or <<- and queues the here-document.
    function opener(tabs,   d, q, c, j) {
      if (hdon) { fail("a here-document inside a here-document"); return }
      while (substr(s, i, 1) == " " || substr(s, i, 1) == "\t") i++
      d = ""; q = 0
      while (i <= n) {
        c = substr(s, i, 1)
        if (index(" \t\n;&|()<>", c)) break
        if (c == SQ) {
          for (j = i + 1; j <= n && substr(s, j, 1) != SQ; j++) ;
          if (j > n) { fail("unterminated quote"); return }
          d = d substr(s, i + 1, j - i - 1); q = 1; i = j + 1
        } else if (c == "\"") {
          for (j = i + 1; j <= n; j++) {
            c = substr(s, j, 1)
            if (c == "\\") { j++; d = d substr(s, j, 1); continue }
            if (c == "\"") break
            d = d c
          }
          if (j > n) { fail("unterminated quote"); return }
          q = 1; i = j + 1
        } else if (c == "\\") {
          d = d substr(s, i + 1, 1); q = 1; i += 2
        } else {
          d = d c; i++
        }
      }
      if (d == "" && !q) { fail("a here-document without a delimiter"); return }
      qn++; qd[qn] = d; qq[qn] = q; qt[qn] = tabs; qc[qn] = cid[sp]; qi[qn] = 0
    }
    # At the start of a line, skips the queued here-document bodies. An unquoted delimiter hands
    # its body to an hd frame, which reads only the substitutions bash would run.
    # A body a shell reads on its stdin is queued, rendered as bash renders it when the delimiter is
    # unquoted, to be read as commands; an unquoted one also goes through the hd frame.
    function heredocs(   k, m, ln, body) {
      while (qh <= qn) {
        if (!(i in lineat)) { fail("a here-document after a broken line"); return }
        k = lineat[i]; body = ""
        for (m = k; m <= nlines; m++) {
          ln = L[m]
          if (qt[qh]) sub(/^\t+/, "", ln)
          if (ln == qd[qh]) break
          body = body ln "\n"
        }
        if (m > nlines) { fail("unterminated here-document (no " qd[qh] " line)"); return }
        if (qi[qh]) work[++wn] = qq[qh] ? body : unesc(body)
        qh++
        if (qq[qh - 1] || m == k) { i = LS[m + 1]; continue }
        push("hd"); hdon = 1; hdend = LS[m]; hdnext = LS[m + 1]
        return
      }
      qh = 1; qn = 0
    }
    # Renders an unquoted here-document body as bash does: \newline vanishes, \\, \$ and \` lose
    # their backslash. \\ goes first, through US, and is rejoined by split: backslashes in a gsub
    # replacement differ between awks.
    function unesc(b,   P, np, x, r) {
      gsub(/\\\\/, US, b); gsub(/\\\n/, "", b); gsub(/\\\$/, "$", b); gsub(/\\`/, "`", b)
      np = split(b, P, US); r = P[1]
      for (x = 2; x <= np; x++) r = r "\\" P[x]
      return r
    }
    function lex(str,   c, c2, c3, T, j, k, p, nl) {
      s = str; gsub(US, " ", s)
      if (substr(s, length(s), 1) != "\n") s = s "\n"
      n = length(s)
      nl = split(s, L, "\n"); nlines = nl - 1
      split("", lineat); p = 1
      for (k = 1; k <= nl; k++) { LS[k] = p; lineat[p] = k; p += length(L[k]) + 1 }
      sp = 0; push("top"); qh = 1; qn = 0; hdon = 0
      i = 1
      while (i <= n && !failed) {
        if (hdon && i >= hdend) {
          if (t[sp] != "hd") { fail("an unterminated substitution in a here-document"); break }
          sp--; hdon = 0; i = hdnext; heredocs(); continue
        }
        c = substr(s, i, 1); c2 = substr(s, i, 2); c3 = substr(s, i, 3); T = t[sp]
        # Inside backquotes bash drops the backslash of \$ and reads \` as a nested substitution.
        if (c == "\\" && inbq()) {
          if (c2 == "\\`") { fail("nested backquotes"); break }
          if (c2 == "\\$") { i++; continue }
        }
        if (T == "hd") {
          if (c == "\\") i += 2
          else if (c3 == "$((") { opensub("ar"); i += 3 }
          else if (c2 == "$(") { opensub("sub"); i += 2 }
          else if (c == "`") { opensub("bq"); i++ }
          else i++
          continue
        }
        if (T == "dq") {
          if (c == "\"") { sp--; i++ }
          else if (c == "\\") {
            j = substr(s, i + 1, 1)
            if (j == "\n") i += 2
            else if (j != "" && index("$`\"\\", j)) { app(j); i += 2 }
            else { app(c); i++ }
          }
          else if (c3 == "$((") { opensub("ar"); i += 3 }
          else if (c2 == "$(") { opensub("sub"); i += 2 }
          else if (c == "`") { opensub("bq"); i++ }
          else { app(c); i++ }
          continue
        }
        # A command frame: top, sub ($( <( >( ), bq (backquotes) or ar ($(( ), where << is a shift.
        if (c == " " || c == "\t" || c == "\r") { endword(sp); i++ }
        else if (c == "\n") { endcmd(sp, 2); i++; if (qh <= qn) heredocs() }
        else if (c == "#" && !inw[sp] && T != "ar") {
          for (j = i; j <= n && substr(s, j, 1) != "\n"; j++) ;
          i = j
        }
        else if (c2 == "||") { endcmd(sp, 0); i += 2 }
        else if (c2 == "|&") { endcmd(sp, 1); i += 2 }
        else if (c == "|") { endcmd(sp, 1); i++ }
        else if (c2 == "&>" && T != "ar") { endword(sp); rd[sp] = 1; i += (c3 == "&>>") ? 3 : 2 }
        else if (c == ";" || c == "&") { endcmd(sp, 0); i++ }
        else if (c == "(") { endcmd(sp, 2); pd[sp]++; i++ }
        else if (c == ")") {
          if (T == "sub" && pd[sp] == 0) { endcmd(sp, 0); sp--; i++ }
          else if (T == "ar" && pd[sp] == 0 && c2 == "))") { endcmd(sp, 0); sp--; i += 2 }
          else { if (pd[sp] > 0) pd[sp]--; endcmd(sp, 2); i++ }
        }
        else if (c == "`") {
          if (T == "bq") { endcmd(sp, 0); sp--; i++ }
          else { opensub("bq"); i++ }
        }
        else if (c == SQ) {
          for (j = i + 1; j <= n && substr(s, j, 1) != SQ; j++) ;
          if (j > n) { fail("unterminated quote"); break }
          quoted(); app(substr(s, i + 1, j - i - 1)); i = j + 1
        }
        else if (c2 == "$" SQ) {
          for (j = i + 2; j <= n && substr(s, j, 1) != SQ; j++) if (substr(s, j, 1) == "\\") j++
          if (j > n) { fail("unterminated quote"); break }
          quoted(); app(substr(s, i + 2, j - i - 2)); i = j + 1
        }
        else if (c == "\"") { quoted(); push("dq"); i++ }
        else if (c == "\\") {
          j = substr(s, i + 1, 1)
          if (j == "\n") i += 2
          else if (j == "") i++
          else { quoted(); app(j); i += 2 }
        }
        else if (c3 == "$((") { opensub("ar"); i += 3 }
        else if (c2 == "$(") { opensub("sub"); i += 2 }
        else if (T == "ar" && (c == "<" || c == ">")) { app(c); i++ }
        else if (c2 == "<(" || c2 == ">(") { opensub("sub"); i += 2 }
        else if (c3 == "<<<") { endword(sp); i += 3 }
        else if (c2 == "<<") {
          endword(sp); i += 2
          if (substr(s, i, 1) == "-") { i++; opener(1) } else opener(0)
        }
        else if (c == "<" || c == ">") {
          if (inw[sp] && !wq[sp] && !ws[sp] && (wv[sp] ~ /^[0-9]+$/ || wv[sp] ~ /^[{][A-Za-z_][A-Za-z0-9_]*[}]$/)) { wv[sp] = ""; inw[sp] = 0 }
          else endword(sp)
          if (c2 == ">>" || c2 == ">|" || c2 == "<>") { rd[sp] = 1; i += 2 }
          else if (c2 == ">&" || c2 == "<&") { rd[sp] = 2; i += 2 }
          else { rd[sp] = 1; i++ }
        }
        else { app(c); i++ }
      }
      if (failed) return
      if (sp > 1) {
        if (t[sp] == "dq") fail("unterminated quote")
        else if (t[sp] == "bq") fail("unterminated backquote")
        else fail("unterminated substitution")
        return
      }
      if (qh <= qn) { fail("a here-document without its body"); return }
      endcmd(1, 0)
    }
    BEGIN {
      US = sprintf("%c", 31); SQ = sprintf("%c", 39); SM = sprintf("%c", 30)
      split("sh bash zsh dash ksh mksh ash fish", tmp, " ")
      for (y in tmp) { INTERP[tmp[y]] = 1; SHELLS[tmp[y]] = 1 }
      INTERP["eval"] = 1; INTERP["watch"] = 1; INTERP["su"] = 1
      split("env command exec builtin time nice nohup timeout stdbuf sudo doas xargs setsid ionice ! { if then else elif do while until", tmp, " ")
      for (y in tmp) WRAP[tmp[y]] = 1
    }
    { buf = buf $0 "\n" }
    END {
      lex(buf)
      while (!failed && wk < wn) { wk++; lex(work[wk]) }
    }
  '
}

# The reading checks of mode qa, on the git call whose verb $1 sits at word $2 of vals.
check_git_read() {
  local verb="$1" j="$2" k nonopt
  for ((k = j + 1; k < n; k++)); do
    case "${vals[k]}" in
      --output|--output=*) deny "git $verb --output writes a file, which mode $mode never does: $cmd" ;;
    esac
  done
  if [ "$verb" = worktree ]; then
    [ "${vals[j+1]-}" = list ] || deny "git worktree ${vals[j+1]-} is forbidden in mode $mode, only worktree list reads: $cmd"
  else
    # An empty verb never matches: the list holds single spaces only.
    case "$QA_GIT_VERBS" in
      *" $verb "*) ;;
      *) deny "git ${verb:-without a verb} is forbidden in mode $mode, which runs reading verbs only: $cmd" ;;
    esac
  fi
  if [ "$verb" = symbolic-ref ]; then
    nonopt=0
    for ((k = j + 1; k < n; k++)); do
      case "${vals[k]}" in
        -q|--quiet|--short|--recurse|--no-recurse) ;;
        -*) deny "git symbolic-ref ${vals[k]} is forbidden in mode $mode, which only reads a ref: $cmd" ;;
        *) nonopt=$((nonopt + 1)) ;;
      esac
    done
    [ "$nonopt" -le 1 ] || deny "git symbolic-ref with a target writes a ref, forbidden in mode $mode: $cmd"
  fi
}

# git restore [-q|--quiet|-W|--worktree] [--] <path>..., the verb at word $1 of vals.
check_restore() {
  local j="$1" k a paths=0 sep=no
  for ((k = j + 1; k < n; k++)); do
    a="${vals[k]}"
    if [ "$sep" = yes ]; then paths=$((paths + 1)); continue; fi
    case "$a" in
      --) sep=yes ;;
      -q|--quiet|-W|--worktree) ;;
      -*) deny "git restore $a is forbidden to the reviewer, which only restores worktree files: $cmd" ;;
      *) paths=$((paths + 1)) ;;
    esac
  done
  [ "$paths" -gt 0 ] || deny "git restore without a path is forbidden to the reviewer: $cmd"
}

# In a throwaway repo of the temp dir ($1), every path the git call names after its verb (word $2 of
# vals) must resolve under the temp dir: a bare word, the value of --opt=value and of -o<value>.
check_temp_paths() {
  local base="$1" j="$2" k a cand
  local -a cands
  for ((k = j + 1; k < n; k++)); do
    a="${vals[k]}"; cands=()
    case "$a" in
      --*=*) cands+=("${a#*=}") ;;
      -[A-Za-z]?*) cands+=("${a:2}") ;;
      -*) ;;
      *) cands+=("$a") ;;
    esac
    for cand in ${cands[@]+"${cands[@]}"}; do
      case "$cand" in
        *$'\036'*|*'$'*|'~'*) deny "git ${vals[j]} names $(readable "$a"), a path po-bounds cannot read: $cmd" ;;
      esac
      resolve_path "$(join_dir "$base" "$cand")"
      under_temp "$RESOLVED" || deny "git ${vals[j]} names $a, which lies outside the temp dir ($TMP_ROOT): $cmd"
    done
  done
}

# In a throwaway repo, every redirection target of the git call, read from the shell's dir $1, must
# resolve under the temp dir too, or be /dev/null, /dev/stdout, /dev/stderr, /dev/fd/1 or /dev/fd/2.
check_redirects() {
  local r
  for r in ${redirs[@]+"${redirs[@]}"}; do
    case "$r" in
      /dev/null|/dev/stdout|/dev/stderr|/dev/fd/1|/dev/fd/2) continue ;;
      *$'\036'*|*'$'*|'~'*) deny "git ${vals[j]-} redirects to $(readable "$r"), a path po-bounds cannot read: $cmd" ;;
      /*) ;;
      *) [ -n "$1" ] || deny "git ${vals[j]-} redirects to $r from an unknown directory: $cmd" ;;
    esac
    resolve_path "$(join_dir "$1" "$r")"
    under_temp "$RESOLVED" || deny "git ${vals[j]-} redirects to $r, which lies outside the temp dir ($TMP_ROOT): $cmd"
  done
}

# Refuses a command-line config entry ($1: key[=value]) that sets core.worktree; $2, when given, follows the role
# in the message. tr, not ${key,,}: macOS ships bash 3.2.
check_config_key() {
  local key
  key="$(printf '%s' "${1%%=*}" | tr '[:upper:]' '[:lower:]')"
  [ "$key" != core.worktree ] || deny "core.worktree points git elsewhere, forbidden to the $mode${2-}: $cmd"
}

# Succeeds, setting ENV_WORD to the variable name, when the typed word ($1) assigns a variable that points git
# elsewhere. A quoted value is still an assignment (GIT_DIR="/x" git log), so q words count too. No subshell:
# it runs once per word of every command.
git_env_word() {
  case "${1:0:1}:${1:1}" in
    [uq]:GIT_DIR=*|[uq]:GIT_WORK_TREE=*|[uq]:GIT_CONFIG_PARAMETERS=*|[uq]:GIT_CONFIG_COUNT=*)
      ENV_WORD="${1:1}"; ENV_WORD="${ENV_WORD%%=*}"; return 0 ;;
  esac
  return 1
}

check_bash() {
  local cmd="$1" cur="$2" mode="$3" lexed line i j k n w a verb dir nonopt re throwaway pointer envpoint=""
  local -a cfgs=()
  local -a words=() vals=() all=() redirs=()
  lexed="$(printf '%s' "$cmd" | lex_command)" || deny "po-bounds cannot read this command: the lexer failed: $cmd"
  while IFS= read -r line; do
    case "$line" in '!'*) deny "po-bounds cannot read this command: ${line#!}: $cmd" ;; esac
  done <<< "$lexed"
  re='^-[A-Za-z]*[fDMC][A-Za-z]*$'
  [ "$mode" = qa ] || temp_root
  if [ "$mode" = implementer ]; then
    # The whole command: an export in an earlier simple command still reaches the git call.
    while IFS= read -r line; do
      IFS=$'\037' read -ra all <<< "$line"
      for a in ${all[@]+"${all[@]}"}; do
        if [ -z "$envpoint" ] && git_env_word "$a"; then envpoint="$ENV_WORD"; fi
      done
    done <<< "$lexed"
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    all=(); words=(); vals=(); redirs=()
    IFS=$'\037' read -ra all <<< "$line"
    for a in ${all[@]+"${all[@]}"}; do
      case "$a" in r*) redirs+=("${a#r}") ;; *) words+=("$a") ;; esac
    done
    n=${#words[@]}
    for ((k = 0; k < n; k++)); do vals[k]="${words[k]#?}"; done
    if [ "$mode" = reviewer ]; then
      for ((k = 0; k < n; k++)); do
        git_env_word "${words[k]}" || continue
        deny "$ENV_WORD points git elsewhere, forbidden to the reviewer: $cmd"
      done
    fi
    i=0
    while [ "$i" -lt "$n" ]; do
      w="${vals[i]}"
      if [ "$w" = cd ]; then
        if [ $((i + 1)) -lt "$n" ] && [[ "${vals[i+1]}" != -* ]]; then
          cur="$(step_dir "$cur" "${vals[i+1]}")"
          i=$((i + 2))
        else
          cur=""
          i=$((i + 1))
        fi
        continue
      fi
      # Quoted text is a git call only as the command word ("git", env \git, A=1 'git').
      if { [ "$w" = git ] || [[ "$w" == */git ]]; } && [ "${words[i]:0:1}" != q ]; then
        j=$((i + 1)); dir="$cur"; pointer=""; cfgs=()
        while [ "$j" -lt "$n" ]; do
          case "${vals[j]}" in
            -C) dir="$(step_dir "$dir" "${vals[j+1]-}")"; j=$((j + 2)) ;;
            --git-dir=*|--work-tree=*)
              [ "$mode" != reviewer ] || deny "git ${vals[j]%%=*} points git elsewhere, forbidden to the reviewer: $cmd"
              [ -n "$pointer" ] || pointer="${vals[j]%%=*}"
              j=$((j + 1)) ;;
            --git-dir|--work-tree)
              [ "$mode" != reviewer ] || deny "git ${vals[j]} points git elsewhere, forbidden to the reviewer: $cmd"
              [ -n "$pointer" ] || pointer="${vals[j]}"
              j=$((j + 2)) ;;
            -c|--config-env)
              [ "$mode" != reviewer ] || check_config_key "${vals[j+1]-}"
              cfgs+=("${vals[j+1]-}")
              j=$((j + 2)) ;;
            --config-env=*)
              [ "$mode" != reviewer ] || check_config_key "${vals[j]#*=}"
              cfgs+=("${vals[j]#*=}")
              j=$((j + 1)) ;;
            --git-dir|--work-tree|--namespace|--attr-source) j=$((j + 2)) ;;
            -*) j=$((j + 1)) ;;
            *) break ;;
          esac
        done
        verb="${vals[j]-}"
        if [ "$mode" = qa ]; then
          check_git_read "$verb" "$j"
        elif [ "$mode" = reviewer ]; then
          case "$verb" in push|send-pack) deny "git $verb is forbidden to the reviewer, everywhere: $cmd" ;; esac
          [ -n "$dir" ] && [ -d "$dir" ] || deny "git ${verb:-without a verb} runs in an unknown or missing directory (${dir:-unknown}): $cmd"
          if try_story_of_dir "$dir"; then
            owns_line "$TOP" "$STORY"
            case "$verb" in
              checkout)
                [ "${vals[j+1]-}" = -- ] && [ $((j + 2)) -lt "$n" ] \
                  || deny "git checkout is forbidden to the reviewer except git checkout -- <path>: $cmd" ;;
              restore) check_restore "$j" ;;
              *) check_git_read "$verb" "$j" ;;
            esac
          elif in_temp_zone "$dir"; then
            check_temp_paths "$dir" "$j"
            check_redirects "$cur"
          else
            deny "git ${verb:-without a verb} runs in $dir, outside a story worktree and outside a throwaway repo of the temp dir (${TMP_ROOT:-no usable temp dir}): $cmd"
          fi
        else
          # A story worktree is judged first: only a throwaway repo of the temp dir allows checkout.
          throwaway=no
          if [ -n "$dir" ] && [ -d "$dir" ] && ! try_story_of_dir "$dir" && in_temp_zone "$dir"; then
            throwaway=yes
          fi
          case "$verb" in
            switch|stash|push) deny "git $verb is forbidden to the implementer: $cmd" ;;
            checkout)
              [ "$throwaway" = yes ] \
                || deny "git checkout is forbidden to the implementer outside a throwaway repo of the temp dir (${TMP_ROOT:-no usable temp dir}): $cmd" ;;
            worktree) [ "${vals[j+1]-}" != add ] || deny "git worktree add is forbidden to the implementer: $cmd" ;;
            update-ref) deny "git update-ref is forbidden to the implementer: $cmd" ;;
            branch)
              for ((k = j + 1; k < n; k++)); do
                a="${vals[k]}"
                case "$a" in
                  -f|--force|-D|-M|-C) deny "git branch $a moves or deletes a branch, forbidden to the implementer: $cmd" ;;
                  --*) continue ;;
                esac
                [[ ! $a =~ $re ]] || deny "git branch $a moves or deletes a branch, forbidden to the implementer: $cmd"
              done
              ;;
            commit|reset|merge|rebase|cherry-pick|revert|am|pull)
              [ -n "$dir" ] && [ -d "$dir" ] || deny "git $verb outside a story/<id> branch: $cmd"
              story_of_dir "git $verb outside a story/<id> branch: $cmd" "$dir"
              ;;
          esac
          if [ "$throwaway" = yes ]; then
            [ -z "$pointer" ] || deny "git $pointer points git elsewhere, forbidden to the implementer in a throwaway repo: $cmd"
            for a in ${cfgs[@]+"${cfgs[@]}"}; do check_config_key "$a" " in a throwaway repo"; done
            [ -z "$envpoint" ] || deny "$envpoint points git elsewhere, forbidden to the implementer in a throwaway repo: $cmd"
            check_temp_paths "$dir" "$j"
            check_redirects "$cur"
          fi
        fi
        i=$j
      fi
      i=$((i + 1))
    done
  done <<< "$lexed"
  exit 0
}

mode="${1-}"
case "$mode" in
  implementer|qa|reviewer) ;;
  *) deny "unknown mode '${mode}' (expected: implementer, qa or reviewer)" ;;
esac

command -v jq > /dev/null 2>&1 || deny "jq is required and was not found; every call is refused without it"
# Claude Code hands the input over a socket, which /dev/stdin cannot open; cat reads fd 0 directly.
input="$(cat)"
tool="$(jq -er '.tool_name | strings' <<< "$input" 2>/dev/null)" || deny "unreadable hook input"

case "$mode:$tool" in
  implementer:Write|implementer:Edit)
    path="$(jq -er '.tool_input.file_path | strings' <<< "$input" 2>/dev/null)" || deny "unreadable hook input: no file_path"
    check_write "$path"
    ;;
  qa:Write)
    path="$(jq -er '.tool_input.file_path | strings' <<< "$input" 2>/dev/null)" || deny "unreadable hook input: no file_path"
    check_write_qa "$path"
    ;;
  reviewer:Write|reviewer:Edit)
    path="$(jq -er '.tool_input.file_path | strings' <<< "$input" 2>/dev/null)" || deny "unreadable hook input: no file_path"
    check_write_reviewer "$path"
    ;;
  implementer:Bash|qa:Bash|reviewer:Bash)
    cmd="$(jq -er '.tool_input.command | strings' <<< "$input" 2>/dev/null)" || deny "unreadable hook input: no command"
    cwd="$(jq -r '.cwd // empty | strings' <<< "$input" 2>/dev/null)" || deny "unreadable hook input"
    check_bash "$cmd" "$cwd" "$mode"
    ;;
  *) deny "tool $tool is not allowed in mode $mode" ;;
esac
deny "no decision reached"
