#!/usr/bin/env bash
#
# severity_recon.sh — severity-focused recon pipeline (Synack LP+ patched)
#
# Changes vs original:
#   - Tool preflight check (required/optional) before any work starts
#   - OSINT_SOURCES flag gates chaos/crtsh/gau/wayback; default = none enabled
#     (set via env, e.g. OSINT_SOURCES="gau,wayback" ./severity_recon.sh TARGET)
#   - Preflight connectivity check for each enabled OSINT source — warns and
#     auto-skips instead of silently producing empty output
#   - BB_HEADER now empty by default, set via env (no hardcoded H1 handle)
#   - Phase 5c SSRF OOB probing requires BOTH SSRF_COLLAB and ACTIVE_PROBE=1
#     to actually send payloads — SSRF_COLLAB alone only lists candidates
#
set -uo pipefail
export LC_ALL=C

TARGET=""
SCOPE_FILE="${SCOPE_FILE:-$HOME/recon/scope/scope.tsv}"
BUDGET="${BUDGET:-1800}"
NO_SCOPE=0
CHECK_SCOPE=0
DEFAULT_RATE=20

CLI_INCLUDE=(); CLI_EXCLUDE=(); CLI_SKIP=()

while [ $# -gt 0 ]; do
    case "$1" in
        --scope)       SCOPE_FILE="$2"; shift 2 ;;
        --budget)      BUDGET="$2"; shift 2 ;;
        --include)     CLI_INCLUDE+=("$2"); shift 2 ;;
        --exclude)     CLI_EXCLUDE+=("$2"); shift 2 ;;
        --skip)        CLI_SKIP+=("$2"); shift 2 ;;
        --no-scope)    NO_SCOPE=1; shift ;;
        --check-scope) CHECK_SCOPE=1; shift ;;
        -h|--help)     echo "Usage: $0 TARGET [--scope FILE] [--budget SEC] [--include P] [--exclude P] [--skip P] [--no-scope] [--check-scope]"; exit 0 ;;
        *)             [ -z "$TARGET" ] && TARGET="$1" || { echo "extra arg: $1" >&2; exit 1; }; shift ;;
    esac
done

if [ "$CHECK_SCOPE" = "1" ] && [ -z "$TARGET" ]; then
    TARGET="check"
fi

[ -n "$TARGET" ] || { echo "Usage: $0 TARGET [--scope FILE] ..." >&2; exit 1; }

if [ "$CHECK_SCOPE" = "0" ]; then
    [[ "$TARGET" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "[!] unsafe TARGET" >&2; exit 1; }
fi

START_EPOCH=$(date +%s)
deadline()   { echo $(( START_EPOCH + BUDGET )); }
remaining()  { local r=$(( $(deadline) - $(date +%s) )); [ "$r" -lt 0 ] && r=0; echo "$r"; }
budget_left(){ [ "$(remaining)" -gt 0 ]; }

# ---------------------------------------------------------------------
# Phase marker helpers
# ---------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_PHASE=$'\033[1;36m'
    C_INFO=$'\033[1;33m'
    C_OK=$'\033[1;32m'
    C_WARN=$'\033[1;31m'
else
    C_RESET=""; C_PHASE=""; C_INFO=""; C_OK=""; C_WARN=""
fi

phase()  { printf '%s[%s]%s %s\n' "$C_PHASE" "$1" "$C_RESET" "$2"; }
info()   { printf '%s   %s%s\n' "$C_INFO" "$1" "$C_RESET"; }
ok()     { printf '%s   [+] %s%s\n' "$C_OK" "$1" "$C_RESET"; }
warn()   { printf '%s   [!] %s%s\n' "$C_WARN" "$1" "$C_RESET"; }

# ---------------------------------------------------------------------
# NEW: Tool preflight — fail fast on missing required tools, warn on
# optional ones so a degraded run is a known state, not a surprise.
# ---------------------------------------------------------------------
REQUIRED_TOOLS="subfinder httpx jq curl awk sort"
OPTIONAL_TOOLS="chaos katana jsluice trufflehog node jshound amass"

if [ "$CHECK_SCOPE" = "0" ]; then
    for t in $REQUIRED_TOOLS; do
        command -v "$t" >/dev/null 2>&1 || { echo "[!] REQUIRED tool missing: $t — aborting." >&2; exit 1; }
    done
    for t in $OPTIONAL_TOOLS; do
        command -v "$t" >/dev/null 2>&1 || warn "optional tool missing: $t (related phase will be degraded or skipped)"
    done
fi

# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------
export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:$PATH"
SECLISTS="$HOME/SecLists"
DIRLIST="$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt"
FILELIST="$SECLISTS/Discovery/Web-Content/common.txt"
LINKFINDER="$HOME/LinkFinder/linkfinder.py"

# NEW: BB_HEADER is now opt-in via env, empty (no header) by default.
#   export BB_HEADER="X-Bug-Bounty: your-handle"   # only if your program wants one
BB_HEADER="${BB_HEADER:-}"
BB_HEADER_ARGS=()
[ -n "$BB_HEADER" ] && BB_HEADER_ARGS=(-H "$BB_HEADER")

BB_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

WORKDIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORKDIR"/{js,results,logs,exports}
LOGFILE="$WORKDIR/logs/run.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "[*] Severity recon v3.7 (Synack-patched): $TARGET   budget=${BUDGET}s   workdir=$WORKDIR"
echo ""

# ---------------------------------------------------------------------
# NEW: OSINT source gating — chaos/crt.sh/gau/waybackurls all depend on
# third-party domains that may not be on a given program's allowlist.
# Nothing is enabled by default; set OSINT_SOURCES to opt in, and each
# enabled source gets a one-time connectivity check so a dead domain
# produces a clear warning instead of a silent empty-file failure.
#
#   export OSINT_SOURCES="gau,wayback"   # enable just these two
#   export OSINT_SOURCES="chaos,crtsh,gau,wayback"   # enable all
# ---------------------------------------------------------------------
OSINT_SOURCES="${OSINT_SOURCES:-}"
declare -A OSINT_DOMAINS=(
    [chaos]="chaos.projectdiscovery.io"
    [crtsh]="crt.sh"
    [gau]="web.archive.org"
    [wayback]="web.archive.org"
)
declare -A OSINT_OK=()
_osint_requested() { [[ ",$OSINT_SOURCES," == *",$1,"* ]]; }
_osint_use()       { [ -n "${OSINT_OK[$1]:-}" ]; }

phase "Preflight" "OSINT source check"
if [ -z "$OSINT_SOURCES" ]; then
    info "OSINT_SOURCES not set — chaos/crt.sh/gau/waybackurls all disabled by default."
    info "Set OSINT_SOURCES=\"gau,wayback\" (or similar) to enable, if those domains are allowlisted."
else
    IFS=',' read -ra _req_sources <<< "$OSINT_SOURCES"
    for src in "${_req_sources[@]}"; do
        [ -z "$src" ] && continue
        d="${OSINT_DOMAINS[$src]:-}"
        if [ -z "$d" ]; then
            warn "unknown OSINT source '$src' — ignoring"
            continue
        fi
        if curl -sI --connect-timeout 4 --max-time 6 "https://$d" >/dev/null 2>&1; then
            OSINT_OK[$src]=1
            ok "OSINT source reachable: $src ($d)"
        else
            warn "OSINT source unreachable, skipping: $src ($d) — not allowlisted or network issue"
        fi
    done
fi
echo ""

# ---------------------------------------------------------------------
# Scope: layered load + rate/header/tag maps
# ---------------------------------------------------------------------
declare -a INC=() EXC=() SKIP=()
declare -A _SC=()
declare -A HOST_RATE=()
declare -A HOST_HEADERS=()
declare -A HOST_TAGS=()

SCOPE_DEPTH=0
MAX_SCOPE_DEPTH=3

load_scope_file() {
    local file="$1"
    [ -f "$file" ] || { warn "scope file missing: $file"; return 0; }
    [ "$SCOPE_DEPTH" -ge "$MAX_SCOPE_DEPTH" ] && { warn "scope recursion too deep: $file"; return 0; }
    SCOPE_DEPTH=$(( SCOPE_DEPTH + 1 ))
    local lineno=0 kind pat val _c
    while IFS=$'\t' read -r kind pat val _c; do
        lineno=$(( lineno + 1 ))
        kind="${kind%$'\r'}"; pat="${pat%$'\r'}"; val="${val%$'\r'}"
        [ -z "${kind:-}" ] && continue
        [[ "$kind" = \#* ]] && continue
        case "$kind" in
            include)
                if [[ "$pat" = ./*.tsv ]]; then
                    load_scope_file "$(dirname "$file")/${pat#./}"
                else
                    INC+=("$pat")
                fi ;;
            exclude) EXC+=("$pat") ;;
            skip)    SKIP+=("$pat") ;;
            rate)    HOST_RATE["$pat"]="$val" ;;
            header)
                if [ -n "${HOST_HEADERS[$pat]:-}" ]; then
                    HOST_HEADERS["$pat"]="${HOST_HEADERS[$pat]}"$'\n'"$val"
                else
                    HOST_HEADERS["$pat"]="$val"
                fi ;;
            tag)
                if [ -n "${HOST_TAGS[$pat]:-}" ]; then
                    HOST_TAGS["$pat"]="${HOST_TAGS[$pat]} $val"
                else
                    HOST_TAGS["$pat"]="$val"
                fi ;;
            *) warn "$file:$lineno unknown kind '$kind'" ;;
        esac
    done < "$file"
    SCOPE_DEPTH=$(( SCOPE_DEPTH - 1 ))
}

_norm() { local h="${1,,}"; h="${h#*://}"; h="${h%%/*}"; h="${h%%:*}"; echo "$h"; }
_matches() { [[ "$2" == $1 || "$2" == *".$1" ]]; }

_decide() {
    local h; h=$(_norm "$1")
    if [ -z "${_SC[$h]:-}" ]; then
        local d="include" p
        for p in "${EXC[@]}";  do _matches "$p" "$h" && { d=exclude; break; }; done
        if [ "$d" = include ]; then
            for p in "${SKIP[@]}"; do _matches "$p" "$h" && { d=skip; break; }; done
        fi
        if [ "$d" = include ] && [ "${#INC[@]}" -gt 0 ]; then
            d=out
            for p in "${INC[@]}"; do _matches "$p" "$h" && { d=include; break; }; done
        fi
        _SC[$h]=$d
    fi
    echo "${_SC[$h]}"
}
_in_scope() { [ "$(_decide "$1")" = include ]; }

_lookup_map() {
    local host="$1"; shift
    local -n _map="$1"
    local pat best=""
    for pat in "${!_map[@]}"; do
        _matches "$pat" "$host" || continue
        [ "${#pat}" -gt "${#best}" ] && best="$pat"
    done
    [ -n "$best" ] && printf '%s' "${_map[$best]}"
}

rate_for_host() {
    local h; h=$(_norm "$1")
    [ -n "${HOST_RATE[$h]:-}" ] && { echo "${HOST_RATE[$h]}"; return; }
    local v; v=$(_lookup_map "$h" HOST_RATE)
    echo "${v:-$DEFAULT_RATE}"
}

headers_for_host() {
    local h; h=$(_norm "$1")
    printf '%s\n' "User-Agent: $BB_UA"
    if [ -n "${HOST_HEADERS[$h]:-}" ]; then
        printf '%s\n' "${HOST_HEADERS[$h]}"
        return
    fi
    local v; v=$(_lookup_map "$h" HOST_HEADERS)
    [ -n "$v" ] && printf '%s\n' "$v"
    return 0
}

tags_for_host() {
    local h; h=$(_norm "$1")
    [ -n "${HOST_TAGS[$h]:-}" ] && { echo "${HOST_TAGS[$h]}"; return; }
    local v; v=$(_lookup_map "$h" HOST_TAGS)
    echo "$v"
}

header_args() {
    local h="$1" line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        printf -- '-H\n%s\n' "$line"
    done < <(headers_for_host "$h")
}

# ── JS ANALYSIS: strip comments + strings, dedupe, score ─────────────
JS_STRIP_MODE="none"
if command -v node >/dev/null 2>&1; then
    JS_STRIP_MODE="node"
fi
export JS_STRIP_MODE

strip_js() {
    local f="$1"
    if [ "$JS_STRIP_MODE" != "node" ]; then
        cat "$f"
        return 0
    fi
    node -e '
        const fs = require("fs");
        const path = process.argv[1];
        const src = fs.readFileSync(path, "utf8");
        let out = "", i = 0, n = src.length, mode = "code";
        let lastSig = "";
        while (i < n) {
            const c = src[i], c2 = src[i+1];
            if (mode === "code") {
                if (c === "/" && c2 === "/") { mode = "lc"; i += 2; continue; }
                if (c === "/" && c2 === "*") { mode = "bc"; i += 2; continue; }
                if (c === "/") {
                    const regexContext = !lastSig || /[=(,;:!&|?{}[\]+\-*%<>~^]/.test(lastSig);
                    if (regexContext) {
                        out += c; i++;
                        while (i < n) {
                            const rc = src[i];
                            if (rc === "\\") { i += 2; continue; }
                            if (rc === "\n") break;
                            if (rc === "/") { out += rc; i++; break; }
                            i++;
                        }
                        lastSig = "/";
                        continue;
                    }
                }
                if (c === "\"") { mode = "dq"; out += c; i++; continue; }
                if (c === "\x27") { mode = "sq"; out += c; i++; continue; }
                if (c === "`")  { mode = "tq"; out += c; i++; continue; }
                out += c;
                if (!/\s/.test(c)) lastSig = c;
                i++; continue;
            }
            if (mode === "lc") {
                if (c === "\n") { mode = "code"; out += c; }
                i++; continue;
            }
            if (mode === "bc") {
                if (c === "*" && c2 === "/") { mode = "code"; i += 2; continue; }
                if (c === "\n") out += c;
                i++; continue;
            }
            const close = mode === "dq" ? "\"" : mode === "sq" ? "\x27" : "`";
            if (c === "\\") { i += 2; continue; }
            if (c === close) { mode = "code"; out += c; lastSig = close; i++; continue; }
            if (c === "\n") out += c;
            i++;
        }
        process.stdout.write(out);
    ' "$f"
}
export -f strip_js
# ── /JS ANALYSIS ──────────────────────────────────────────────────────

# ── SEVERITY: host scoring ────────────────────────────────────────────
severity_score_host() {
    local h="${1,,}" score=0 tags
    case "$h" in
        api.*|api-*|*-api.*|*.*.api.*|*.api.*)           score=$((score+5)) ;;
    esac
    case "$h" in
        admin.*|*.admin.*|internal.*|*.internal.*)       score=$((score+5)) ;;
        staging.*|*.staging.*|dev.*|*.dev.*)             score=$((score+5)) ;;
        test.*|*.test.*|qa.*|*.qa.*|preprod.*|*.preprod.*) score=$((score+4)) ;;
        auth.*|*.auth.*|accounts.*|*.accounts.*)         score=$((score+4)) ;;
        login.*|*.login.*|sso.*|*.sso.*)                 score=$((score+4)) ;;
        *payment*|*billing*|*checkout*)                  score=$((score+4)) ;;
        *graphql*|*rpc*)                                 score=$((score+3)) ;;
        *api*)                                           score=$((score+2)) ;;
    esac

    tags=$(tags_for_host "$h")
    [[ "$tags" == *high-value* ]] && score=$((score+5))
    [[ "$tags" == *auth* ]]       && score=$((score+4))
    [[ "$tags" == *admin* ]]      && score=$((score+4))

    echo "$score"
}
# ── /SEVERITY ─────────────────────────────────────────────────────────

# ---------------------------------------------------------------------
# Scope validator
# ---------------------------------------------------------------------
validate_scope() {
    local file="${1:-$SCOPE_FILE}"
    local errors=0 warnings=0
    local -A include_pats=() skip_pats=() exclude_pats=()

    echo "[*] Validating $file"

    _val_file() {
        local f="$1"
        [ -f "$f" ] || { echo "  ERR: file not found: $f"; errors=$((errors+1)); return; }
        local ln=0 kind pat val _c
        while IFS=$'\t' read -r kind pat val _c; do
            ln=$(( ln + 1 ))
            local where="$f:$ln"
            kind="${kind%$'\r'}"; pat="${pat%$'\r'}"; val="${val%$'\r'}"
            [ -z "$kind" ] && continue
            [[ "$kind" = \#* ]] && continue

            if [[ "$kind" == *" "* ]]; then
                echo "  ERR $where: fields separated by space, not tab"
                errors=$((errors+1)); continue
            fi

            case "$kind" in
                include)
                    if [[ "$pat" = ./*.tsv ]]; then _val_file "$(dirname "$f")/${pat#./}"; continue; fi
                    [ -z "$pat" ] && { echo "  ERR $where: empty include pattern"; errors=$((errors+1)); continue; }
                    [[ "$pat" =~ ^https?:// ]] && { echo "  WARN $where: include pattern has scheme"; warnings=$((warnings+1)); }
                    [[ "$pat" =~ [A-Z] ]] && { echo "  WARN $where: pattern has uppercase"; warnings=$((warnings+1)); }
                    [[ "$pat" =~ ^\*[^*]+\* ]] && { echo "  WARN $where: wildcard only supported as '*.prefix'"; warnings=$((warnings+1)); }
                    include_pats["$pat"]=1 ;;
                exclude)
                    [ -z "$pat" ] && { echo "  ERR $where: empty exclude pattern"; errors=$((errors+1)); continue; }
                    exclude_pats["$pat"]=1 ;;
                skip)
                    [ -z "$pat" ] && { echo "  ERR $where: empty skip pattern"; errors=$((errors+1)); continue; }
                    skip_pats["$pat"]=1 ;;
                rate)
                    [ -z "$pat" -o -z "$val" ] && { echo "  ERR $where: rate needs pattern AND number"; errors=$((errors+1)); continue; }
                    [[ "$val" =~ ^[0-9]+$ ]] || { echo "  ERR $where: rate '$val' not an integer"; errors=$((errors+1)); } ;;
                header)
                    [ -z "$pat" -o -z "$val" ] && { echo "  ERR $where: header needs pattern AND 'Name: Value'"; errors=$((errors+1)); continue; }
                    [[ "$val" =~ ^[A-Za-z0-9-]+\ *: ]] || { echo "  WARN $where: header value malformed"; warnings=$((warnings+1)); } ;;
                tag)
                    [ -z "$pat" -o -z "$val" ] && { echo "  ERR $where: tag needs pattern AND name"; errors=$((errors+1)); continue; }
                    [[ "$val" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "  WARN $where: unusual tag '$val'"; warnings=$((warnings+1)); } ;;
                *) echo "  ERR $where: unknown kind '$kind'"; errors=$((errors+1)) ;;
            esac
        done < "$f"
    }

    _val_file "$file"

    local p
    for p in "${!include_pats[@]}"; do
        [ -n "${skip_pats[$p]:-}" ]    && { echo "  WARN: '$p' in both include and skip (skip wins)"; warnings=$((warnings+1)); }
        [ -n "${exclude_pats[$p]:-}" ] && { echo "  WARN: '$p' in both include and exclude (exclude wins)"; warnings=$((warnings+1)); }
    done

    [ "${#include_pats[@]}" -eq 0 ] && { echo "  WARN: no include rules — every host will be 'out'"; warnings=$((warnings+1)); }

    echo "[*] Validation: $errors error(s), $warnings warning(s)"
    [ "$errors" -gt 0 ] && return 1
    return 0
}

if [ "$CHECK_SCOPE" = "1" ]; then
    if validate_scope "$SCOPE_FILE"; then
        echo "[*] Scope OK"
        rm -rf "$WORKDIR"
        exit 0
    else
        echo "[!] Scope has errors" >&2
        rm -rf "$WORKDIR"
        exit 1
    fi
fi

if [ "$NO_SCOPE" = "1" ]; then
    info "scope disabled (--no-scope)"
else
    if [ -f "$SCOPE_FILE" ]; then load_scope_file "$SCOPE_FILE"; else warn "no scope file at $SCOPE_FILE — allowing everything"; fi
    [ "${#CLI_INCLUDE[@]}" -gt 0 ] && INC+=("${CLI_INCLUDE[@]}")
    [ "${#CLI_EXCLUDE[@]}" -gt 0 ] && EXC+=("${CLI_EXCLUDE[@]}")
    [ "${#CLI_SKIP[@]}"    -gt 0 ] && SKIP+=("${CLI_SKIP[@]}")
    info "scope: ${#INC[@]}inc ${#EXC[@]}exc ${#SKIP[@]}skip ${#HOST_RATE[@]}rate ${#HOST_HEADERS[@]}hdr ${#HOST_TAGS[@]}tag"
fi

case "$(_decide "$TARGET")" in
    include|skip) : ;;
    *) warn "$TARGET not in scope. Aborting."; exit 1 ;;
esac

echo ""

# ---------------------------------------------------------------------
# Phase 1 — hosts (bucketed by rate)
# ---------------------------------------------------------------------
phase "Phase 1" "Host discovery"
subfinder -d "$TARGET" -silent -o "$WORKDIR/results/subs.subfinder.txt" 2>/dev/null || true

if _osint_use chaos && command -v chaos >/dev/null 2>&1; then
    chaos -d "$TARGET" -silent -o "$WORKDIR/results/subs.chaos.txt" 2>/dev/null || true
fi

cat "$WORKDIR/results/subs.subfinder.txt" "$WORKDIR/results/subs.chaos.txt" 2>/dev/null | \
    sort -u > "$WORKDIR/results/subs.raw.txt"

if [ ! -s "$WORKDIR/results/subs.raw.txt" ] && _osint_use crtsh; then
    curl -s --connect-timeout 5 "https://crt.sh/?q=%25.$TARGET&output=json" \
    | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' > "$WORKDIR/results/subs.raw.txt"
elif [ ! -s "$WORKDIR/results/subs.raw.txt" ] && command -v amass >/dev/null 2>&1; then
    info "crt.sh disabled/unreachable — falling back to amass passive enum"
    amass enum -passive -d "$TARGET" -o "$WORKDIR/results/subs.amass.txt" 2>/dev/null || true
    cat "$WORKDIR/results/subs.amass.txt" 2>/dev/null >> "$WORKDIR/results/subs.raw.txt"
fi

echo "$TARGET" >> "$WORKDIR/results/subs.raw.txt"
sort -u "$WORKDIR/results/subs.raw.txt" -o "$WORKDIR/results/subs.raw.txt"

awk '!seen[$0]++' "$WORKDIR/results/subs.raw.txt" \
    | while read -r h; do
        if _in_scope "$h"; then
            echo "$h"
        fi
    done > "$WORKDIR/results/subs.txt"
info "subs: $(wc -l < "$WORKDIR/results/subs.raw.txt") raw -> $(wc -l < "$WORKDIR/results/subs.txt") in-scope"

[ -s "$WORKDIR/results/subs.txt" ] || { warn "no in-scope subdomains. Aborting."; exit 1; }

: > "$WORKDIR/results/hosts_by_rate.txt"
while read -r h; do
    [ -z "$h" ] && continue
    printf '%s\t%s\n' "$(rate_for_host "$h")" "$h" >> "$WORKDIR/results/hosts_by_rate.txt"
done < "$WORKDIR/results/subs.txt"
sort -n "$WORKDIR/results/hosts_by_rate.txt" -o "$WORKDIR/results/hosts_by_rate.txt"

: > "$WORKDIR/results/live.txt"
awk -F'\t' '{print $1}' "$WORKDIR/results/hosts_by_rate.txt" | uniq | while read -r bucket_rate; do
    awk -F'\t' -v r="$bucket_rate" '$1==r{print $2}' "$WORKDIR/results/hosts_by_rate.txt" > "$WORKDIR/results/_b.txt"
    [ -s "$WORKDIR/results/_b.txt" ] || continue
    first_host=$(head -1 "$WORKDIR/results/_b.txt")
    mapfile -t HDRS < <(header_args "$first_host")
    httpx -l "$WORKDIR/results/_b.txt" -silent -timeout 8 -retries 1 \
        -threads 100 -rate-limit "$bucket_rate" \
        -tls-impersonate chrome \
        "${HDRS[@]}" "${BB_HEADER_ARGS[@]}" >> "$WORKDIR/results/live.txt" || true
done
info "live (TCP-connected): $(wc -l < "$WORKDIR/results/live.txt")"

# ── SEVERITY: host ranking ────────────────────────────────────────────
phase "Phase 1b" "Host severity ranking"
: > "$WORKDIR/results/hosts_ranked.tsv"
while read -r h; do
    [ -z "$h" ] && continue
    printf '%s\t%s\n' "$(severity_score_host "$h")" "$h"
done < "$WORKDIR/results/live.txt" | sort -rn > "$WORKDIR/results/hosts_ranked.tsv"

awk -F'\t' '$1 >= 3 {print $2}' "$WORKDIR/results/hosts_ranked.tsv" \
    > "$WORKDIR/results/priority_hosts.txt"

if [ "$(wc -l < "$WORKDIR/results/priority_hosts.txt")" -lt 10 ]; then
    head -10 "$WORKDIR/results/hosts_ranked.tsv" | cut -f2 \
        > "$WORKDIR/results/priority_hosts.txt"
fi

echo "$TARGET" >> "$WORKDIR/results/priority_hosts.txt"
sort -u "$WORKDIR/results/priority_hosts.txt" -o "$WORKDIR/results/priority_hosts.txt"

info "priority hosts: $(wc -l < "$WORKDIR/results/priority_hosts.txt")"
# ── /SEVERITY ─────────────────────────────────────────────────────────

# ---------------------------------------------------------------------
# Phase 2 — historical URLs (tiered, OSINT-gated)
# ---------------------------------------------------------------------
phase "Phase 2" "Historical URLs"
: > "$WORKDIR/results/hist.raw.txt"
if _osint_use gau && command -v gau >/dev/null 2>&1; then
    gau --threads 10 "$TARGET" 2>/dev/null >> "$WORKDIR/results/hist.raw.txt" || true
fi
if _osint_use wayback && command -v waybackurls >/dev/null 2>&1; then
    waybackurls "$TARGET" 2>/dev/null >> "$WORKDIR/results/hist.raw.txt" || true
fi
if [ ! -s "$WORKDIR/results/hist.raw.txt" ]; then
    info "no historical-URL sources enabled/reachable — Phase 2 will be empty (Phase 3 katana crawl still runs)"
fi
sort -u "$WORKDIR/results/hist.raw.txt" -o "$WORKDIR/results/hist.raw.txt"

RAW_COUNT=$(wc -l < "$WORKDIR/results/hist.raw.txt")
info "raw: $RAW_COUNT URLs"

TIER1_PATTERN='(/api/|/v[0-9]+/|/admin|/internal|/management|/console|/dashboard|/upload|/execute|/eval|/import|/export|/report|/download|/graphql|/rpc|/webhook|/callback|/proxy|/fetch|/oauth|/auth|/token|/sso|/saml|/reset|/forgot|/verify|[?&](id|user_?id|account_?id|order_?id|file_?id|doc_?id|item_?id|url|uri|redirect|callback|webhook|proxy|fetch|target|dest)=)'
TIER2_PATTERN='\.js(\?|$)'
TIER3_CAP="${TIER3_CAP:-5000}"

TIER1=$(mktemp); TIER2=$(mktemp); TIER3=$(mktemp)

grep -E "$TIER1_PATTERN" "$WORKDIR/results/hist.raw.txt" > "$TIER1" || true
grep -vE "$TIER1_PATTERN" "$WORKDIR/results/hist.raw.txt" | grep -E "$TIER2_PATTERN" > "$TIER2" || true
grep -vE "$TIER1_PATTERN" "$WORKDIR/results/hist.raw.txt" | grep -vE "$TIER2_PATTERN" | shuf | head -"$TIER3_CAP" > "$TIER3" || true

T1=$(wc -l < "$TIER1"); T2=$(wc -l < "$TIER2"); T3=$(wc -l < "$TIER3")
info "tier1 (high-signal): $T1"
info "tier2 (js files):    $T2"
info "tier3 (other, cap):  $T3"

cat "$TIER1" "$TIER2" "$TIER3" > "$WORKDIR/results/hist.capped.txt"
rm -f "$TIER1" "$TIER2" "$TIER3"

awk '{
    u = $0
    h = u; sub(/^https?:\/\//, "", h); sub(/[\/:?].*/, "", h)
    print h "\t" u
}' "$WORKDIR/results/hist.capped.txt" \
    | while IFS=$'\t' read -r h u; do
        if _in_scope "$h"; then
            echo "$u"
        fi
    done > "$WORKDIR/results/hist.txt"
info "historical (in-scope): $(wc -l < "$WORKDIR/results/hist.txt")"

# ---------------------------------------------------------------------
# Phase 3 — katana (gated on priority hosts)
# ---------------------------------------------------------------------
phase "Phase 3" "Katana crawl"
mapfile -t TARGET_HDRS < <(header_args "$TARGET")

KATANA_INPUT="$WORKDIR/results/live.txt"
if [ -s "$WORKDIR/results/priority_hosts.txt" ]; then
    KATANA_INPUT="$WORKDIR/results/priority_hosts.txt"
    info "katana scoped to priority_hosts.txt ($(wc -l < "$KATANA_INPUT") hosts)"
fi

timeout 180 katana -list "$KATANA_INPUT" \
    -jc -kf all -silent -fs fqdn -field-scope rdn -cos '^https?://' \
    -c 50 -p 20 -rl "$(rate_for_host "$TARGET")" -timeout 8 \
    "${TARGET_HDRS[@]}" "${BB_HEADER_ARGS[@]}" \
    -o "$WORKDIR/results/katana.raw.txt" || true

awk '{
    u = $0
    h = u; sub(/^https?:\/\//, "", h); sub(/[\/:?].*/, "", h)
    print h "\t" u
}' "$WORKDIR/results/katana.raw.txt" \
    | while IFS=$'\t' read -r h u; do
        if _in_scope "$h"; then
            echo "$u"
        fi
    done > "$WORKDIR/results/katana.txt"
info "katana: $(wc -l < "$WORKDIR/results/katana.txt")"

# ---------------------------------------------------------------------
# Phase 4 — JS pipeline
# ---------------------------------------------------------------------
phase "Phase 4" "JS pipeline"

: "${JS_CAP:=500}"

{
    grep -E '\.js(\?|$)' "$WORKDIR/results/hist.txt"   || true
    grep -E '\.js(\?|$)' "$WORKDIR/results/katana.txt" || true
} | sort -u > "$WORKDIR/results/js_urls.raw.txt"

awk -F'?' '{print $1}' "$WORKDIR/results/js_urls.raw.txt" \
    | sort -u > "$WORKDIR/results/js_urls.dedup.txt"

{
    grep -E '/(app|main|index|vendor|runtime|polyfills|chunk)[.-]' "$WORKDIR/results/js_urls.dedup.txt" || true
    grep -vE '/(app|main|index|vendor|runtime|polyfills|chunk)[.-]' "$WORKDIR/results/js_urls.dedup.txt" || true
} | awk '!seen[$0]++' | head -"$JS_CAP" > "$WORKDIR/results/js_urls.txt"

info "JS URLs: $(wc -l < "$WORKDIR/results/js_urls.raw.txt") raw -> $(wc -l < "$WORKDIR/results/js_urls.dedup.txt") dedup -> $(wc -l < "$WORKDIR/results/js_urls.txt") capped"

: > "$WORKDIR/results/js_endpoints.tsv"
: > "$WORKDIR/results/js_params.txt"
: > "$WORKDIR/results/js_map.tsv"

download_js() {
    local url="$1"
    local hash out tmp host hdr
    hash=$(echo -n "$url" | sha256sum | cut -c1-16)
    out="$WORKDIR/js/${hash}.js"
    tmp="${out}.part"

    [ -s "$out" ] && return 0

    hdr="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

    local curl_hdr_args=()
    [ -n "$BB_HEADER" ] && curl_hdr_args=(-H "$BB_HEADER")

    if ! curl -sL "${curl_hdr_args[@]}" \
             -H "User-Agent: $hdr" \
             -H "Accept: */*" \
             --connect-timeout 4 --max-time 12 --max-filesize 3145728 \
             -o "$tmp" "$url" 2>/dev/null; then
        rm -f "$tmp"
        return 0
    fi

    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        return 0
    fi

    if head -c 20 "$tmp" | grep -qE '^[[:space:]]*<(!doctype|html)'; then
        rm -f "$tmp"
        return 0
    fi

    mv "$tmp" "$out"
    host="${url#*://}"; host="${host%%/*}"
    printf '%s\t%s\t%s\n' "$hash" "$url" "$host" >> "$WORKDIR/results/js_map.tsv"

    {
        jsluice urls -f "$out" 2>/dev/null | jq -r '.url // empty' 2>/dev/null
        python3 "$LINKFINDER" -i "file://$out" -o cli 2>/dev/null | grep -vE '^(Usage:|Error:|\./)' || true
    } | awk -v h="$host" -v u="$url" -v OFS='\t' 'NF{print h,$0,u}' \
      >> "$WORKDIR/results/js_endpoints.tsv"

    grep -oE '[?&][a-zA-Z_][a-zA-Z0-9_]{1,30}=' "$out" 2>/dev/null \
        | tr -d '?&=' | sort -u >> "$WORKDIR/results/js_params.txt"
}
export -f download_js
export WORKDIR LINKFINDER BB_HEADER

if [ -s "$WORKDIR/results/js_urls.txt" ]; then
    xargs -r -P 8 -I{} bash -c 'download_js "$@"' _ {} \
        < "$WORKDIR/results/js_urls.txt" || true
fi

info "JS: $(find "$WORKDIR/js" -name '*.js' -type f | wc -l) files, $(wc -l < "$WORKDIR/results/js_endpoints.tsv") endpoints"

# ── SEVERITY: JS pattern analysis ─────────────────────────────────────
phase "Phase 4b" "JS severity patterns (mode=$JS_STRIP_MODE)"
if [ "$JS_STRIP_MODE" != "node" ]; then
    warn "node not found — stripper unavailable, JS severity will be noisy."
    warn "Install node for accurate ranking; results still produced but discounted."
fi

: > "$WORKDIR/results/js_severity_raw.tsv"
: > "$WORKDIR/results/js_severity.tsv"
: > "$WORKDIR/results/js_severity_high.tsv"

JS_PATTERN='(api[_-]?key|secret|token|password|passwd|authorization|bearer|eval\s*\(|new Function|innerHTML\s*=|outerHTML\s*=|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|setTimeout\s*\(\s*["'"'"']|setInterval\s*\(\s*["'"'"']|fetch\(|axios\.[a-z]+\(|XMLHttpRequest|/admin|/internal|/debug|/graphql|/upload|/rpc|/callback|/webhook|/proxy|/fetch|isAdmin|hasRole\s*\(|checkPermission|feature[_-]?flag|featureFlag|FEATURE_[A-Z_]+|__DEV__|isDev|DEBUG\s*[:=]|debug\s*[:=]\s*true|\?debug=|&debug=|__NEXT_DATA__|window\.__[A-Z_]+|enabled\s*[:=]\s*true)'

JS_INFRA_PATTERN='(s3[.-][A-Za-z0-9._-]+\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|gs://|(^|[^0-9])(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]+\.[0-9]+|eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----)'

find "$WORKDIR/js" -name '*.js' -type f -print0 | while IFS= read -r -d '' f; do
    strip_js "$f" 2>/dev/null \
    | grep -noE ".{0,40}${JS_PATTERN}.{0,40}" 2>/dev/null \
    | while IFS=: read -r lineno match; do
        ctx=$(printf '%s' "$match" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
        [ -z "$ctx" ] && continue
        printf '%s\t%s\t%s\t%s\n' "$ctx" "$f" "$lineno" "primary"
    done
done >> "$WORKDIR/results/js_severity_raw.tsv"

find "$WORKDIR/js" -name '*.js' -type f -print0 | while IFS= read -r -d '' f; do
    strip_js "$f" 2>/dev/null \
    | grep -noE ".{0,40}${JS_INFRA_PATTERN}.{0,40}" 2>/dev/null \
    | while IFS=: read -r lineno match; do
        ctx=$(printf '%s' "$match" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
        [ -z "$ctx" ] && continue
        printf '%s\t%s\t%s\t%s\n' "$ctx" "$f" "$lineno" "infra"
    done
done >> "$WORKDIR/results/js_severity_raw.tsv"

awk -F'\t' '!seen[$1]++' "$WORKDIR/results/js_severity_raw.tsv" \
    > "$WORKDIR/results/js_severity_dedup.tsv"

awk -F'\t' -v mode="$JS_STRIP_MODE" '
    {
        ctx   = $1
        file  = $2
        kind  = $4
        score = 1

        if (ctx ~ /eval\s*\(|new Function/)                    score += 4
        if (ctx ~ /fetch\(|axios\.[a-z]+\(|XMLHttpRequest/)    score += 3
        if (ctx ~ /\/admin|\/internal|\/debug/)                score += 2
        if (ctx ~ /\/graphql|\/upload/)                        score += 2
        if (ctx ~ /api[_-]?key|secret|token|password/)         score += 2

        if (ctx ~ /innerHTML\s*=|outerHTML\s*=|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML/) score += 4
        if (ctx ~ /isAdmin|hasRole\s*\(|checkPermission/)      score += 2
        if (ctx ~ /feature[_-]?flag|featureFlag|FEATURE_[A-Z_]+|__DEV__|isDev/) score += 1
        if (ctx ~ /DEBUG\s*[:=]|debug\s*[:=]\s*true|\?debug=|&debug=/) score += 1
        if (ctx ~ /__NEXT_DATA__|window\.__[A-Z_]+/)           score += 1

        if (kind == "infra") {
            if (ctx ~ /s3[.-][A-Za-z0-9._-]+\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|gs:\/\//) score += 4
            if (ctx ~ /(^|[^0-9])(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]+\.[0-9]+/) score += 3
            if (ctx ~ /eyJ[A-Za-z0-9_-]{10,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----/) score += 5
        }

        if (kind == "primary" && (ctx ~ /"[^"]{6,}"/ || ctx ~ /\x27[^\x27]{6,}\x27/)) score += 1

        if (ctx ~ /^[^a-zA-Z0-9_$]{0,5}$/)                     score -= 1
        if (ctx ~ /setTimeout\s*\(|setInterval\s*\(/)          score -= 1
        if (mode != "node")                                    score -= 1

        if (score < 1) score = 1
        print score "\t" $0
    }
' "$WORKDIR/results/js_severity_dedup.tsv" | sort -rn > "$WORKDIR/results/js_severity_ranked.tsv"

awk -F'\t' '$1 >= 5' "$WORKDIR/results/js_severity_ranked.tsv" \
    > "$WORKDIR/results/js_severity_high.tsv"

cp "$WORKDIR/results/js_severity_ranked.tsv" "$WORKDIR/results/js_severity.tsv"

info "JS severity: raw=$(wc -l < "$WORKDIR/results/js_severity_raw.tsv") dedup=$(wc -l < "$WORKDIR/results/js_severity_dedup.tsv") high=$(wc -l < "$WORKDIR/results/js_severity_high.tsv")"
# ── /SEVERITY ──────────────────────────────────────────────────────

# ── jshound: Runtime API discovery for SPAs ───────────────────────────
phase "Phase 4c" "jshound runtime API discovery"

JSHOUND_BIN=""
if command -v jshound >/dev/null 2>&1; then
    JSHOUND_BIN="jshound"
elif [ -f "$HOME/jshound/jshound/cli.py" ]; then
    JSHOUND_BIN="python3 -m jshound.cli"
    export PYTHONPATH="$HOME/jshound:$PYTHONPATH"
fi

if [ -n "$JSHOUND_BIN" ]; then
    : > "$WORKDIR/results/jshound_endpoints.tsv"
    JSHOUND_ROOT="$WORKDIR/results/jshound"
    mkdir -p "$JSHOUND_ROOT"

    JSHOUND_TARGETS=$(mktemp)
    while read -r host; do
        [ -z "$host" ] && continue
        case "$host" in
            api.*|*-api.*|api-*.*|*.api.*) continue ;;
        esac
        echo "$host"
    done < <(head -10 "$WORKDIR/results/priority_hosts.txt" 2>/dev/null) > "$JSHOUND_TARGETS"

    if [ ! -s "$JSHOUND_TARGETS" ]; then
        info "no HTML-serving hosts in priority list, skipping jshound"
    else
        info "jshound targets: $(wc -l < "$JSHOUND_TARGETS")"
        while read -r host; do
            [ -z "$host" ] && continue
            safe_host="${host//[:\/]/_}"
            out_dir="$JSHOUND_ROOT/$safe_host"

            info "[$host] jshound running (up to 300s)"
            timeout 300 bash -c "
                $JSHOUND_BIN -o '$out_dir' '$host' -q
            " 2>/dev/null || true

            endpoints_file="$out_dir/endpoints.txt"
            if [ -s "$endpoints_file" ]; then
                count=$(wc -l < "$endpoints_file")
                ok "[$host] jshound: $count endpoints"

                awk -v h="$host" -v OFS='\t' '
                    {
                        method = $1
                        url = $2
                        sub(/^https?:\/\/[^\/]+/, "", url)
                        if (url == "") url = "/"
                        print h, url, method, "", "jshound", "jshound_" h, "", ""
                    }
                ' "$endpoints_file" >> "$WORKDIR/results/jshound_endpoints.tsv"
            else
                info "[$host] jshound: no endpoints file produced"
            fi
        done < "$JSHOUND_TARGETS"
    fi
    rm -f "$JSHOUND_TARGETS"

    if [ -s "$WORKDIR/results/jshound_endpoints.tsv" ]; then
        cat "$WORKDIR/results/jshound_endpoints.tsv" >> "$WORKDIR/results/js_endpoints.tsv"
        info "jshound total: $(wc -l < "$WORKDIR/results/jshound_endpoints.tsv") endpoints"
    fi
else
    warn "jshound not found. Install with: cd ~/jshound && pip install -e ."
fi
# ── /jshound ──────────────────────────────────────────────────────────

# ---------------------------------------------------------------------
# Phase 5 — inventory (canonical 8-column layout, capped)
# ---------------------------------------------------------------------
phase "Phase 5" "Inventory"
{
    awk -F'\t' -v OFS='\t' '{
        ep=$2
        if (ep ~ /^https?:\/\//)      u=ep;
        else if (ep ~ /^\/\//)        u="https:" ep;
        else if (ep ~ /^\//)          u=$1 ep;
        else                          u=$1 "/" ep;
        h=u; sub(/^https?:\/\//,"",h); sub(/\/.*/,"",h);
        p=u; sub(/^https?:\/\/[^\/]+/,"",p); if(p=="") p="/";
        print h, p, "GET", "", "js", $3, "", ""
    }' "$WORKDIR/results/js_endpoints.tsv"
    cat "$WORKDIR/results/hist.txt" "$WORKDIR/results/katana.txt" 2>/dev/null \
    | grep -vE '\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webp)(\?|$)' \
    | awk -F'\t' -v OFS='\t' '{
        u=$0
        h=u; sub(/^https?:\/\//,"",h); sub(/\/.*/,"",h)
        p=u; sub(/^https?:\/\/[^\/]+/,"",p); if(p=="") p="/"
        print h, p, "GET", "", "url", "", "", ""
    }'
} | sort -u > "$WORKDIR/results/inventory.raw.tsv"

INV_CAP="${INV_CAP:-3000}"
HIGH_SIGNAL='(/api/|/v[0-9]+/|/admin|/internal|/management|/console|/dashboard|/auth|/login|/oauth|/token|/sso|/saml|/reset|/forgot|/verify|/graphql|/rpc|/upload|/execute|/eval|/import|/export|/report|/download|/webhook|/callback|/proxy|/fetch|[?&](id|user_?id|account_?id|order_?id|file_?id|doc_?id|item_?id|url|uri|redirect|callback|webhook|proxy|fetch|target|dest)=)'

{
    grep -E "$HIGH_SIGNAL" "$WORKDIR/results/inventory.raw.tsv" || true
    grep -vE "$HIGH_SIGNAL" "$WORKDIR/results/inventory.raw.tsv" | shuf || true
} | awk -F'\t' '!seen[$1 $2]++' | head -"$INV_CAP" \
    > "$WORKDIR/results/inventory.tsv"

RAW_INV=$(wc -l < "$WORKDIR/results/inventory.raw.tsv")
CAPPED_INV=$(wc -l < "$WORKDIR/results/inventory.tsv")
info "inventory: $RAW_INV raw -> $CAPPED_INV capped (INV_CAP=$INV_CAP)"

awk -F'\t' '{print $1 $2}' "$WORKDIR/results/inventory.tsv" | sort -u > "$WORKDIR/results/inv_urls.txt"

if [ -s "$WORKDIR/results/inv_urls.txt" ]; then
    : > "$WORKDIR/results/_inv_by_rate.txt"
    while read -r u; do
        h=$(_norm "$u")
        printf '%s\t%s\n' "$(rate_for_host "$h")" "$u" >> "$WORKDIR/results/_inv_by_rate.txt"
    done < "$WORKDIR/results/inv_urls.txt"
    sort -n "$WORKDIR/results/_inv_by_rate.txt" -o "$WORKDIR/results/_inv_by_rate.txt"

    : > "$WORKDIR/results/inv_live.jsonl"
    BUCKET_CAP="${BUCKET_CAP:-2000}"

    awk -F'\t' '{print $1}' "$WORKDIR/results/_inv_by_rate.txt" | uniq | while read -r bucket_rate; do
        awk -F'\t' -v r="$bucket_rate" '$1==r{print $2}' "$WORKDIR/results/_inv_by_rate.txt" \
            > "$WORKDIR/results/_ib.txt"
        [ -s "$WORKDIR/results/_ib.txt" ] || continue

        BUCKET_SIZE=$(wc -l < "$WORKDIR/results/_ib.txt")
        if [ "$BUCKET_SIZE" -gt "$BUCKET_CAP" ]; then
            head -"$BUCKET_CAP" "$WORKDIR/results/_ib.txt" > "$WORKDIR/results/_ib.capped.txt"
            mv "$WORKDIR/results/_ib.capped.txt" "$WORKDIR/results/_ib.txt"
            info "bucket rate=$bucket_rate: $BUCKET_SIZE -> $BUCKET_CAP (capped)"
        fi

        first_url=$(head -1 "$WORKDIR/results/_ib.txt")
        mapfile -t HDRS < <(header_args "$first_url")
        httpx -l "$WORKDIR/results/_ib.txt" -silent -mc 200,201,301,302,401,403,405 -json \
            -timeout 6 -retries 1 -threads 80 -rate-limit "$bucket_rate" \
            -tls-impersonate chrome \
            "${HDRS[@]}" "${BB_HEADER_ARGS[@]}" >> "$WORKDIR/results/inv_live.jsonl" || true
    done

    jq -r 'select(.status_code)|[.url,(.status_code|tostring)]|@tsv' \
        "$WORKDIR/results/inv_live.jsonl" 2>/dev/null > "$WORKDIR/results/url_status.tsv"
fi
info "live (HTTP status confirmed): $(wc -l < "$WORKDIR/results/url_status.tsv")"

# ---------------------------------------------------------------------
# Phase 5b — GraphQL introspection check
# ---------------------------------------------------------------------
if [ -s "$WORKDIR/results/url_status.tsv" ]; then
    phase "Phase 5b" "GraphQL introspection check"
    : > "$WORKDIR/results/critical_findings.txt"
    while IFS=$'\t' read -r url status; do
        [[ "$url" == *graphql* ]] || continue
        h=$(_norm "$url")
        _in_scope "$h" || continue
        resp=$(timeout 5 curl -s -X POST "$url" \
            -H 'Content-Type: application/json' \
            -d '{"query":"{ __schema { types { name } } }"}' 2>/dev/null)
        if printf '%s' "$resp" | jq -e '.data.__schema.types | length > 0' >/dev/null 2>&1; then
            echo "GRAPHQL_INTROSPECTION_LEAKED  $url" >> "$WORKDIR/results/critical_findings.txt"
            warn "GraphQL introspection leaked: $url"
        fi
    done < "$WORKDIR/results/url_status.tsv"
fi

{
    awk -F'\t' '{print $1}' "$WORKDIR/results/inventory.tsv" | sort -u | while read -r h; do
        printf '%s\t%s\t%s\n' "$h" "$(_decide "$h")" "$(tags_for_host "$h")"
    done
} > "$WORKDIR/results/_host_meta.tsv"

awk -F'\t' -v OFS='\t' '
    NR==FNR { scope[$1]=$2; tags[$1]=$3; next }
    {
        $7 = (($1 in scope) ? scope[$1] : "include")
        $8 = (($1 in tags)  ? tags[$1]  : "")
        print
    }
' "$WORKDIR/results/_host_meta.tsv" "$WORKDIR/results/inventory.tsv" \
    > "$WORKDIR/results/inventory.meta.tsv"
mv "$WORKDIR/results/inventory.meta.tsv" "$WORKDIR/results/inventory.tsv"

if [ -s "$WORKDIR/results/url_status.tsv" ]; then
    awk -F'\t' -v OFS='\t' '
        NR==FNR { st[$1]=$2; next }
        {
            url = $1 $2
            if (url in st) $4 = st[url]
            print
        }
    ' "$WORKDIR/results/url_status.tsv" "$WORKDIR/results/inventory.tsv" \
        > "$WORKDIR/results/inventory.status.tsv"
    mv "$WORKDIR/results/inventory.status.tsv" "$WORKDIR/results/inventory.tsv"
fi

# ── SSRF: OOB parameter probing ─────────────────────────────────────
# NEW: requires BOTH SSRF_COLLAB and ACTIVE_PROBE=1. SSRF_COLLAB alone
# only lists candidates — it does not fire live payloads. This is an
# active-testing phase, not passive recon; treat the double gate as
# deliberate, not a bug.
if [ -s "$WORKDIR/results/inventory.tsv" ] && budget_left; then
    phase "Phase 5c" "SSRF OOB probing"
    : > "$WORKDIR/results/ssrf_candidates.txt"

    awk -F'\t' '
        $1 $2 ~ /[?&](url|uri|src|dest|redirect|callback|webhook|proxy|fetch|target|link|path|image|load|file)=/ ||
        $2 ~ /(\/proxy|\/fetch|\/redirect|\/webhook|\/callback|\/import|\/preview|\/load)/
    ' "$WORKDIR/results/inventory.tsv" | head -20 > "$WORKDIR/results/ssrf_candidates.txt"

    COLLAB="${SSRF_COLLAB:-}"
    ACTIVE_PROBE="${ACTIVE_PROBE:-0}"

    if [ -n "$COLLAB" ] && [ "$ACTIVE_PROBE" = "1" ]; then
        while IFS=$'\t' read -r host path method status source src_file scope tags; do
            url="https://${host}${path}"
            param=$(printf '%s' "$path" | grep -oE '[?&][a-zA-Z_]+=' | head -1 | tr -d '?&=')
            [ -z "$param" ] && continue

            test_url="${url}${url:+&}${param}=http://${COLLAB}/ssrf-${host}"
            curl -s -o /dev/null --connect-timeout 5 "$test_url" 2>/dev/null || true
        done < "$WORKDIR/results/ssrf_candidates.txt"
        ok "Sent OOB payloads to $(wc -l < "$WORKDIR/results/ssrf_candidates.txt") candidates. Check $COLLAB for callbacks."
    elif [ -n "$COLLAB" ]; then
        info "$(wc -l < "$WORKDIR/results/ssrf_candidates.txt") SSRF candidates listed in ssrf_candidates.txt."
        info "SSRF_COLLAB is set but ACTIVE_PROBE!=1 — no payloads sent. Set ACTIVE_PROBE=1 to actually fire them."
    else
        info "SSRF_COLLAB not set. Candidates listed in ssrf_candidates.txt, no payloads sent."
        info "Set SSRF_COLLAB=your.interactsh.host AND ACTIVE_PROBE=1 to enable live OOB probing."
    fi
fi

# ---------------------------------------------------------------------
# Phase 6 — Verify existing inventory URLs
# ---------------------------------------------------------------------
if command -v httpx >/dev/null 2>&1 && budget_left; then
    phase "Phase 6" "Verify inventory URLs (httpx)"

    INV_URLS="$WORKDIR/results/inv_urls.txt"
    if [ -s "$INV_URLS" ]; then
        head -2500 "$INV_URLS" > "$WORKDIR/results/_verify_targets.txt"

        timeout 180 httpx -l "$WORKDIR/results/_verify_targets.txt" \
            -silent -sc -json \
            -mc 200,201,301,302,401,403,405 \
            -rate-limit 15 -threads 30 \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" \
            "${BB_HEADER_ARGS[@]}" \
            -o "$WORKDIR/results/verified_urls.jsonl" \
            2>/dev/null || true

        if [ -s "$WORKDIR/results/verified_urls.jsonl" ]; then
            jq -r 'select(.status_code) | [(.url // ""), (.status_code|tostring)] | @tsv' \
                "$WORKDIR/results/verified_urls.jsonl" 2>/dev/null \
            | awk -F'\t' -v OFS='\t' '{
                u=$1; status=$2
                h=u; sub(/^https?:\/\//,"",h); sub(/\/.*/,"",h)
                p=u; sub(/^https?:\/\/[^\/]+/,"",p); if(p=="") p="/"
                print h, p, "GET", status, "httpx", "", "", ""
            }' >> "$WORKDIR/results/inventory.tsv"
            sort -u "$WORKDIR/results/inventory.tsv" -o "$WORKDIR/results/inventory.tsv"
            info "httpx verified: $(wc -l < "$WORKDIR/results/verified_urls.jsonl") URLs"
        fi

        rm -f "$WORKDIR/results/_verify_targets.txt"
    else
        info "no inventory URLs to verify"
    fi
fi

awk -F'\t' -v OFS='\t' '
    NR==FNR { scope[$1]=$2; tags[$1]=$3; next }
    {
        $7 = (($1 in scope) ? scope[$1] : "include")
        $8 = (($1 in tags)  ? tags[$1]  : "")
        print
    }
' "$WORKDIR/results/_host_meta.tsv" "$WORKDIR/results/inventory.tsv" \
    > "$WORKDIR/results/inventory.meta2.tsv"
mv "$WORKDIR/results/inventory.meta2.tsv" "$WORKDIR/results/inventory.tsv"

# ── SEVERITY: endpoint severity ranking (after ffuf) ──────────────────
phase "Phase 6b" "Severity prioritization"
awk -F'\t' '{
    hp = $1 $2
    score = 0

    if (hp ~ /\/api\/.*\/(user|account|profile|order).*(\?.*id=|\/[0-9])/) score += 3
    if (hp ~ /(\/login|\/auth|\/oauth|\/authorize|\/token)/) score += 3
    if (hp ~ /(\/upload|\/execute|\/run|\/eval|\/import)/) score += 4
    if (hp ~ /(\/admin|\/management|\/console|\/internal)/) score += 3
    if (hp ~ /(\/graphql|\/rpc|\/api\/.*\?query)/) score += 2
    if (hp ~ /(\/webhook|\/callback|\/hook|\/fetch|\/proxy|\/url)/) score += 2
    if (hp ~ /(\/export|\/report|\/analytics|\/dump|\/backup|\/download)/) score += 2

    if ($4 ~ /^2/ && $1 $2 ~ /(\/admin|\/internal|\/management|\/console)/) score += 3
    if ($4 == "200" && $1 $2 ~ /(\/upload|\/execute)/) score += 3
    if ($4 == "200" && $1 $2 ~ /\/api\/.*\/(me|profile|account)/ && $1 $2 !~ /(login|register|signup|forgot|reset)/) score += 3
    if ($4 == "200" && $1 $2 ~ /(\/settings|\/preferences|\/history|\/billing|\/payment|\/invoices?|\/transactions?)/) score += 2
    if ($4 == "200" && $1 $2 ~ /(\/admin|\/internal|\/management|\/console|\/debug|\/upload|\/execute)/) score += 5

    if ($1 $2 ~ /\/[0-9]{4,}(\/|$|\?)/) score += 2
    if ($1 $2 ~ /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/) score += 2
    if ($1 $2 ~ /[?&](id|user_?id|account_?id|order_?id|file_?id|doc_?id|item_?id)=/) score += 1

    if ($1 $2 ~ /[?&](url|uri|src|dest|redirect|callback|webhook|proxy|fetch|target|link|path|image|load|file)=/) score += 3
    if ($1 $2 ~ /(\/proxy|\/fetch|\/redirect|\/webhook|\/callback|\/import|\/preview|\/load)/) score += 3

    if ($1 $2 ~ /(\/login|\/auth|\/oauth|\/token|\/sso|\/saml)/) score += 3
    if ($1 $2 ~ /(\/reset|\/forgot|\/verify|\/2fa|\/otp|\/mfa)/) score += 3
    if ($1 $2 ~ /(\/admin|\/dashboard|\/settings)/ && $4 == "200") score += 4

    if ($3 ~ /^(POST|PUT|PATCH)$/ && $1 $2 ~ /(\/user|\/profile|\/account|\/settings)/) score += 2

    if ($5 == "js") score += 1
    if ($5 == "jshound") score += 2
    if ($5 == "ffuf") score -= 1

    print score "\t" $0
}' "$WORKDIR/results/inventory.tsv" | sort -rn > "$WORKDIR/exports/severity_ranked.tsv"

head -20 "$WORKDIR/exports/severity_ranked.tsv" | cut -f2- \
    > "$WORKDIR/exports/priority_test_targets.tsv"
info "severity ranked: $(wc -l < "$WORKDIR/exports/severity_ranked.tsv"), top 20 exported"
# ── /SEVERITY ─────────────────────────────────────────────────────────

# ---------------------------------------------------------------------
# Phase 7 — secrets
# ---------------------------------------------------------------------
if command -v trufflehog >/dev/null 2>&1 && budget_left && [ "$(find "$WORKDIR/js" -name '*.js' | wc -l)" -gt 0 ]; then
    phase "Phase 7" "Secrets scan (trufflehog)"
    timeout 180 trufflehog filesystem "$WORKDIR/js/" --json --no-update \
        > "$WORKDIR/results/secrets.jsonl" 2>/dev/null || true
fi

grep -oE '\?[^ ]+' "$WORKDIR/results/hist.txt" 2>/dev/null \
    | tr '&' '\n' | cut -d= -f1 | tr -d '?' | sort -u > "$WORKDIR/results/params_hist.txt" || true
cat "$WORKDIR/results/js_params.txt" "$WORKDIR/results/params_hist.txt" 2>/dev/null \
    | sort -u > "$WORKDIR/results/params.txt"

# ---------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------
INV="$WORKDIR/results/inventory.tsv"

awk -F'\t' '{print $1 $2}' "$INV" | sort -u > "$WORKDIR/exports/urls.txt"

cp "$WORKDIR/results/params.txt" "$WORKDIR/exports/params.txt"

{
    echo "URL,Status,Source,Scope,Tags"
    awk -F'\t' -v OFS=',' '{
        url = $1 $2
        src = $5; scope = $7; tags = $8
        gsub(/"/,"\"\"", src); gsub(/"/,"\"\"", scope); gsub(/"/,"\"\"", tags)
        print url, $4, "\"" src "\"", scope, "\"" tags "\""
    }' "$INV"
} > "$WORKDIR/exports/endpoints.csv"

cp "$INV" "$WORKDIR/exports/inventory.tsv"

if [ -s "$WORKDIR/results/js_severity_ranked.tsv" ]; then
    cp "$WORKDIR/results/js_severity_ranked.tsv" \
       "$WORKDIR/exports/js_severity_ranked.tsv"
    cp "$WORKDIR/results/js_severity_high.tsv" \
       "$WORKDIR/exports/js_severity_high.tsv"
fi

if [ -s "$WORKDIR/results/jshound_endpoints.tsv" ]; then
    cp "$WORKDIR/results/jshound_endpoints.tsv" \
       "$WORKDIR/exports/jshound_endpoints.tsv"
fi

if [ -d "$WORKDIR/results/jshound" ]; then
    cp -r "$WORKDIR/results/jshound" \
          "$WORKDIR/exports/jshound_raw"
fi

: > "$WORKDIR/exports/api.txt";       : > "$WORKDIR/exports/admin.txt"
: > "$WORKDIR/exports/auth.txt";      : > "$WORKDIR/exports/high-value.txt"
awk -F'\t' '
    {
        hp = $1 $2
        t  = tolower($8); pl = tolower($2)
        if (t ~ /(^| )api( |$)/   || pl ~ /\/api\/|\/v[0-9]\//)               print hp > ("'"$WORKDIR"'/exports/api.txt")
        if (t ~ /(^| )admin( |$)/ || pl ~ /\/admin|\/dashboard|\/console/)    print hp > ("'"$WORKDIR"'/exports/admin.txt")
        if (t ~ /(^| )auth( |$)/  || pl ~ /\/login|\/auth|\/oauth|\/token/)   print hp > ("'"$WORKDIR"'/exports/auth.txt")
        if (t ~ /high-value/ || t ~ /(^| )primary( |$)/)                      print hp > ("'"$WORKDIR"'/exports/high-value.txt")
    }
' "$INV"

{
    echo "Score,URL,Status,Source,Scope,Tags"
    awk -F'\t' -v OFS=',' '{
        score  = $1
        url    = $2 $3
        status = $5
        src    = $6
        scope  = $8
        tags   = $9
        gsub(/"/,"\"\"", src); gsub(/"/,"\"\"", scope); gsub(/"/,"\"\"", tags)
        print score, url, status, "\"" src "\"", scope, "\"" tags "\""
    }' "$WORKDIR/exports/severity_ranked.tsv"
} > "$WORKDIR/exports/severity_endpoints.csv"

awk -F'\t' '$1 >= 5 && $5 == "200" && $3 ~ /(\/admin|\/api|\/upload|\/execute|\/debug|graphql)/' \
    "$WORKDIR/exports/severity_ranked.tsv" \
    > "$WORKDIR/exports/quick_wins.tsv"

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
ELAPSED=$(( $(date +%s) - START_EPOCH ))
cat <<EOF

$C_PHASE============================================$C_RESET
  Severity recon v3.7 complete: $TARGET
  Elapsed: ${ELAPSED}s
  Work dir: $WORKDIR/
$C_PHASE============================================$C_RESET
  Hosts:         $(wc -l < "$WORKDIR/results/live.txt" 2>/dev/null || echo 0)
  Priority:      $(wc -l < "$WORKDIR/results/priority_hosts.txt" 2>/dev/null || echo 0)
  Endpoints:     $(wc -l < "$INV" 2>/dev/null || echo 0)
  Live check:    $(wc -l < "$WORKDIR/results/url_status.tsv" 2>/dev/null || echo 0)
  Params:        $(wc -l < "$WORKDIR/results/params.txt" 2>/dev/null || echo 0)
  OSINT sources enabled: ${OSINT_SOURCES:-none}

  Severity artifacts:
    $WORKDIR/results/hosts_ranked.tsv           (score<TAB>host)
    $WORKDIR/results/priority_hosts.txt         (score >= 3, floor 10)
    $WORKDIR/results/js_severity_ranked.tsv     (score<TAB>ctx<TAB>file<TAB>line<TAB>kind)
    $WORKDIR/results/js_severity_high.tsv       (score >= 5)
    $WORKDIR/exports/severity_ranked.tsv        (score<TAB>host<TAB>path<TAB>...)
    $WORKDIR/exports/priority_test_targets.tsv  (top 20, test these first)
    $WORKDIR/exports/severity_endpoints.csv     (Score,URL,Status,Source,Scope,Tags)
    $WORKDIR/exports/js_severity_ranked.tsv     (full JS findings)
    $WORKDIR/exports/js_severity_high.tsv       (high-confidence JS findings)
    $WORKDIR/results/jshound_endpoints.tsv      (SPA endpoints from jshound)
    $WORKDIR/exports/jshound_endpoints.tsv      (full jshound findings)
    $WORKDIR/exports/jshound_raw/               (jshound raw: openapi.json, requests.jsonl)
    $WORKDIR/exports/quick_wins.tsv             (high-score + 200 + sensitive path)
    $WORKDIR/results/critical_findings.txt      (GraphQL introspection leaks, if any)
    $WORKDIR/results/ssrf_candidates.txt        (SSRF candidates — payloads only sent if ACTIVE_PROBE=1)

  Exports:
    $WORKDIR/exports/urls.txt
    $WORKDIR/exports/params.txt
    $WORKDIR/exports/endpoints.csv
    $WORKDIR/exports/inventory.tsv     (host,path,method,status,source,source_file,scope,tags)
    $WORKDIR/exports/api.txt
    $WORKDIR/exports/admin.txt
    $WORKDIR/exports/auth.txt
    $WORKDIR/exports/high-value.txt

  Testing order:
    1. priority_test_targets.tsv          — unauth admin/internal, IDOR, upload
    2. severity_ranked.tsv (score >= 3)   — auth bypass, GraphQL, SSRF, exfil
    3. js_severity_high.tsv               — high-confidence JS leads (score >= 5)
    4. js_severity_ranked.tsv (score 3-4) — medium-confidence review
    5. jshound_endpoints.tsv              — SPA endpoints from runtime discovery
    6. api.txt / auth.txt                 — authorization boundary checks
$C_PHASE============================================$C_RESET
EOF
