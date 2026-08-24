
#!/bin/bash
#
set -o pipefail

# count_lines: safe line counter that doesn't blow up on missing/empty files
count_lines() {
    if [ -f "$1" ] && [ -s "$1" ]; then
        wc -l < "$1"
    else
        echo 0
    fi
}

TARGET="$1"
RATE_LIMIT="7"
WORKDIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"
THREADS=20
CONCURRENT=10

# --- Paths -----------------------------------------------------------
export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:$PATH"
LINKFINDER="$HOME/LinkFinder/linkfinder.py"
KITERUNNER_DICT="$HOME/wordlists/routes-large.kite"
SECLISTS="$HOME/SecLists"

# Specific wordlists for tools
WEB_CONTENT_WORDLIST="$SECLISTS/Discovery/Web-Content/raft-large-directories.txt"
WEB_FILES_WORDLIST="$SECLISTS/Discovery/Web-Content/raft-large-files.txt"
API_WORDLIST="$SECLISTS/Discovery/Web-Content/api/common.txt"

RESOLVERS="$HOME/resolvers.txt"
BB_HEADER="X-Synack:"

# --- Setup -----------------------------------------------------------
mkdir -p "$WORKDIR"/{js_files,results,logs,screenshots,exports}
LOGFILE="$WORKDIR/logs/pipeline.log"
exec > >(tee -a "$LOGFILE") 2>&1

if [ ! -f "$RESOLVERS" ]; then
    echo "[*] Downloading fresh resolvers.txt..."
    curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o "$RESOLVERS"
fi

# --- Tool checks (split required / optional) -------------------------

echo "[*] Checking tools..."
REQUIRED="curl jq httpx python3 gau katana waybackurls subfinder"
OPTIONAL="trufflehog gowitness arjun ffuf kr js-beautify getjs puredns amass"
for tool in $REQUIRED; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[!] REQUIRED missing: $tool"; exit 1; }
done
for tool in $OPTIONAL; do
    command -v "$tool" >/dev/null 2>&1 || echo "[!] Optional missing: $tool (phase will be skipped)"
done

# ---------- Phase 0: Baseline (with bug bounty header) ---------------
echo "[Phase 0] Baseline"

for i in {1..3}; do
    curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" -H "$BB_HEADER" "https://$TARGET/api/health" || true
done

# ---------- Phase 1: Asset Discovery ---------------------------------

#   subfinder + amass -> merge -> puredns/httpx resolve -> httpx probe -> live_webservers.txt
echo "[Phase 1] Subdomain enumeration & resolution"
subfinder -d "$TARGET" -o "$WORKDIR/results/subdomains.txt" -silent
if [ ! -s "$WORKDIR/results/subdomains.txt" ]; then
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$WORKDIR/results/subdomains.txt"
fi

if command -v amass >/dev/null 2>&1; then
    amass enum \
        -passive \
        -d "$TARGET" \
        -o "$WORKDIR/results/amass_subdomains.txt" \
        2>/dev/null

    cat "$WORKDIR/results/amass_subdomains.txt" >> "$WORKDIR/results/subdomains.txt"
    sort -u "$WORKDIR/results/subdomains.txt" -o "$WORKDIR/results/subdomains.txt"
    echo "   amass found: $(count_lines "$WORKDIR/results/amass_subdomains.txt")"
fi

echo "   subdomains: $(count_lines "$WORKDIR/results/subdomains.txt")"

if command -v puredns >/dev/null 2>&1; then
    puredns resolve "$WORKDIR/results/subdomains.txt" -r "$RESOLVERS" --write "$WORKDIR/results/resolved.txt"
else
    httpx -l "$WORKDIR/results/subdomains.txt" -silent -o "$WORKDIR/results/resolved.txt" -H "$BB_HEADER"
fi
[ -s "$WORKDIR/results/resolved.txt" ] || { echo "[!] No hosts resolved. Exiting."; exit 1; }
echo "   resolved: $(count_lines "$WORKDIR/results/resolved.txt")"

echo "[*] Live HTTP services"
httpx -l "$WORKDIR/results/resolved.txt" -silent -o "$WORKDIR/results/live_webservers.txt" -timeout 10 -rate-limit "$RATE_LIMIT" -H "$BB_HEADER"
[ -s "$WORKDIR/results/live_webservers.txt" ] || { echo "[!] No HTTP services. Exiting."; exit 1; }
echo "   live hosts: $(count_lines "$WORKDIR/results/live_webservers.txt")"

# if command -v gowitness &>/dev/null; then
#    gowitness scan file -f "$WORKDIR/results/live_webservers.txt" --screenshot-path "$WORKDIR/screenshots/"
#    echo "[*] Screenshots saved"
#fi

# ---------- Phase 2: JS Discovery ------------------------------------
echo "[Phase 2] JS & historical URL collection"
gau "$TARGET" > "$WORKDIR/results/gau_urls.txt"
waybackurls "$TARGET" >> "$WORKDIR/results/gau_urls.txt"
sort -u "$WORKDIR/results/gau_urls.txt" -o "$WORKDIR/results/gau_urls.txt"

katana -list "$WORKDIR/results/live_webservers.txt" -jc -kf all -silent -o "$WORKDIR/results/katana_urls.txt" -H "$BB_HEADER"

grep -E '\.js(\?|$)' "$WORKDIR/results/gau_urls.txt" > "$WORKDIR/results/js_urls_historical.txt"
grep -E '\.js(\?|$)' "$WORKDIR/results/katana_urls.txt" >> "$WORKDIR/results/js_urls_historical.txt"
# After katana crawl, before generic getjs
echo "[*] Prioritized live host scanning"

# Extract top candidates from live hosts (hosts with common API/service patterns)
PRIORITY_HOSTS=$(grep -iE '(api|cdn|static|internal|streaming|agent|cashier|payment|auth|admin|app|web|mobile)' "$WORKDIR/results/live_webservers.txt" | head -10)

if [ -n "$PRIORITY_HOSTS" ]; then
    while read -r host; do
        echo "[*] Extracting JS from: $host"

        if command -v getjs >/dev/null 2>&1; then
            safe_host=$(echo "$host" | sed 's|https\?://||' | tr '/:' '_')
            getjs -url "$host" --timeout 10 --output "$WORKDIR/results/getjs_${safe_host}.txt" 2>/dev/null
            [ -s "$WORKDIR/results/getjs_${safe_host}.txt" ] && cat "$WORKDIR/results/getjs_${safe_host}.txt" >> "$WORKDIR/results/js_urls_historical.txt"
        fi

        (( $(jobs -r | wc -l) >= 3 )) && wait -n
    done <<< "$PRIORITY_HOSTS"
    wait
    echo "   Priority host JS extraction complete"
fi

# Then fall back to generic target scan
if command -v getjs >/dev/null 2>&1; then
    getjs -url "https://$TARGET" --timeout 10 --output "$WORKDIR/results/js_urls_getjs.txt"
    [ -s "$WORKDIR/results/js_urls_getjs.txt" ] && cat "$WORKDIR/results/js_urls_getjs.txt" >> "$WORKDIR/results/js_urls_historical.txt"
fi

if command -v getjs >/dev/null 2>&1; then
    getjs -url "https://$TARGET" --timeout 10 --output "$WORKDIR/results/js_urls_getjs.txt"
    cat "$WORKDIR/results/js_urls_getjs.txt" >> "$WORKDIR/results/js_urls_historical.txt"
fi

sort -u "$WORKDIR/results/js_urls_historical.txt" -o "$WORKDIR/results/js_urls_all_prefilter.txt"
echo "   JS URLs before filtering: $(count_lines "$WORKDIR/results/js_urls_all_prefilter.txt")"

# JS pre-validation: confirm content-type before we bother downloading
cat "$WORKDIR/results/js_urls_all_prefilter.txt" | \
httpx \
    -silent \
    -mc 200,304 \
    -jc \
    -timeout 8 \
    -rate-limit "$RATE_LIMIT" \
    -H "$BB_HEADER" \
    -o "$WORKDIR/results/js_urls_validated.txt"

grep -iE 'javascript|ecmascript|text/js|application/x-js' \
    "$WORKDIR/results/js_urls_validated.txt" | \
awk '{print $1}' \
    > "$WORKDIR/results/js_urls_all.txt"

echo "   Valid JS URLs: $(count_lines "$WORKDIR/results/js_urls_all.txt")"

# Improved JS downloader: hash fallback chain, size cap, status+content validation
download_js() {
    local url="$1"

    if command -v md5sum >/dev/null 2>&1; then
        hash=$(echo -n "$url" | md5sum | cut -d' ' -f1)
    elif command -v md5 >/dev/null 2>&1; then
        hash=$(echo -n "$url" | md5)
    else
        hash=$(echo -n "$url" | sha256sum | cut -c1-16)
    fi

    output="$WORKDIR/js_files/${hash}.js"

    [ -s "$output" ] && return

    code=$(curl \
        -s \
        -L \
        -H "$BB_HEADER" \
        --max-time 10 \
        --max-filesize 5242880 \
        -w "%{http_code}" \
        -o "$output" \
        "$url")

    if [ "$code" != "200" ] || [ ! -s "$output" ]; then
        rm -f "$output"
    fi
}
export -f download_js

MAX_JOBS=20
while read -r url; do
    download_js "$url" &
    (( $(jobs -r | wc -l) >= MAX_JOBS )) && wait -n
done < "$WORKDIR/results/js_urls_all.txt"
wait
echo "   downloaded: $(find "$WORKDIR/js_files" -name "*.js" | wc -l) files"

if command -v js-beautify >/dev/null 2>&1; then
    # nullglob fix: avoids the loop running once on a literal "*.js" if the dir is empty
    shopt -s nullglob
    for file in "$WORKDIR/js_files"/*.js; do
        readable=$(grep -oE '[a-zA-Z_][a-zA-Z0-9_]{20,}' "$file" | wc -l)
        if [ "$readable" -lt 10 ]; then
            js-beautify "$file" -o "${file%.js}_beautified.js" 2>/dev/null
        else
            cp "$file" "${file%.js}_beautified.js"
        fi
    done
    shopt -u nullglob
    echo "   beautified: $(find "$WORKDIR/js_files" -name "*_beautified.js" | wc -l)"
fi

# ---------- Phase 2b: API Schema & GraphQL Discovery from JS --------
echo "[Phase 2b] Extracting API schemas from JS"

> "$WORKDIR/results/api_schema_refs.txt"
> "$WORKDIR/results/graphql_refs.txt"
> "$WORKDIR/results/swagger_refs.txt"
> "$WORKDIR/results/api_endpoints_from_js.txt"

shopt -s nullglob
for file in "$WORKDIR/js_files"/*_beautified.js; do

    # GraphQL endpoint references
    # Matches: graphql, apollo, gql, introspection, __schema, subscription
    grep -oiE '(graphql|apollo|gql)["\x27:\s/=]*["\x27]?https?://[^"\x27\s]+|graphql["\x27:\s/=]*["\x27](https?://)?[^"\x27\s]+' "$file" | \
        sed 's/.*\(https\?:\/\/[^"\x27\s]*\).*/\1/' | \
        grep -E 'https?://' >> "$WORKDIR/results/graphql_refs.txt" || true

    grep -iE '(__schema|__typename|introspection|subscription.*graphql)' "$file" >> "$WORKDIR/results/graphql_refs.txt" || true

    # Swagger/OpenAPI references
    grep -oiE '(swagger|openapi)["\x27:\s/=]*["\x27]?(https?://)?[^"\x27\s;,]+' "$file" | \
        sed 's/.*\(https?:\/\/[^"\x27\s]*\).*/\1/' | \
        grep -E 'https?://' >> "$WORKDIR/results/swagger_refs.txt" || true

    grep -iE '(swagger\.json|openapi\.json|api-docs|swagger\.yaml)' "$file" >> "$WORKDIR/results/swagger_refs.txt" || true

    # Generic API schema/documentation endpoints
    grep -oiE '(https?://[^"\x27\s]+/(swagger|openapi|graphql|api-docs|schema|documentation))' "$file" >> "$WORKDIR/results/api_schema_refs.txt" || true

    # API version patterns (e.g., /api/v1, /v2/users, /rest/api/v1)
    grep -oiE '(https?://[^"\x27\s]+/[a-z]*/?v[0-9]+(/[a-z]+)?)' "$file" | \
        head -5 >> "$WORKDIR/results/api_endpoints_from_js.txt" || true

done

shopt -u nullglob

# Clean & deduplicate
for file in "$WORKDIR/results/graphql_refs.txt" "$WORKDIR/results/swagger_refs.txt" "$WORKDIR/results/api_schema_refs.txt" "$WORKDIR/results/api_endpoints_from_js.txt"; do
    if [ -f "$file" ]; then
        sort -u "$file" -o "$file"
        sed -i '/^$/d' "$file"  # Remove empty lines
    fi
done

echo "   GraphQL references: $(count_lines "$WORKDIR/results/graphql_refs.txt")"
echo "   Swagger references: $(count_lines "$WORKDIR/results/swagger_refs.txt")"
echo "   API schema endpoints: $(count_lines "$WORKDIR/results/api_schema_refs.txt")"
echo "   Versioned APIs: $(count_lines "$WORKDIR/results/api_endpoints_from_js.txt")"

# Probe found references (actual URLs from JS)
if [ -s "$WORKDIR/results/api_schema_refs.txt" ]; then
    cat "$WORKDIR/results/api_schema_refs.txt" | \
    httpx -silent -mc 200,401,403 -timeout 8 -rate-limit "$RATE_LIMIT" -H "$BB_HEADER" \
        -o "$WORKDIR/results/api_schema_live.txt"
    echo "   Live schema endpoints: $(count_lines "$WORKDIR/results/api_schema_live.txt")"
fi

# GraphQL introspection on found endpoints
if [ -s "$WORKDIR/results/api_schema_live.txt" ]; then
    while read -r url; do
        if echo "$url" | grep -qi graphql; then
            echo "[*] GraphQL introspection: $url"
            curl -s -X POST "$url" \
                -H "Content-Type: application/json" \
                -H "$BB_HEADER" \
                -d '{"query":"query{__schema{queryType{name}mutationType{name}subscriptionType{name}}}"}' 2>/dev/null | \
                jq '.' >> "$WORKDIR/results/graphql_introspection.json" 2>/dev/null
        fi
    done < "$WORKDIR/results/api_schema_live.txt"
fi

# TruffleHog (optional)
if command -v trufflehog >/dev/null 2>&1; then
    trufflehog filesystem "$WORKDIR/js_files/" --json > "$WORKDIR/results/trufflehog.json"
    echo "   TruffleHog candidates: $(count_lines "$WORKDIR/results/trufflehog.json")"
fi
if [ -f "$HOME/DumpsterDiver/DumpsterDiver.py" ]; then
    python3 "$HOME/DumpsterDiver/DumpsterDiver.py" -p "$WORKDIR/js_files/" --json > "$WORKDIR/results/dumpsterdiver.json" 2>/dev/null
    echo "   DumpsterDiver run"
fi

# ---------- Phase 3: Endpoint Extraction -----------------------------
echo "[Phase 3] Endpoint extraction"

# JSluice (hardened: || true so one bad file doesn't kill the loop)
find "$WORKDIR/js_files/" \
    -name "*_beautified.js" \
    -type f | \
while read -r f; do
    jsluice urls -f "$f" 2>/dev/null | \
        jq -r '.url // empty' \
        >> "$WORKDIR/results/endpoints_jsluice.txt" || true
done
sort -u "$WORKDIR/results/endpoints_jsluice.txt" -o "$WORKDIR/results/endpoints_jsluice.txt"
echo "   JSluice: $(count_lines "$WORKDIR/results/endpoints_jsluice.txt")"

# LinkFinder
find "$WORKDIR/js_files/" -name "*_beautified.js" | while read -r f; do
    python3 "$LINKFINDER" -i "file://$f" -o cli >> "$WORKDIR/results/endpoints_linkfinder.txt" 2>/dev/null
done
sort -u "$WORKDIR/results/endpoints_linkfinder.txt" -o "$WORKDIR/results/endpoints_linkfinder.txt"
echo "   LinkFinder: $(count_lines "$WORKDIR/results/endpoints_linkfinder.txt")"

# GAU endpoints (fixed: proper char-class quoting + strips static asset extensions)
grep -Eo 'https?://[^/]+(/[^"'\''[:space:]]*)' "$WORKDIR/results/gau_urls.txt" | \
sed -E 's|https?://[^/]*||g' | \
grep -vE '\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf)$' | \
sort -u \
    > "$WORKDIR/results/endpoints_gau.txt"
echo "   GAU endpoints: $(count_lines "$WORKDIR/results/endpoints_gau.txt")"

# Merge
cat "$WORKDIR/results/endpoints_jsluice.txt" "$WORKDIR/results/endpoints_linkfinder.txt" "$WORKDIR/results/endpoints_gau.txt" | \
    sort -u | grep -v "^#" | grep -v "^//" | grep -E "^/[a-zA-Z0-9/_\-\.]+" > "$WORKDIR/results/endpoints_merged.txt"
echo "   merged: $(count_lines "$WORKDIR/results/endpoints_merged.txt")"

# Kiterunner (kr, optional)
if command -v kr >/dev/null 2>&1 && [ -f "$KITERUNNER_DICT" ]; then
    while read -r host; do
        kr scan "$host" -w "$KITERUNNER_DICT" -x 10 -H "$BB_HEADER" --output "$WORKDIR/results/kr_${host//[:\/]/_}.txt" 2>/dev/null
        grep -Eo '/[a-zA-Z0-9/_\-]+' "$WORKDIR/results/kr_${host//[:\/]/_}.txt" >> "$WORKDIR/results/endpoints_merged.txt"
    done < "$WORKDIR/results/live_webservers.txt"
    sort -u "$WORKDIR/results/endpoints_merged.txt" -o "$WORKDIR/results/endpoints_merged.txt"
    echo "   after Kiterunner: $(count_lines "$WORKDIR/results/endpoints_merged.txt")"
fi

# httpx validation (endpoint-aware URL construction fix — prevents
# "https://site.comhttps://api.site.com/users"-style mangled URLs:
# absolute endpoints pass through untouched, relative ones get prefixed per host)
echo "[*] httpx validation"
{
while read -r endpoint; do
    if echo "$endpoint" | grep -q '^https\?://'; then
        echo "$endpoint"
    else
        while read -r host; do
            echo "${host}${endpoint}"
        done < "$WORKDIR/results/live_webservers.txt"
    fi
done < "$WORKDIR/results/endpoints_merged.txt"
} | sort -u | \
httpx \
    -silent \
    -mc 200,201,301,302,401,403 \
    -sc \
    -timeout 8 \
    -rate-limit "$RATE_LIMIT" \
    -H "$BB_HEADER" \
    -o "$WORKDIR/results/live_endpoints.txt"
echo "   validated: $(count_lines "$WORKDIR/results/live_endpoints.txt")"

# Extract 403 endpoints (bracket format)
grep '\[403\]' "$WORKDIR/results/live_endpoints.txt" | awk '{print $1}' > "$WORKDIR/results/endpoints_403.txt"
echo "   403 endpoints: $(count_lines "$WORKDIR/results/endpoints_403.txt")"

# bypass-403 & nomore403
if command -v bypass-403 >/dev/null 2>&1 && [ -s "$WORKDIR/results/endpoints_403.txt" ]; then
    while read -r url; do
        bypass-403 -u "$url" >> "$WORKDIR/results/bypass_403_results.txt" 2>/dev/null
    done < "$WORKDIR/results/endpoints_403.txt"
    echo "[*] bypass-403 completed"
fi
if command -v nomore403 >/dev/null 2>&1 && [ -s "$WORKDIR/results/endpoints_403.txt" ]; then
    while read -r url; do
        nomore403 -u "$url" >> "$WORKDIR/results/nomore403_results.txt" 2>/dev/null
    done < "$WORKDIR/results/endpoints_403.txt"
    echo "[*] nomore403 completed"
fi

# ffuf on interesting subs (with BB header) - Parallel dir & file discovery
# NOTE: kept as-is intentionally. No GNU Parallel, no concurrency rewrite —
# the existing background-job + wait -n pattern is left untouched.
if command -v ffuf >/dev/null 2>&1; then
    grep -iE 'admin|api|internal|dev|staging' "$WORKDIR/results/live_webservers.txt" | while read -r host; do
        # Directory discovery
        ffuf -u "$host/FUZZ" -w "$WEB_CONTENT_WORDLIST" \
            -t 5 -rate "$RATE_LIMIT" -mc 200,301,302,401,403 \
            -H "$BB_HEADER" \
            -o "$WORKDIR/results/ffuf_dirs_${host//[:\/]/_}.json" -of json -s &

        # File discovery (parallel)
        ffuf -u "$host/FUZZ" -w "$WEB_FILES_WORDLIST" \
            -t 5 -rate "$RATE_LIMIT" -mc 200,301,302,401,403 \
            -H "$BB_HEADER" \
            -o "$WORKDIR/results/ffuf_files_${host//[:\/]/_}.json" -of json -s &

        # Limit concurrent jobs
        (( $(jobs -r | wc -l) >= 10 )) && wait -n
    done
    wait  # Wait for all remaining jobs
    echo "[*] ffuf (directories & files) completed"
fi

# ---------- Phase 4: Parameter Extraction ----------------------------
echo "[Phase 4] Parameter extraction"
for file in "$WORKDIR/js_files/"*_beautified.js; do
    grep -oE '\?[a-zA-Z_][a-zA-Z0-9_]*=' "$file" | cut -d'=' -f1 | cut -d'?' -f2 >> "$WORKDIR/results/js_params_query.txt"
    grep -oE ':\s*"[a-zA-Z_][a-zA-Z0-9_]*"' "$file" | cut -d'"' -f2 >> "$WORKDIR/results/js_params_json.txt"
    grep -oE 'name=["\x27][a-zA-Z_][a-zA-Z0-9_]*["\x27]' "$file" | cut -d'"' -f2 | cut -d"'" -f2 >> "$WORKDIR/results/js_params_form.txt"
done
cat "$WORKDIR/results/js_params_*.txt" | sort -u > "$WORKDIR/results/js_parameters_all.txt"
echo "   static params: $(count_lines "$WORKDIR/results/js_parameters_all.txt")"

# ParamSpider (added)
if [ -d "$HOME/ParamSpider" ]; then
    while read -r host; do
        cleanhost=$(echo "$host" | \
            sed 's|https\?://||' | \
            cut -d/ -f1)

        python3 \
            "$HOME/ParamSpider/paramspider.py" \
            --domain "$cleanhost" \
            --output \
            "$WORKDIR/results/paramspider_${cleanhost}.txt" &

        (( $(jobs -r | wc -l) >= 3 )) && wait -n
    done < "$WORKDIR/results/live_webservers.txt"

    wait
    echo "[*] ParamSpider complete"
fi

# Arjun on API endpoints (optional, with header)
if command -v arjun >/dev/null 2>&1; then
    awk '{print $1}' "$WORKDIR/results/live_endpoints.txt" | grep -E '/api/|/v[0-9]/' | head -20 > "$WORKDIR/results/arjun_targets.txt"
    while read -r url; do
        outfile="$WORKDIR/results/arjun_$(echo -n "$url" | md5sum | cut -d' ' -f1).json"
        arjun -u "$url" -t "$THREADS" --delay 1 -o "$outfile" -q --headers "$BB_HEADER"
        [ -s "$outfile" ] && echo "   arjun success: $url" || echo "   arjun no output: $url"
    done < "$WORKDIR/results/arjun_targets.txt"
fi

# ---------- Phase 5 / Phase 6: intentionally omitted ------------------
# Corsy (Phase 5) and Gobuster/BBOT (Phase 6) were excluded from this merge
# per request. Numbering jumps straight to the semantic analysis phase below
# (kept as "Phase 7" to match the original script's labeling).

# ---------- Phase 7: Semantic Analysis (API patterns) ---------------
echo "[Phase 7] Semantic analysis"
python3 - <<PYEOF

import glob
import json
import re
from collections import defaultdict

patterns = defaultdict(list)

for f in glob.glob("$WORKDIR/js_files/*_beautified.js"):

    try:

        with open(
            f,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as fh:
            c = fh.read()

        patterns["fetch"].extend(
            re.findall(
                r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
                c
            )
        )

        patterns["http_method"].extend(
            re.findall(
                r"(?:axios|http)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
                c
            )
        )

        patterns["xhr"].extend([
            f"{m} {e}"
            for m, e in re.findall(
                r"open\s*\(\s*['\"]([A-Z]+)['\"],\s*['\"]([^'\"]+)['\"]",
                c
            )
        ])

    except Exception:
        pass

with open(
    "$WORKDIR/results/api_patterns.json",
    "w"
) as fp:

    json.dump(
        {k: list(set(v)) for k, v in patterns.items()},
        fp,
        indent=2
    )

print("[*] API patterns saved")

PYEOF

# ---------- Export Formatting (for Burp) -----------------------------
echo "[*] Generating Burp-ready exports"

# Export 1: All live endpoints (ready for Burp Intruder)
awk '{print $1}' "$WORKDIR/results/live_endpoints.txt" | sed -E 's|https?://[^/]*||g' | sort -u > "$WORKDIR/exports/burp_endpoints.txt"
echo "   Burp endpoints: $WORKDIR/exports/burp_endpoints.txt ($(count_lines "$WORKDIR/exports/burp_endpoints.txt") paths)"

# Export 2: Parameterized endpoints for Burp Intruder
while IFS= read -r endpoint; do
    while IFS= read -r param; do
        # Determine if endpoint already has params
        if [[ "$endpoint" == *"?"* ]]; then
            echo "${endpoint}&${param}=FUZZ"
        else
            echo "${endpoint}?${param}=FUZZ"
        fi
    done < "$WORKDIR/results/js_parameters_all.txt"
done < "$WORKDIR/exports/burp_endpoints.txt" | head -1000 > "$WORKDIR/exports/burp_parameterized.txt"
echo "   Parameterized requests: $WORKDIR/exports/burp_parameterized.txt ($(count_lines "$WORKDIR/exports/burp_parameterized.txt") requests)"

# Export 3: Interesting endpoints by category
echo "[*] Categorizing interesting endpoints"
> "$WORKDIR/exports/interesting_api.txt"
> "$WORKDIR/exports/interesting_admin.txt"
> "$WORKDIR/exports/interesting_auth.txt"
> "$WORKDIR/exports/interesting_config.txt"

while read -r endpoint; do
    if echo "$endpoint" | grep -qiE '/api/|/v[0-9]/|/graphql|/swagger'; then
        echo "$endpoint" >> "$WORKDIR/exports/interesting_api.txt"
    fi
    if echo "$endpoint" | grep -qiE '/admin|/dashboard|/console|/manager'; then
        echo "$endpoint" >> "$WORKDIR/exports/interesting_admin.txt"
    fi
    if echo "$endpoint" | grep -qiE '/login|/auth|/oauth|/token|/session'; then
        echo "$endpoint" >> "$WORKDIR/exports/interesting_auth.txt"
    fi
    if echo "$endpoint" | grep -qiE '/config|/debug|/status|/info|/health'; then
        echo "$endpoint" >> "$WORKDIR/exports/interesting_config.txt"
    fi
done < "$WORKDIR/exports/burp_endpoints.txt"

for cat in api admin auth config; do
    if [ -s "$WORKDIR/exports/interesting_${cat}.txt" ]; then
        echo "   ${cat}: $(count_lines "$WORKDIR/exports/interesting_${cat}.txt") endpoints"
    fi
done

# Export 4: Secrets and sensitive data
if [ -f "$WORKDIR/results/trufflehog.json" ] && [ -s "$WORKDIR/results/trufflehog.json" ]; then
    jq -r '.Raw // empty' "$WORKDIR/results/trufflehog.json" | sort -u > "$WORKDIR/exports/secrets_trufflehog.txt" 2>/dev/null
    echo "   Secrets: $WORKDIR/exports/secrets_trufflehog.txt"
fi

# Export 5: Full endpoint summary (CSV)
echo "URL,Status Code,Category" > "$WORKDIR/exports/endpoint_summary.csv"
while read -r line; do
    url=$(echo "$line" | awk '{print $1}')
    status=$(echo "$line" | grep -oE '\[[0-9]{3}\]' | tr -d '[]')
    if echo "$url" | grep -qiE '/api/'; then
        cat="API"
    elif echo "$url" | grep -qiE '/admin|/dashboard'; then
        cat="Admin"
    elif echo "$url" | grep -qiE '/login|/auth'; then
        cat="Auth"
    else
        cat="General"
    fi
    echo "$url,$status,$cat" >> "$WORKDIR/exports/endpoint_summary.csv"
done < "$WORKDIR/results/live_endpoints.txt"
echo "   CSV summary: $WORKDIR/exports/endpoint_summary.csv"

# --- Manual hints -----------------------------------------------------
echo ""
echo "============================================"
echo "  Pipeline completed at $(date)"
echo "  Target: $TARGET"
echo "  Work directory: $WORKDIR/"
echo "============================================"
echo ""
echo "  Export files ready for Burp:"
echo "    - Burp Intruder endpoints: $WORKDIR/exports/burp_endpoints.txt"
echo "    - Parameterized requests:  $WORKDIR/exports/burp_parameterized.txt"
echo ""
echo "  Interesting endpoints by category:"
echo "    - API:    $WORKDIR/exports/interesting_api.txt"
echo "    - Admin:  $WORKDIR/exports/interesting_admin.txt"
echo "    - Auth:   $WORKDIR/exports/interesting_auth.txt"
echo "    - Config: $WORKDIR/exports/interesting_config.txt"
echo ""
echo "  Other exports:"
echo "    - CSV summary: $WORKDIR/exports/endpoint_summary.csv"
echo "    - API patterns: $WORKDIR/results/api_patterns.json"
if [ -f "$WORKDIR/exports/secrets_trufflehog.txt" ]; then
    echo "    - Secrets: $WORKDIR/exports/secrets_trufflehog.txt"
fi
echo ""
echo "  Manual steps:"
echo "    - Import exports/ into Burp Intruder/Repeater"
echo "    - Review screenshots: $WORKDIR/screenshots/"
echo "    - Check 403 bypasses: $WORKDIR/results/bypass_403_results.txt"
echo "    - Run Gitleaks on repo if accessible"
echo "============================================"
