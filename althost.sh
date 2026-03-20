#!/usr/bin/env bash
set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
ORANGE='\033[38;5;208m'
PURPLE='\033[38;5;93m'
NC='\033[0m'

print() {
  printf "%b%s%b\n" "$1" "$2" "$NC"
}

banner() {
  printf "%b" "$RED"
  cat <<'EOF_BANNER'
  _______  _    _________            _______  _______ _________
 (  ___  )( ╲   ╲__   __╱  │╲     ╱│(  ___  )(  ____ ╲╲__   __╱
 │ (   ) ││ (      ) (     │ )   ( ││ (   ) ││ (    ╲╱   ) (   
 │ (___) ││ │      │ │     │ (___) ││ │   │ ││ (_____    │ │   
 │  ___  ││ │      │ │     │  ___  ││ │   │ │(_____  )   │ │   
 │ (   ) ││ │      │ │     │ (   ) ││ │   │ │      ) │   │ │   
 │ )   ( ││ (____╱╲│ │     │ )   ( ││ (___) │╱╲____) │   │ │   
 │╱     ╲│(_______╱)_(     │╱     ╲│(_______)╲_______)   )_(   
EOF_BANNER
  printf "%b" "$NC"

  printf "%b" "$ORANGE"
  printf "\n"
  printf "             Advanced Host Header Injection Scanner\n"
  printf "%b" "$NC"

  printf "%b" "$PURPLE"
  printf "                   Author : h3xh7wk\n"
  printf "%b" "$NC"
}

show_help() {
  local exit_code="${1:-0}"

  banner

  printf "\n"

  print "$MAGENTA" "Description:"
  cat <<'EOF_DESC'
  Scans for Host Header Injection and related poisoning signals by comparing a baseline request against multiple header mutation modes, scoring the strongest signal per target.

  Features:
    - Subdomain enumeration (-d) via subfinder/assetfinder/amass (if installed)
    - Live URL probing via httpx/httprobe (if installed)
    - Path spraying across common auth/admin/API endpoints (-p)
    - Multiple header modes (-H): Host, X-Forwarded-Host, Forwarded, and more (plus "combined")
    - Detection signals: reflection, redirects, absolute URL poisoning, CORS origin reflection,
      cache signals, status/title/length diffs, and web-cache-deception heuristics
    - Evidence + artifacts saved per finding, plus TXT/CSV/JSONL outputs; optional HTML report (-A)
    - Parallel scanning (-P), resume mode (-r), proxy support (-x), GET/HEAD (-m)
EOF_DESC

  print "$CYAN" "Usage:"
  cat <<EOF_USE
  $0 -u https://target.tld [options]
  $0 -d example.com      [options]
  $0 -l urls.txt         [options]
EOF_USE

  printf "\n"
  print "$CYAN" "Options:"
  printf "%b%-6s%s%b\n" "$GREEN" "-d" "Root domain to enumerate and scan" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-l" "File containing domains or URLs" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-u" "Single URL to scan (bypasses enumeration/probing)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-o" "Output directory (default: hh_scan_output)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-t" "Threads for live probing via httpx (default: 100)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-P" "Parallel workers for target scanning (default: 15)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-T" "Curl timeout in seconds (default: 10)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-a" "Attacker host/canary value (random if empty)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-x" "Proxy URL (e.g. http://127.0.0.1:8080)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-A" "Generate HTML report (report.html)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-p" "Comma-separated paths to test" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-H" "Comma-separated header modes to test" "$NC"
  printf "        %s\n" "default: host,x-forwarded-host,forwarded,x-host,x-forwarded-server,x-http-host-override,x-forwarded-proto,x-original-host,x-rewrite-url,combined"
  printf "%b%-6s%s%b\n" "$GREEN" "-m" "HTTP method: GET or HEAD (default: GET)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-nr" "Do not follow redirects" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-s" "Max response body bytes to keep (default: 200000)" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-k" "Keep clean/raw artifacts too" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-r" "Resume: skip targets already present in results file" "$NC"
  printf "%b%-6s%s%b\n" "$GREEN" "-h" "Show help" "$NC"

  printf "\n"
  print "$YELLOW" "Example:"
  cat <<EOF_EX
  $0 -u https://target.tld -x http://127.0.0.1:8080 -A
  $0 -d example.com -P 20 -a canary.yourcollab.test
  $0 -l urls.txt -p '/,/login,/forgot-password'
EOF_EX

  exit "$exit_code"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

safe_name() {
  local name="$1"
  if [[ ${#name} -gt 100 ]]; then
    local hash
    hash=$(echo -n "$name" | md5sum | cut -d' ' -f1 | cut -c1-8)
    name="${name:0:60}_${hash}"
  fi
  echo -n "$name" | sed 's#https\?://##; s#[^A-Za-z0-9._-]#_#g'
}

join_by() {
  local IFS="$1"
  shift
  echo "$*"
}

json_escape() {
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  echo -n "$s"
}

generate_random_canary() {
  local ts rand
  ts=$(date +%s)
  rand=$(shuf -i 1000-9999 -n1 2>/dev/null || echo "$RANDOM")
  echo "canary-${ts}-${rand}.alt.host"
}

enumerate_subdomains() {
  local domain="$1"
  local outfile="$2"
  : > "$outfile"

  print "$CYAN" "[*] Enumerating subdomains for $domain"
  have subfinder && subfinder -silent -d "$domain" >> "$outfile" 2>/dev/null || true
  have assetfinder && assetfinder --subs-only "$domain" >> "$outfile" 2>/dev/null || true
  have amass && amass enum -passive -d "$domain" >> "$outfile" 2>/dev/null || true
  sort -u "$outfile" -o "$outfile"

  if [[ ! -s "$outfile" ]]; then
    print "$RED" "[-] No subdomains found. Install subfinder / assetfinder / amass."
    exit 1
  fi
  print "$GREEN" "[+] Found $(wc -l < "$outfile") unique subdomains"
}

probe_live_hosts() {
  local subdomains_file="$1"
  local live_file="$2"
  local threads="$3"

  print "$CYAN" "[*] Probing live hosts"
  if have httpx; then
    httpx -silent -l "$subdomains_file" -threads "$threads" -no-color -follow-host-redirects \
      -status-code -title -tech-detect 2>/dev/null | awk '{print $1}' | sort -u > "$live_file"
  elif have httprobe; then
    httprobe < "$subdomains_file" 2>/dev/null | sort -u > "$live_file"
  else
    print "$RED" "[-] Need httpx or httprobe."
    exit 1
  fi
  print "$GREEN" "[+] Live hosts: $(wc -l < "$live_file")"
}

normalize_input_urls() {
  local infile="$1"
  local outfile="$2"
  awk 'NF' "$infile" | while IFS= read -r line; do
    if [[ "$line" =~ ^https?:// ]]; then
      echo "$line"
    else
      echo "https://$line"
      echo "http://$line"
    fi
  done | sort -u > "$outfile"
}

prepare_targets_from_paths() {
  local live_file="$1"
  local paths_csv="$2"
  local targets_file="$3"
  : > "$targets_file"
  IFS=',' read -r -a paths <<< "$paths_csv"

  while IFS= read -r base; do
    [[ -z "$base" ]] && continue
    base="${base%/}"
    for p in "${paths[@]}"; do
      [[ "$p" =~ ^/ ]] || p="/$p"
      echo "${base}${p}"
    done
  done < "$live_file" | sort -u > "$targets_file"
}

curl_fetch() {
  local url="$1"
  local method="$2"
  local timeout="$3"
  local follow_redirects="$4"
  local body_limit="$5"
  local mode="$6"
  local attacker_host="$7"
  local hdr_out="$8"
  local body_out="$9"
  local proxy="${10}"

  local curl_follow=()
  [[ "$follow_redirects" == "1" ]] && curl_follow=(-L)

  local -a header_args=()
  case "$mode" in
    baseline) ;;
    host) header_args=(-H "Host: $attacker_host") ;;
    x-forwarded-host) header_args=(-H "X-Forwarded-Host: $attacker_host") ;;
    forwarded) header_args=(-H "Forwarded: host=$attacker_host;proto=https") ;;
    x-host) header_args=(-H "X-Host: $attacker_host") ;;
    x-forwarded-server) header_args=(-H "X-Forwarded-Server: $attacker_host") ;;
    x-http-host-override) header_args=(-H "X-HTTP-Host-Override: $attacker_host") ;;
    x-forwarded-proto) header_args=(-H "X-Forwarded-Proto: https") ;;
    x-original-host) header_args=(-H "X-Original-Host: $attacker_host") ;;
    x-rewrite-url) header_args=(-H "X-Rewrite-URL: /$attacker_host") ;;
    combined)
      header_args=(
        -H "Host: $attacker_host"
        -H "X-Forwarded-Host: $attacker_host"
        -H "Forwarded: host=$attacker_host;proto=https"
        -H "X-Host: $attacker_host"
        -H "X-Forwarded-Server: $attacker_host"
        -H "X-HTTP-Host-Override: $attacker_host"
        -H "X-Forwarded-Proto: https"
        -H "X-Original-Host: $attacker_host"
      )
      ;;
    *) return 1 ;;
  esac

  local ua="Mozilla/5.0 (HostHeaderScanner by h3xh7wk)"
  local proxy_args=()
  [[ -n "$proxy" ]] && proxy_args=(-x "$proxy")

  if [[ "$method" == "HEAD" ]]; then
    curl -ksS "${curl_follow[@]}" --max-time "$timeout" --retry 1 -A "$ua" -I \
      -D "$hdr_out" "${header_args[@]}" "${proxy_args[@]}" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000"
    : > "$body_out"
  else
    curl -ksS "${curl_follow[@]}" --max-time "$timeout" --retry 1 -A "$ua" \
      -D "$hdr_out" "${header_args[@]}" "${proxy_args[@]}" "$url" 2>/dev/null | head -c "$body_limit" > "$body_out" || true
    awk 'BEGIN{c="000"} /^HTTP\//{c=$2} END{print c}' "$hdr_out"
  fi
}

extract_title() {
  local body_file="$1"
  tr '\n' ' ' < "$body_file" | sed -n 's:.*<title[^>]*>\(.*\)</title>.*:\1:Ip' | sed 's/<[^>]*>//g' | head -c 200
}

extract_content_length() {
  local hdr_file="$1"
  awk 'tolower($1)=="content-length:"{print $2}' "$hdr_file" | tr -d '\r' | tail -n1
}

extract_cache_signal() {
  local hdr_file="$1"
  grep -iE '^(Age:|X-Cache:|CF-Cache-Status:|Cache-Status:|Via:|Server:|CDN-Cache-Control:|Surrogate-Control:|Vary:)' "$hdr_file" | tr '\n' ';' | sed 's/;$/\n/'
}

body_has_attacker() {
  local file="$1"
  local attacker="$2"
  grep -qiF "$attacker" "$file"
}

header_has_attacker() {
  local file="$1"
  local attacker="$2"
  grep -qiF "$attacker" "$file"
}

collect_findings() {
  local baseline_hdr="$1"
  local baseline_body="$2"
  local test_hdr="$3"
  local test_body="$4"
  local attacker="$5"
  local mode="$6"

  local findings=()
  local score=0

  local baseline_title test_title baseline_len test_len
  baseline_title="$(extract_title "$baseline_body")"
  test_title="$(extract_title "$test_body")"
  baseline_len="$(extract_content_length "$baseline_hdr")"
  test_len="$(extract_content_length "$test_hdr")"

  if header_has_attacker "$test_hdr" "$attacker" && ! header_has_attacker "$baseline_hdr" "$attacker"; then
    findings+=("header_reflection:$mode")
    score=$((score + 3))
  fi

  if body_has_attacker "$test_body" "$attacker" && ! body_has_attacker "$baseline_body" "$attacker"; then
    findings+=("body_reflection:$mode")
    score=$((score + 2))
  fi

  if grep -qiE "^Location:\s*(https?:)?//${attacker}|^Refresh:.*${attacker}" "$test_hdr" \
     && ! grep -qiE "^Location:\s*(https?:)?//${attacker}|^Refresh:.*${attacker}" "$baseline_hdr"; then
    findings+=("redirect_poisoning:$mode")
    score=$((score + 5))
  fi

  if grep -qiE "(canonical|og:url|twitter:url|base href|form action|href=|src=).*$attacker" "$test_body" \
     && ! grep -qiE "(canonical|og:url|twitter:url|base href|form action|href=|src=).*$attacker" "$baseline_body"; then
    findings+=("absolute_url_poisoning:$mode")
    score=$((score + 4))
  fi

  if grep -qiE '^Access-Control-Allow-Origin:\s*https?://'"$attacker"'$' "$test_hdr" \
     && ! grep -qiE '^Access-Control-Allow-Origin:\s*https?://'"$attacker"'$' "$baseline_hdr"; then
    findings+=("cors_origin_reflection:$mode")
    score=$((score + 4))
  fi

  if grep -qiE "password reset|forgot password|reset password|verify email|verification|magic link|signin|login" "$test_body"; then
    findings+=("auth_surface:$mode")
    score=$((score + 1))
  fi

  if grep -qiE 'set-cookie:|csrf|token|session' "$test_hdr"; then
    findings+=("sensitive_context:$mode")
    score=$((score + 1))
  fi

  local base_code test_code
  base_code="$(awk 'BEGIN{c="000"} /^HTTP\//{c=$2} END{print c}' "$baseline_hdr")"
  test_code="$(awk 'BEGIN{c="000"} /^HTTP\//{c=$2} END{print c}' "$test_hdr")"

  if [[ "$base_code" != "$test_code" ]]; then
    findings+=("status_diff:${base_code}->${test_code}:$mode")
    score=$((score + 3))
  fi

  if [[ -n "$baseline_title" && -n "$test_title" && "$baseline_title" != "$test_title" ]]; then
    findings+=("title_diff:$mode")
    score=$((score + 2))
  fi

  if [[ -n "$baseline_len" && -n "$test_len" && "$baseline_len" != "$test_len" ]]; then
    findings+=("content_length_diff:$mode")
    score=$((score + 1))
  fi

  if grep -qiE 'internal|staging|dev|admin|forbidden|unauthorized' "$test_body" \
     && ! grep -qiE 'internal|staging|dev|admin|forbidden|unauthorized' "$baseline_body"; then
    findings+=("routing_or_vhost_signal:$mode")
    score=$((score + 3))
  fi

  if grep -qiE 'Age:|X-Cache:|CF-Cache-Status:|Cache-Status:' "$test_hdr"; then
    if printf '%s\n' "${findings[@]}" | grep -qE 'header_reflection|body_reflection|redirect_poisoning|absolute_url_poisoning'; then
      findings+=("cache_poisoning_signal:$mode")
      score=$((score + 2))
    fi
  fi

  if grep -qiE '^(Cache-Control:|Pragma:|Expires:)' "$test_hdr" && \
     grep -qiE 'internal|staging|dev|admin|forbidden' "$test_body" && \
     ! grep -qiE 'internal|staging|dev|admin|forbidden' "$baseline_body"; then
    findings+=("web_cache_deception:$mode")
    score=$((score + 7))
  fi

  if printf '%s\n' "${findings[@]}" | grep -q 'auth_surface:' \
     && printf '%s\n' "${findings[@]}" | grep -qE 'redirect_poisoning|absolute_url_poisoning|header_reflection'; then
    findings+=("reset_poisoning_candidate:$mode")
    score=$((score + 5))
  fi

  local severity="clean"
  if (( score >= 12 )); then
    severity="high-signal"
  elif (( score >= 6 )); then
    severity="medium-signal"
  elif (( score > 0 )); then
    severity="low-signal"
  fi

  printf '%s|%s|%s\n' "$severity" "$score" "$(join_by "," "${findings[@]}")"
}

write_evidence() {
  local evidence_file="$1"
  local target_url="$2"
  local mode="$3"
  local severity="$4"
  local score="$5"
  local findings_str="$6"
  local baseline_hdr="$7"
  local baseline_body="$8"
  local test_hdr="$9"
  local test_body="${10}"
  local attacker="${11}"

  {
    echo "URL: $target_url"
    echo "MODE: $mode"
    echo "SEVERITY: $severity"
    echo "SCORE: $score"
    echo "FINDINGS: $findings_str"
    echo
    echo "=== BASELINE CACHE SIGNALS ==="
    extract_cache_signal "$baseline_hdr" || true
    echo
    echo "=== MUTATED CACHE SIGNALS ==="
    extract_cache_signal "$test_hdr" || true
    echo
    echo "=== BASELINE HEADERS ==="
    cat "$baseline_hdr"
    echo
    echo "=== MUTATED HEADERS ==="
    cat "$test_hdr"
    echo
    echo "=== MUTATED BODY MATCH PREVIEW ==="
    grep -inE "$attacker|password reset|forgot password|reset password|verify email|verification|magic link|signin|login|canonical|og:url|base href|action=|href=|src=|internal|staging|dev|admin" "$test_body" | head -n 60 || true
  } > "$evidence_file"
}

scan_target() {
  local target_url="$1"
  local attacker_host="$2"
  local timeout="$3"
  local follow_redirects="$4"
  local raw_dir="$5"
  local evidence_dir="$6"
  local header_modes_csv="$7"
  local method="$8"
  local body_limit="$9"
  local keep_clean="${10}"
  local proxy="${11}"

  local tmpdir
  tmpdir="$(mktemp -d)"

  local baseline_hdr="$tmpdir/baseline.headers"
  local baseline_body="$tmpdir/baseline.body"
  local baseline_code
  baseline_code="$(curl_fetch "$target_url" "$method" "$timeout" "$follow_redirects" "$body_limit" "baseline" "$attacker_host" "$baseline_hdr" "$baseline_body" "$proxy")"

  local best_severity="clean"
  local best_score=0
  local best_findings="-"
  local best_mode="-"

  IFS=',' read -r -a header_modes <<< "$header_modes_csv"
  for mode in "${header_modes[@]}"; do
    local test_hdr="$tmpdir/${mode}.headers"
    local test_body="$tmpdir/${mode}.body"
    curl_fetch "$target_url" "$method" "$timeout" "$follow_redirects" "$body_limit" "$mode" "$attacker_host" "$test_hdr" "$test_body" "$proxy" >/dev/null

    local result severity score findings
    result="$(collect_findings "$baseline_hdr" "$baseline_body" "$test_hdr" "$test_body" "$attacker_host" "$mode")"
    IFS='|' read -r severity score findings <<< "$result"

    if (( score > best_score )); then
      best_score="$score"
      best_severity="$severity"
      best_findings="$findings"
      best_mode="$mode"
    fi

    if [[ "$severity" != "clean" || "$keep_clean" == "1" ]]; then
      local safe
      safe="$(safe_name "${target_url}__${mode}")"
      cp "$test_hdr" "$raw_dir/${safe}.headers.txt"
      cp "$test_body" "$raw_dir/${safe}.body.txt"
      write_evidence "$evidence_dir/${safe}.evidence.txt" "$target_url" "$mode" "$severity" "$score" "$findings" \
        "$baseline_hdr" "$baseline_body" "$test_hdr" "$test_body" "$attacker_host"
    fi
  done

  if [[ "$keep_clean" == "1" ]]; then
    local bsafe
    bsafe="$(safe_name "${target_url}__baseline")"
    cp "$baseline_hdr" "$raw_dir/${bsafe}.headers.txt" 2>/dev/null || true
    cp "$baseline_body" "$raw_dir/${bsafe}.body.txt" 2>/dev/null || true
  fi

  printf '%s|%s|%s|%s|%s|%s\n' "$target_url" "$baseline_code" "$best_severity" "$best_score" "$best_mode" "$best_findings"
  rm -rf "$tmpdir"
}

scan_worker() {
  local target="$1"
  local raw_dir="$2"
  local evidence_dir="$3"
  local result_tmp_dir="$4"
  local attacker_host="$5"
  local timeout="$6"
  local follow_redirects="$7"
  local header_modes_csv="$8"
  local method="$9"
  local body_limit="${10}"
  local keep_clean="${11}"
  local proxy="${12}"

  local result
  result="$(scan_target "$target" "$attacker_host" "$timeout" "$follow_redirects" "$raw_dir" "$evidence_dir" "$header_modes_csv" "$method" "$body_limit" "$keep_clean" "$proxy")"
  local safe
  safe="$(safe_name "$target")"
  echo "$result" > "$result_tmp_dir/${safe}.result"
}

run_parallel_scans() {
  local targets_file="$1"
  local parallel_jobs="$2"
  local raw_dir="$3"
  local evidence_dir="$4"
  local result_tmp_dir="$5"
  local attacker_host="$6"
  local timeout="$7"
  local follow_redirects="$8"
  local header_modes_csv="$9"
  local method="${10}"
  local body_limit="${11}"
  local keep_clean="${12}"
  local resume_mode="${13}"
  local results_txt="${14}"
  local proxy="${15}"

  while IFS= read -r target; do
    [[ -z "$target" ]] && continue

    if [[ "$resume_mode" == "1" && -f "$results_txt" ]] && grep -Fq "^${target}|" "$results_txt" 2>/dev/null; then
      continue
    fi

    while (( $(jobs -rp | wc -l) >= parallel_jobs )); do
      sleep 0.2
    done

    scan_worker "$target" "$raw_dir" "$evidence_dir" "$result_tmp_dir" "$attacker_host" "$timeout" \
      "$follow_redirects" "$header_modes_csv" "$method" "$body_limit" "$keep_clean" "$proxy" &
  done < "$targets_file"
  wait
}

save_result() {
  local line="$1"
  local txt_file="$2"
  local csv_file="$3"
  local jsonl_file="$4"
  local pot_file="$5"

  echo "$line" >> "$txt_file"
  IFS='|' read -r url code severity score mode findings <<< "$line"
  printf '"%s","%s","%s","%s","%s","%s"\n' "$url" "$code" "$severity" "$score" "$mode" "$findings" >> "$csv_file"
  printf '{"url":"%s","http_code":"%s","severity":"%s","score":"%s","best_mode":"%s","findings":"%s"}\n' \
    "$(json_escape "$url")" "$(json_escape "$code")" "$(json_escape "$severity")" \
    "$(json_escape "$score")" "$(json_escape "$mode")" "$(json_escape "$findings")" >> "$jsonl_file"

  [[ "$severity" != "clean" ]] && echo "$line" >> "$pot_file"
}

generate_html_report() {
  local outdir="$1"
  local attacker_host="$2"
  local report="$outdir/report.html"
  cat > "$report" <<HTML_EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Host Header Injection Report</title>
<style>
  body { font-family: system-ui, Arial; margin: 40px; background: #f8f9fa; }
  table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
  th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
  th { background: #f1f3f5; cursor: pointer; }
  .high-signal { background: #ffe6e6 !important; }
  .medium-signal { background: #fff3e6 !important; }
  tr:hover { background: #f8f9fa; }
  a { color: #0066cc; }
</style>
</head>
<body>
<h1>Host Header Injection Report</h1>
<p><strong>Generated:</strong> $(date)</p>
<p><strong>ALT HOST (Canary):</strong> $attacker_host</p>
<table id="findings">
<thead><tr><th>URL</th><th>Code</th><th>Severity</th><th>Score</th><th>Mode</th><th>Findings</th><th>Evidence</th></tr></thead>
<tbody>
HTML_EOF

  if [[ -f "$outdir/results.csv" ]]; then
    tail -n +2 "$outdir/results.csv" | while IFS=',' read -r url code severity score mode findings; do
      local clean_sev safe_url
      clean_sev=$(echo "$severity" | tr -d '"')
      safe_url=$(safe_name "$url")
      echo "<tr class='$clean_sev'><td>$url</td><td>$code</td><td>$clean_sev</td><td>$score</td><td>$mode</td><td>$findings</td><td><a href='evidence/${safe_url}__${mode}.evidence.txt' target='_blank'>📄</a></td></tr>" >> "$report"
    done 2>/dev/null || true
  fi

  cat >> "$report" <<'HTML_EOF2'
</tbody>
</table>
<script>
  document.querySelectorAll('th').forEach(header => {
    header.addEventListener('click', () => {
      const table = header.closest('table');
      const tbody = table.querySelector('tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      const idx = Array.from(header.parentNode.children).indexOf(header);
      const asc = header.classList.toggle('asc');
      rows.sort((a, b) => {
        const A = a.children[idx].textContent;
        const B = b.children[idx].textContent;
        return (A.localeCompare(B, undefined, {numeric: true})) * (asc ? 1 : -1);
      });
      rows.forEach(row => tbody.appendChild(row));
    });
  });
</script>
</body>
</html>
HTML_EOF2

  print "$GREEN" "[+] HTML Report saved locally: $report"
}

# ==================== MAIN ====================

DOMAIN=""
LIST=""
SINGLE_URL=""
OUTDIR="hh_scan_output"
THREADS="100"
PARALLEL="15"
TIMEOUT="10"
ATTACKER_HOST=""
PROXY=""
HTML_REPORT="0"
PATHS_CSV="/,/.well-known/security.txt,/login,/signin,/forgot-password,/reset-password,/register,/account,/admin,/api,/api/v1,/graphql,/dashboard,/internal,/wp-admin,/administrator,/user,/profile"
HEADER_MODES="host,x-forwarded-host,forwarded,x-host,x-forwarded-server,x-http-host-override,x-forwarded-proto,x-original-host,x-rewrite-url,combined"
FOLLOW_REDIRECTS="1"
METHOD="GET"
BODY_LIMIT="200000"
KEEP_CLEAN="0"
RESUME_MODE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2 ;;
    -l) LIST="$2"; shift 2 ;;
    -u) SINGLE_URL="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -P) PARALLEL="$2"; shift 2 ;;
    -T) TIMEOUT="$2"; shift 2 ;;
    -a) ATTACKER_HOST="$2"; shift 2 ;;
    -x) PROXY="$2"; shift 2 ;;
    -A) HTML_REPORT="1"; shift ;;
    -p) PATHS_CSV="$2"; shift 2 ;;
    -H) HEADER_MODES="$2"; shift 2 ;;
    -m) METHOD="$2"; shift 2 ;;
    -s) BODY_LIMIT="$2"; shift 2 ;;
    -k) KEEP_CLEAN="1"; shift ;;
    -r) RESUME_MODE="1"; shift ;;
    -nr) FOLLOW_REDIRECTS="0"; shift ;;
    -h|--help) show_help 0 ;;
    *) print "$RED" "[-] Unknown option: $1"; show_help 1 ;;
  esac
done

# If no arguments provided, show help then exit
if [[ $# -eq 0 && -z "${DOMAIN}${LIST}${SINGLE_URL}" ]]; then
  show_help 0
fi

have curl || { print "$RED" "[-] Missing dependency: curl"; exit 1; }

if [[ "$OUTDIR" == "/" ]]; then
  print "$RED" "[-] Refusing to use output directory: /"
  exit 1
fi

mkdir -p "$OUTDIR"
if [[ "$RESUME_MODE" != "1" ]]; then
  rm -rf "$OUTDIR/raw" "$OUTDIR/evidence" "$OUTDIR/tmp_results"
fi
mkdir -p "$OUTDIR"/{raw,evidence,tmp_results}

banner

if [[ -z "$ATTACKER_HOST" ]]; then
  ATTACKER_HOST="$(generate_random_canary)"
fi

print "$CYAN" "[*] ALT HOST (Canary) : $ATTACKER_HOST"
print "$CYAN" "[*] Proxy         : ${PROXY:-none}"
print "$CYAN" "[*] Paths         : $PATHS_CSV"
print "$CYAN" "[*] Header modes  : $HEADER_MODES"

SUBS_FILE="$OUTDIR/subdomains.txt"
LIVE_FILE="$OUTDIR/live_urls.txt"
TARGETS_FILE="$OUTDIR/targets.txt"
RESULTS_TXT="$OUTDIR/results.txt"
RESULTS_CSV="$OUTDIR/results.csv"
RESULTS_JSONL="$OUTDIR/results.jsonl"
POTENTIALS_TXT="$OUTDIR/potential_findings.txt"

if [[ -n "$SINGLE_URL" ]]; then
  echo "$SINGLE_URL" > "$LIVE_FILE"
  print "$GREEN" "[+] Single URL mode: $SINGLE_URL"
elif [[ -n "$DOMAIN" ]]; then
  enumerate_subdomains "$DOMAIN" "$SUBS_FILE"
  probe_live_hosts "$SUBS_FILE" "$LIVE_FILE" "$THREADS"
elif [[ -n "$LIST" ]]; then
  normalize_input_urls "$LIST" "$LIVE_FILE"
else
  show_help 1
fi

prepare_targets_from_paths "$LIVE_FILE" "$PATHS_CSV" "$TARGETS_FILE"
print "$CYAN" "[*] Targets       : $(wc -l < "$TARGETS_FILE")"

if [[ "$RESUME_MODE" != "1" ]]; then
  : > "$RESULTS_TXT"
  : > "$POTENTIALS_TXT"
  echo '"url","http_code","severity","score","best_mode","findings"' > "$RESULTS_CSV"
  : > "$RESULTS_JSONL"
else
  [[ -f "$RESULTS_TXT" ]] || : > "$RESULTS_TXT"
  [[ -f "$POTENTIALS_TXT" ]] || : > "$POTENTIALS_TXT"
  [[ -f "$RESULTS_CSV" ]] || echo '"url","http_code","severity","score","best_mode","findings"' > "$RESULTS_CSV"
  [[ -f "$RESULTS_JSONL" ]] || : > "$RESULTS_JSONL"
fi

run_parallel_scans "$TARGETS_FILE" "$PARALLEL" "$OUTDIR/raw" "$OUTDIR/evidence" "$OUTDIR/tmp_results" \
  "$ATTACKER_HOST" "$TIMEOUT" "$FOLLOW_REDIRECTS" "$HEADER_MODES" "$METHOD" "$BODY_LIMIT" \
  "$KEEP_CLEAN" "$RESUME_MODE" "$RESULTS_TXT" "$PROXY"

count=0
total="$(find "$OUTDIR/tmp_results" -type f -name '*.result' | wc -l | tr -d ' ')"
find "$OUTDIR/tmp_results" -type f -name '*.result' | sort | while IFS= read -r result_file; do
  line="$(cat "$result_file")"
  save_result "$line" "$RESULTS_TXT" "$RESULTS_CSV" "$RESULTS_JSONL" "$POTENTIALS_TXT"
  IFS='|' read -r url code severity score mode findings <<< "$line"
  count=$((count + 1))
  if [[ "$severity" == "clean" ]]; then
    print "$GREEN" "[+] [$count/$total] $url [$code] clean"
  else
    print "$RED" "[!] [$count/$total] $url [$code] $severity score=$score via=$mode -> $findings"
  fi
done

rm -rf "$OUTDIR/tmp_results"

high=$(grep -c "high-signal" "$RESULTS_TXT" 2>/dev/null || echo 0)
medium=$(grep -c "medium-signal" "$RESULTS_TXT" 2>/dev/null || echo 0)
low=$(grep -c "low-signal" "$RESULTS_TXT" 2>/dev/null || echo 0)

print "$RED"    "[!] High-signal   : $high"
print "$YELLOW" "[!] Medium-signal : $medium"
print "$GREEN"  "[+] Low-signal    : $low"

if [[ "$HTML_REPORT" == "1" ]]; then
  generate_html_report "$OUTDIR" "$ATTACKER_HOST"
fi

print "$BLUE" "[*] Done"
print "$GREEN" "[+] Results TXT   : $RESULTS_TXT"
print "$GREEN" "[+] Results CSV   : $RESULTS_CSV"
print "$GREEN" "[+] Results JSONL : $RESULTS_JSONL"
print "$GREEN" "[+] Potentials    : $POTENTIALS_TXT"
print "$GREEN" "[+] Evidence dir  : $OUTDIR/evidence"
print "$GREEN" "[+] Raw dir       : $OUTDIR/raw"
print "$GREEN" "[+] All output saved locally in: $OUTDIR"
