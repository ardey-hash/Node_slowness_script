#!/usr/bin/env bash
# Read-only slowness checks for one RHEL node.
# Works against an extracted sos-report, an sos-report tarball, or the live system.
#
#   ./check-node-slowness.sh /path/to/extracted-sosreport
#   ./check-node-slowness.sh /path/to/sosreport.tar.xz
#   ./check-node-slowness.sh --live
#
# Exit status: 0 nothing over threshold, 1 warning, 2 critical, 3 bad input.
# Thresholds are below. They are triage hints, not a diagnosis.

# ---- thresholds -----------------------------------------------------------
IOWAIT_SAMPLE_WARN=20
IOWAIT_SAMPLE_CRIT=40
IOWAIT_AVG_WARN=10
IOWAIT_AVG_CRIT=25
STEAL_SAMPLE_WARN=5
STEAL_SAMPLE_CRIT=15
BUSY_SAMPLE_WARN=85
BUSY_SAMPLE_CRIT=98
BUSY_AVG_WARN=70
BUSY_AVG_CRIT=90
LOAD_RATIO_WARN=1.5
LOAD_RATIO_CRIT=4
BLOCKED_WARN=1
BLOCKED_CRIT=10
MEM_USED_WARN=90
MEM_USED_CRIT=97
MEM_AVAIL_WARN=10
MEM_AVAIL_CRIT=5
SWAP_USED_WARN=50
PSI_WARN=10
PSI_CRIT=40
DF_WARN=90
DF_CRIT=97
AWAIT_WARN=20
AWAIT_CRIT=100
UTIL_WARN=85
UTIL_CRIT=97
DSTATE_WARN=1
DSTATE_CRIT=10
DROP_WARN=1
DROP_CRIT=50
IFUTIL_WARN=80
IFUTIL_CRIT=95
# --------------------------------------------------------------------------

export LC_ALL=C

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: run this script with bash." >&2
  exit 3
fi

CLEAN_DIRS=()
FINDINGS=""
DETAIL=""
HEADER=""

cleanup() {
  local d
  for d in "${CLEAN_DIRS[@]}"; do
    [ -n "$d" ] && rm -rf "$d"
  done
  [ -n "$FINDINGS" ] && rm -f "$FINDINGS"
  [ -n "$DETAIL" ] && rm -f "$DETAIL"
  [ -n "$HEADER" ] && rm -f "$HEADER"
}
trap cleanup EXIT

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 3
}

usage() {
  cat <<'EOF'
Usage:
  check-node-slowness.sh /path/to/extracted-sosreport
  check-node-slowness.sh /path/to/sosreport.tar.xz
  check-node-slowness.sh --live

Reads an sos-report (or the local system with --live) and reports what is
slow: CPU, iowait, steal, memory, PSI, D-state tasks, disk latency, full
filesystems, multipath/iSCSI, and a few log patterns.

Exit status: 0 clean, 1 warning, 2 critical, 3 usage or unreadable input.
EOF
}

ge() {
  awk -v v="$1" -v t="$2" 'BEGIN { exit !((v + 0) >= (t + 0)) }'
}

fmt_num() {
  awk -v v="$1" 'BEGIN { printf "%.2f", v + 0 }'
}

finding() {
  # $1 severity, $2 message
  printf '%s\t%s\n' "$1" "$2" >> "$FINDINGS"
}

detail() {
  printf '%s\n' "$1" >> "$DETAIL"
}

first_file() {
  local f
  for f in "$@"; do
    [ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

find_root() {
  local d="$1" sub kids
  if [ -d "$d/sos_commands" ] || [ -f "$d/proc/meminfo" ] || [ -f "$d/sos_logs/sos.log" ]; then
    (cd "$d" && pwd)
    return 0
  fi
  sub=$(find "$d" -mindepth 1 -maxdepth 3 -type d -name 'sosreport-*' 2>/dev/null | head -n 1)
  if [ -n "$sub" ]; then
    (cd "$sub" && pwd)
    return 0
  fi
  kids=$(find "$d" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  if [ "$kids" -eq 1 ]; then
    sub=$(find "$d" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1)
    find_root "$sub"
    return 0
  fi
  (cd "$d" && pwd)
}

is_probably_binary() {
  # NUL in the first 512 bytes means this is not a text sar report.
  head -c 512 "$1" 2>/dev/null | od -An -tx1 | grep -q ' 00 '
}

gather_live() {
  local dest="$1" dd yest sa prefix wrote sample
  mkdir -p \
    "$dest/proc/pressure" \
    "$dest/sos_commands/process" \
    "$dest/sos_commands/filesys" \
    "$dest/sos_commands/kernel" \
    "$dest/sos_commands/sar" \
    "$dest/sos_commands/logs" \
    "$dest/sos_commands/systemd" \
    "$dest/sos_commands/tuned" \
    "$dest/sos_commands/multipath" \
    "$dest/sos_commands/iscsi" \
    "$dest/var/log" \
    "$dest/etc"

  hostname > "$dest/hostname" 2>/dev/null || echo unknown > "$dest/hostname"
  date > "$dest/date" 2>/dev/null || true
  uptime > "$dest/uptime" 2>/dev/null || true
  uname -a > "$dest/sos_commands/kernel/uname_-a" 2>/dev/null || true
  [ -r /etc/os-release ] && cp /etc/os-release "$dest/etc/os-release"

  [ -r /proc/loadavg ] && cp /proc/loadavg "$dest/proc/loadavg"
  [ -r /proc/meminfo ] && cp /proc/meminfo "$dest/proc/meminfo"
  [ -r /proc/cpuinfo ] && cp /proc/cpuinfo "$dest/proc/cpuinfo"
  [ -r /proc/pressure/cpu ] && cp /proc/pressure/cpu "$dest/proc/pressure/cpu"
  [ -r /proc/pressure/io ] && cp /proc/pressure/io "$dest/proc/pressure/io"
  [ -r /proc/pressure/memory ] && cp /proc/pressure/memory "$dest/proc/pressure/memory"

  ps auxwww > "$dest/sos_commands/process/ps_auxwww" 2>/dev/null || true
  df -hP > "$dest/sos_commands/filesys/df_-hP" 2>/dev/null || true
  df -iP > "$dest/sos_commands/filesys/df_-iP" 2>/dev/null || true

  if [ "$(uname -s)" = "Linux" ] && command -v top >/dev/null 2>&1; then
    top -b -n 1 -w 512 > "$dest/sos_commands/process/top_-b_-n_1" 2>/dev/null || true
  fi

  if command -v vmstat >/dev/null 2>&1; then
    vmstat 1 3 > "$dest/sos_commands/process/vmstat_1_3" 2>/dev/null || true
  fi

  if command -v sar >/dev/null 2>&1; then
    today=$(date +%d)
    yest=""
    yest=$(date -d yesterday +%d 2>/dev/null || date -v-1d +%d 2>/dev/null || true)
    wrote=0
    for dd in $today $yest; do
      [ -n "$dd" ] || continue
      for prefix in /var/log/sa/sa /var/log/sysstat/sa; do
        sa="${prefix}${dd}"
        [ -f "$sa" ] || continue
        sample="$dest/sos_commands/sar/sar_${dd}.txt"
        if LC_ALL=C sar -A -f "$sa" > "$sample" 2>/dev/null; then
          wrote=1
        elif LC_ALL=C sar -u -q -r -S -W -d -n DEV -n EDEV -f "$sa" > "$sample" 2>/dev/null; then
          wrote=1
        else
          rm -f "$sample"
        fi
      done
    done
    if [ "$wrote" -eq 0 ]; then
      LC_ALL=C sar -u -q -r 1 3 > "$dest/sos_commands/sar/sar_sample.txt" 2>/dev/null || true
    fi
  fi

  if command -v dmesg >/dev/null 2>&1; then
    dmesg -T > "$dest/sos_commands/kernel/dmesg" 2>/dev/null || dmesg > "$dest/sos_commands/kernel/dmesg" 2>/dev/null || true
  fi
  if [ -r /var/log/messages ]; then
    tail -n 80000 /var/log/messages > "$dest/var/log/messages" 2>/dev/null || true
  fi
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -k --since "7 days ago" --no-pager > "$dest/sos_commands/logs/journalctl_kernel" 2>/dev/null || true
  fi
  if command -v iscsiadm >/dev/null 2>&1; then
    iscsiadm -m session -P 3 > "$dest/sos_commands/iscsi/iscsiadm_-m_session_-P_3" 2>/dev/null || true
  fi
  if command -v multipath >/dev/null 2>&1; then
    multipath -ll > "$dest/sos_commands/multipath/multipath_-ll" 2>/dev/null || true
  fi
  if command -v tuned-adm >/dev/null 2>&1; then
    tuned-adm active > "$dest/sos_commands/tuned/tuned-adm_active" 2>/dev/null || true
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --failed --no-pager > "$dest/sos_commands/systemd/systemctl_--failed" 2>/dev/null || true
  fi
}

ncpu_of() {
  local root="$1" n lscpu
  if [ -f "$root/proc/cpuinfo" ]; then
    n=$(grep -c '^processor' "$root/proc/cpuinfo" 2>/dev/null || true)
    [ -n "$n" ] && [ "$n" -gt 0 ] && { echo "$n"; return; }
  fi
  lscpu=$(first_file "$root/sos_commands/processor/lscpu" "$root/sos_commands/host/lscpu" || true)
  if [ -n "$lscpu" ]; then
    n=$(awk -F: '/^CPU\(s\)/ { gsub(/ /,"",$2); print $2; exit }' "$lscpu")
    [ -n "$n" ] && echo "$n" && return
  fi
  echo 0
}

snapshot_load() {
  local root="$1" ncpu="$2" f load1 load5 load15 ratio sev
  f=$(first_file "$root/proc/loadavg" || true)
  [ -n "$f" ] || return 0
  read -r load1 load5 load15 _ < "$f"
  detail "load average at collection: ${load1} ${load5} ${load15} (1/5/15 min), cpus: ${ncpu}"
  [ "$ncpu" -gt 0 ] || {
    finding INFO "CPU count was not in the report, so load average was not scored."
    return 0
  }
  ratio=$(awk -v l="$load1" -v n="$ncpu" 'BEGIN { printf "%.2f", l / n }')
  detail "1-minute load per cpu: ${ratio}"
  sev=""
  if ge "$ratio" "$LOAD_RATIO_CRIT"; then
    sev=CRIT
  elif ge "$ratio" "$LOAD_RATIO_WARN"; then
    sev=WARN
  fi
  [ -n "$sev" ] && finding "$sev" "Load at collection is ${load1} on ${ncpu} cpus (${ratio} per cpu)."
}

snapshot_mem() {
  local root="$1" f avail used swap
  f=$(first_file "$root/proc/meminfo" || true)
  [ -n "$f" ] || { finding INFO "proc/meminfo was not in the report."; return 0; }
  IFS='|' read -r avail used swap <<EOF
$(awk '
  /^MemTotal:/ { t = $2 }
  /^MemAvailable:/ { a = $2 }
  /^MemFree:/ { free = $2 }
  /^SwapTotal:/ { st = $2 }
  /^SwapFree:/ { sf = $2 }
  END {
    if (t <= 0) exit
    if (a == "") a = free
    sw = 0
    if (st > 0) sw = ((st - sf) / st) * 100
    printf "%.2f|%.2f|%.2f\n", (a / t) * 100, ((t - a) / t) * 100, sw
  }
' "$f")
EOF
  [ -n "$avail" ] || return 0
  detail "memory at collection: available ${avail}%, used about ${used}%, swap used ${swap}%"
  if ge "$used" "$MEM_USED_CRIT" || ! ge "$avail" "$MEM_AVAIL_CRIT"; then
    finding CRIT "Memory at collection is tight: available ${avail}%, used about ${used}%."
  elif ge "$used" "$MEM_USED_WARN" || ! ge "$avail" "$MEM_AVAIL_WARN"; then
    finding WARN "Memory at collection is elevated: available ${avail}%, used about ${used}%."
  fi
  if ge "$swap" "$SWAP_USED_WARN"; then
    finding WARN "Swap is ${swap}% used at collection. Check si/so in sar before calling this a memory leak."
  fi
}

snapshot_psi() {
  local root="$1" kind f a10 a60 full10 sev
  for kind in cpu io memory; do
    f=$(first_file "$root/proc/pressure/$kind" || true)
    [ -n "$f" ] || continue
    a10=$(awk '$1=="some"{for(i=1;i<=NF;i++) if($i ~ /^avg10=/){split($i,a,"="); print a[2]}}' "$f")
    a60=$(awk '$1=="some"{for(i=1;i<=NF;i++) if($i ~ /^avg60=/){split($i,a,"="); print a[2]}}' "$f")
    full10=$(awk '$1=="full"{for(i=1;i<=NF;i++) if($i ~ /^avg10=/){split($i,a,"="); print a[2]}}' "$f")
    detail "PSI ${kind}: some avg10=${a10:-n/a} avg60=${a60:-n/a} full avg10=${full10:-n/a}"
    sev=""
    if ge "${a10:-0}" "$PSI_CRIT" || ge "${a60:-0}" "$PSI_CRIT"; then
      sev=CRIT
    elif ge "${a10:-0}" "$PSI_WARN" || ge "${a60:-0}" "$PSI_WARN"; then
      sev=WARN
    fi
    [ -n "$sev" ] && finding "$sev" "PSI ${kind} pressure is high (some avg10=${a10}, avg60=${a60})."
  done
}

snapshot_top() {
  local root="$1" f wa st line
  f=$(find "$root/sos_commands/process" -type f -name 'top_*' 2>/dev/null | head -n 1)
  [ -n "$f" ] || return 0
  line=$(grep -m 1 '%Cpu' "$f" 2>/dev/null || true)
  [ -n "$line" ] || return 0
  wa=$(printf '%s\n' "$line" | awk '{
    for (i = 1; i <= NF; i++) if ($i == "wa," || $i == "wa") { print $(i-1); exit }
  }')
  st=$(printf '%s\n' "$line" | awk '{
    for (i = 1; i <= NF; i++) if ($i == "st" || $i == "st,") { print $(i-1); exit }
  }')
  detail "top at collection: ${line}"
  if [ -n "$wa" ]; then
    if ge "$wa" "$IOWAIT_SAMPLE_CRIT"; then
      finding CRIT "top at collection shows iowait ${wa}%."
    elif ge "$wa" "$IOWAIT_SAMPLE_WARN"; then
      finding WARN "top at collection shows iowait ${wa}%."
    fi
  fi
  if [ -n "$st" ]; then
    if ge "$st" "$STEAL_SAMPLE_CRIT"; then
      finding CRIT "top at collection shows steal ${st}%. The hypervisor is not giving this guest CPU."
    elif ge "$st" "$STEAL_SAMPLE_WARN"; then
      finding WARN "top at collection shows steal ${st}%."
    fi
  fi
}

snapshot_vmstat() {
  local root="$1" f
  [ -d "$root/sos_commands/process" ] || return 0
  f=$(find "$root/sos_commands/process" -type f -name 'vmstat*' 2>/dev/null | head -n 1)
  [ -n "$f" ] || return 0
  # vmstat 1 N: the first numeric row is the average since boot. Score the later rows.
  awk -v iowait_warn="$IOWAIT_SAMPLE_WARN" -v iowait_crit="$IOWAIT_SAMPLE_CRIT" \
      -v steal_warn="$STEAL_SAMPLE_WARN" -v steal_crit="$STEAL_SAMPLE_CRIT" \
      -v blocked_warn="$BLOCKED_WARN" -v blocked_crit="$BLOCKED_CRIT" '
    $0 ~ /wa/ && $0 ~ /us/ && wacol == 0 {
      for (i = 1; i <= NF; i++) {
        if ($i == "b") bcol = i
        if ($i == "wa") wacol = i
        if ($i == "st") stcol = i
        if ($i == "si") sicol = i
        if ($i == "so") socol = i
      }
      next
    }
    $1 ~ /^[0-9]+$/ {
      n++
      b = (bcol ? $bcol : 0)
      wa = (wacol ? $wacol : 0)
      st = (stcol ? $stcol : 0)
      si = (sicol ? $sicol : 0)
      so = (socol ? $socol : 0)
      if (n == 1) { fb=b; fwa=wa; fst=st; fsi=si; fso=so }
      else {
        if (scored == 0 || wa+0 > maxwa) maxwa = wa
        if (scored == 0 || st+0 > maxst) maxst = st
        if (scored == 0 || b+0 > maxb) maxb = b
        if (scored == 0 || si+0 > maxsi) maxsi = si
        if (scored == 0 || so+0 > maxso) maxso = so
        scored++
      }
    }
    END {
      if (n == 0) exit
      if (n >= 2) { b=maxb; wa=maxwa; st=maxst; si=maxsi; so=maxso; label="vmstat during collection" }
      else { b=fb; wa=fwa; st=fst; si=fsi; so=fso; label="vmstat since-boot sample" }
      printf "DETAIL|%s: blocked=%s iowait=%s steal=%s si=%s so=%s\n", label, b, wa, st, si, so
      if (wa+0 >= iowait_crit) printf "CRIT|%s iowait is %s%%.\n", label, wa
      else if (wa+0 >= iowait_warn) printf "WARN|%s iowait is %s%%.\n", label, wa
      if (st+0 >= steal_crit) printf "CRIT|%s steal is %s%%.\n", label, st
      else if (st+0 >= steal_warn) printf "WARN|%s steal is %s%%.\n", label, st
      if (b+0 >= blocked_crit) printf "CRIT|%s shows %s tasks blocked on I/O.\n", label, b
      else if (b+0 >= blocked_warn) printf "WARN|%s shows %s tasks blocked on I/O.\n", label, b
    }
  ' "$f" | while IFS='|' read -r sev msg; do
    if [ "$sev" = "DETAIL" ]; then
      detail "$msg"
    else
      finding "$sev" "$msg"
    fi
  done
}

snapshot_ps() {
  local root="$1" list f count zcount
  list=$(mktemp)
  if [ -d "$root/sos_commands/process" ]; then
    find "$root/sos_commands/process" -type f -name 'ps*' 2>/dev/null > "$list" || true
  fi
  [ -s "$list" ] || { rm -f "$list"; finding INFO "ps output was not in the report."; return 0; }
  # One ps listing. aux and alx from the same sos would count the same tasks twice.
  f=$(grep -m 1 'ps_auxwww$' "$list" || true)
  [ -n "$f" ] || f=$(grep -m 1 'ps_aux$' "$list" || true)
  [ -n "$f" ] || f=$(head -n 1 "$list")
  detail ""
  detail "Tasks in D state (uninterruptible sleep):"
  awk '
    NR == 1 {
      for (i = 1; i <= NF; i++) if ($i == "STAT" || $i == "S" || $i == "STATE") col = i
      next
    }
    col > 0 && $col ~ /^D/ { print }
  ' "$f" > "$list.d"
  count=$(wc -l < "$list.d" | tr -d ' ')
  if [ "$count" -eq 0 ]; then
    detail "  none"
  else
    sed 's/^/  /' "$list.d" | head -n 30 >> "$DETAIL"
    [ "$count" -gt 30 ] && detail "  ... $count total, showing 30"
    if [ "$count" -ge "$DSTATE_CRIT" ]; then
      finding CRIT "${count} tasks are stuck in D state. This is usually disk, multipath, or a remote filesystem."
    elif [ "$count" -ge "$DSTATE_WARN" ]; then
      finding WARN "${count} task(s) stuck in D state. This is usually disk, multipath, or a remote filesystem."
    fi
  fi
  zcount=$(awk '
    NR == 1 {
      for (i = 1; i <= NF; i++) if ($i == "STAT" || $i == "S" || $i == "STATE") col = i
      next
    }
    col > 0 && $col ~ /^Z/ { c++ }
    END { print c+0 }
  ' "$f")
  if [ "$zcount" -gt 0 ]; then
    detail "zombie tasks: ${zcount}"
    [ "$zcount" -ge 50 ] && finding WARN "${zcount} zombie tasks."
  fi
  rm -f "$list" "$list.d"
}

snapshot_df() {
  local root="$1" kind label list f base use_p mark now
  for kind in space inode; do
    list=$(mktemp)
    : > "$list"
    if [ -d "$root/sos_commands/filesys" ]; then
      find "$root/sos_commands/filesys" -type f -name 'df*' 2>/dev/null > "$list.raw" || true
    else
      : > "$list.raw"
    fi
    [ -f "$root/df" ] && echo "$root/df" >> "$list.raw"
    while read -r f; do
      [ -f "$f" ] || continue
      base=$(basename "$f")
      if [ "$kind" = "inode" ]; then
        if grep -q 'IUse%' "$f" 2>/dev/null || printf '%s' "$base" | grep -q 'df_-i'; then
          echo "$f" >> "$list"
        fi
      else
        if grep -q 'IUse%' "$f" 2>/dev/null; then
          continue
        fi
        if grep -q 'Use%' "$f" 2>/dev/null || printf '%s' "$base" | grep -q '^df'; then
          echo "$f" >> "$list"
        fi
      fi
    done < "$list.raw"
    use_p=$(mktemp)
    : > "$use_p"
    while read -r f; do
      [ -f "$f" ] || continue
      base=$(basename "$f")
      if printf '%s' "$base" | grep -q 'P'; then
        echo "$f" >> "$use_p"
      fi
    done < "$list"
    if [ -s "$use_p" ]; then
      cp "$use_p" "$list"
    fi
    if [ "$kind" = "inode" ]; then
      label="inode use"
    else
      label="filesystem use"
    fi
    if [ ! -s "$list" ]; then
      [ "$kind" = "space" ] && finding INFO "df output was not in the report."
      rm -f "$list" "$list.raw" "$use_p"
      continue
    fi
    detail ""
    detail "${label} at or above ${DF_WARN}%:"
    mark=$(wc -l < "$DETAIL" | tr -d ' ')
    awk -v warn="$DF_WARN" -v crit="$DF_CRIT" -v label="$label" '
      function noisy(m) {
        return m ~ /^\/(dev|run|sys)($|\/)/
      }
      {
        pct = -1
        for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+%$/) pct = $i + 0
        if (pct < 0) next
        mount = $NF
        if (!(mount in best) || pct > best[mount]) best[mount] = pct
      }
      END {
        for (m in best) {
          pct = best[m]
          if (pct + 0 < warn) continue
          sev = "WARN"
          if (pct + 0 >= crit && !noisy(m)) sev = "CRIT"
          else if (noisy(m)) sev = "WARN"
          printf "%s|%s on %s is %d%%.\n", sev, label, m, pct
          printf "DETAIL|  %3d%%  %s\n", pct, m
        }
      }
    ' $(cat "$list") | while IFS='|' read -r sev msg; do
      if [ "$sev" = "DETAIL" ]; then
        detail "$msg"
      else
        finding "$sev" "$msg"
      fi
    done
    now=$(wc -l < "$DETAIL" | tr -d ' ')
    if [ "$now" -eq "$mark" ]; then
      detail "  none"
    fi
    rm -f "$list" "$list.raw" "$use_p"
  done
}

parse_sar_files() {
  local root="$1" ncpu="$2" text combined f out dir
  text=$(mktemp)
  combined=$(mktemp)
  : > "$text"
  for dir in "$root/sos_commands/sar" "$root/var/log/sa" "$root/var/log/sysstat"; do
    [ -d "$dir" ] || continue
    find "$dir" -type f 2>/dev/null
  done | while read -r f; do
    [ -f "$f" ] || continue
    if is_probably_binary "$f"; then
      echo "BIN $f"
    elif grep -q -E '%iowait|ldavg-1|%memused|%util|rxdrop' "$f" 2>/dev/null; then
      echo "TXT $f"
    fi
  done > "$text.kind"

  : > "$combined"
  while read -r kind f; do
    [ "$kind" = "TXT" ] || continue
    cat "$f" >> "$combined"
    echo >> "$combined"
  done < "$text.kind"

  if command -v sar >/dev/null 2>&1; then
    while read -r kind f; do
      [ "$kind" = "BIN" ] || continue
      out=$(mktemp)
      if LC_ALL=C sar -A -f "$f" > "$out" 2>/dev/null && grep -q '%iowait' "$out"; then
        cat "$out" >> "$combined"
        echo >> "$combined"
      elif LC_ALL=C sar -u -q -r -S -W -d -n DEV -n EDEV -f "$f" > "$out" 2>/dev/null && grep -q -E '%iowait|%util' "$out"; then
        cat "$out" >> "$combined"
        echo >> "$combined"
      fi
      rm -f "$out"
    done < "$text.kind"
  fi

  if ! grep -q -E '%iowait|ldavg-1|%util' "$combined" 2>/dev/null; then
    finding INFO "sar history was not in the report, so only the collection-time snapshot was checked."
    rm -f "$text" "$text.kind" "$combined"
    return 0
  fi

  out=$(mktemp)
  awk -v ncpu="$ncpu" '
    function is_header(line) {
      return line ~ /%iowait/ || line ~ /ldavg-1/ || line ~ /%memused/ || line ~ /%swpused/ || line ~ /pswpin/ || line ~ /rxdrop/ || line ~ /rxpck/ || (line ~ /%util/ && line ~ /await/)
    }
    function section_of(line) {
      if (line ~ /%iowait/) return "cpu"
      if (line ~ /ldavg-1/) return "load"
      if (line ~ /%memused/) return "mem"
      if (line ~ /%swpused/) return "swap"
      if (line ~ /pswpin/) return "paging"
      if (line ~ /rxdrop/) return "neterr"
      if (line ~ /rxpck/) return "netdev"
      if (line ~ /%util/ && line ~ /await/) return "disk"
      return ""
    }
    function parse_header(   i, name) {
      delete col
      hdr_ampm = ($2 == "AM" || $2 == "PM") ? 1 : 0
      for (i = 1; i <= NF; i++) {
        name = tolower($i)
        gsub(/%/, "", name)
        gsub(/\/s/, "", name)
        col[name] = i
      }
      sect = section_of($0)
    }
    function fval(name, is_avg,   i) {
      i = col[name]
      if (i == 0) return ""
      if (is_avg && hdr_ampm) i--
      if (i < 1 || i > NF) return ""
      return $i
    }
    function tstamp(is_avg) {
      if (is_avg) return "Average"
      if ($2 == "AM" || $2 == "PM") return $1 " " $2
      return $1
    }
    function skip_dev(d) {
      return d == "" || d == "dev" || d ~ /^(loop|ram|fd|sr|scd)/
    }
    BEGIN {
      worst_iowait = -1
      worst_steal = -1
      worst_busy = -1
      worst_load = -1
      worst_blocked = -1
      worst_mem = -1
      worst_swap = -1
      worst_psin = -1
      worst_psout = -1
      have_cpu = 0
      have_cpu_avg = 0
      have_load = 0
      have_load_avg = 0
      have_mem = 0
      have_mem_avg = 0
    }
    {
      gsub(/\r/, "", $0)
    }
    is_header($0) {
      parse_header()
      next
    }
    $1 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ || $1 == "Average:" {
      is_avg = ($1 == "Average:") ? 1 : 0
      ts = tstamp(is_avg)
      if (sect == "cpu") {
        cpu = fval("cpu", is_avg)
        if (cpu != "all" && cpu != "-") next
        iw = fval("iowait", is_avg) + 0
        stl = fval("steal", is_avg) + 0
        busy = fval("user", is_avg) + fval("system", is_avg)
        have_cpu = 1
        if (is_avg) {
          avg_iowait = iw
          avg_steal = stl
          avg_busy = busy
          have_cpu_avg = 1
        } else {
          cpu_n++
          sum_iowait += iw
          sum_steal += stl
          sum_busy += busy
          if (iw > worst_iowait) { worst_iowait = iw; worst_iowait_t = ts }
          if (stl > worst_steal) { worst_steal = stl; worst_steal_t = ts }
          if (busy > worst_busy) { worst_busy = busy; worst_busy_t = ts }
        }
      } else if (sect == "load") {
        ld = fval("ldavg-1", is_avg) + 0
        blk = fval("blocked", is_avg) + 0
        have_load = 1
        if (is_avg) { avg_load = ld; have_load_avg = 1 }
        else {
          if (ld > worst_load) { worst_load = ld; worst_load_t = ts }
          if (blk > worst_blocked) { worst_blocked = blk; worst_blocked_t = ts }
        }
      } else if (sect == "mem") {
        mu = fval("memused", is_avg) + 0
        have_mem = 1
        if (is_avg) { avg_mem = mu; have_mem_avg = 1 }
        else if (mu > worst_mem) { worst_mem = mu; worst_mem_t = ts }
      } else if (sect == "swap") {
        sw = fval("swpused", is_avg) + 0
        if (!is_avg && sw > worst_swap) { worst_swap = sw; worst_swap_t = ts }
      } else if (sect == "paging") {
        pin = fval("pswpin", is_avg) + 0
        pout = fval("pswpout", is_avg) + 0
        if (!is_avg && pin > worst_psin) { worst_psin = pin; worst_psin_t = ts }
        if (!is_avg && pout > worst_psout) worst_psout = pout
      } else if (sect == "disk") {
        dev = fval("dev", is_avg)
        if (skip_dev(dev)) next
        aw = fval("await", is_avg) + 0
        ut = fval("util", is_avg) + 0
        if (is_avg) {
          disk_await_avg[dev] = aw
          disk_util_avg[dev] = ut
        } else {
          if (!(dev in disk_await) || aw > disk_await[dev]) {
            disk_await[dev] = aw
            disk_await_t[dev] = ts
          }
          if (!(dev in disk_util) || ut > disk_util[dev]) {
            disk_util[dev] = ut
            disk_util_t[dev] = ts
          }
        }
      } else if (sect == "netdev") {
        iface = fval("iface", is_avg)
        if (iface == "" || iface == "lo" || iface == "IFACE") next
        iu = fval("ifutil", is_avg) + 0
        if (!is_avg && (!(iface in net_util) || iu > net_util[iface])) {
          net_util[iface] = iu
          net_util_t[iface] = ts
        }
      } else if (sect == "neterr") {
        iface = fval("iface", is_avg)
        if (iface == "" || iface == "lo") next
        rd = fval("rxdrop", is_avg) + 0
        td = fval("txdrop", is_avg) + 0
        if (!is_avg && (!(iface in net_drop) || (rd + td) > net_drop[iface])) {
          net_drop[iface] = rd + td
          net_rx[iface] = rd
          net_tx[iface] = td
          net_drop_t[iface] = ts
        }
      }
      next
    }
    END {
      if (have_cpu) {
        if (!have_cpu_avg && cpu_n > 0) {
          avg_iowait = sum_iowait / cpu_n
          avg_steal = sum_steal / cpu_n
          avg_busy = sum_busy / cpu_n
        }
        printf "CPU|%.2f|%.2f|%s|%.2f|%.2f|%s|%.2f|%.2f|%s|%d\n", \
          avg_iowait+0, (worst_iowait < 0 ? 0 : worst_iowait), worst_iowait_t, \
          avg_steal+0, (worst_steal < 0 ? 0 : worst_steal), worst_steal_t, \
          avg_busy+0, (worst_busy < 0 ? 0 : worst_busy), worst_busy_t, cpu_n+0
      }
      if (have_load) {
        printf "LOAD|%.2f|%.2f|%s|%.2f|%s\n", \
          (have_load_avg ? avg_load : worst_load), \
          (worst_load < 0 ? 0 : worst_load), worst_load_t, \
          (worst_blocked < 0 ? 0 : worst_blocked), worst_blocked_t
      }
      if (have_mem) {
        printf "MEM|%.2f|%.2f|%s\n", \
          (have_mem_avg ? avg_mem : worst_mem), \
          (worst_mem < 0 ? 0 : worst_mem), worst_mem_t
      }
      if (worst_swap >= 0) printf "SWAP|%.2f|%s\n", worst_swap, worst_swap_t
      if (worst_psin >= 0 || worst_psout >= 0) printf "PAGING|%.2f|%.2f|%s\n", (worst_psin < 0 ? 0 : worst_psin), (worst_psout < 0 ? 0 : worst_psout), worst_psin_t
      for (dev in disk_await) {
        printf "DISK|%s|%.2f|%s|%.2f|%.2f|%s|%.2f\n", dev, \
          disk_await[dev]+0, disk_await_t[dev], disk_await_avg[dev]+0, \
          disk_util[dev]+0, disk_util_t[dev], disk_util_avg[dev]+0
      }
      for (iface in net_util) printf "NET|%s|%.2f|%s\n", iface, net_util[iface]+0, net_util_t[iface]
      for (iface in net_drop) printf "NETERR|%s|%.2f|%.2f|%s\n", iface, net_rx[iface]+0, net_tx[iface]+0, net_drop_t[iface]
    }
  ' "$combined" > "$out"

  detail ""
  detail "sar history:"
  while IFS='|' read -r tag a b c d e f g h i j; do
    [ -n "$tag" ] || continue
    case "$tag" in
      CPU)
        detail "  cpu samples=${j}  iowait avg=${a}% worst=${b}% at ${c}  steal avg=${d}% worst=${e}% at ${f}  user+system avg=${g}% worst=${h}% at ${i}"
        if ge "$b" "$IOWAIT_SAMPLE_CRIT" || ge "$a" "$IOWAIT_AVG_CRIT"; then
          finding CRIT "sar iowait avg ${a}%, worst ${b}% at ${c}. Tasks are waiting on disk."
        elif ge "$b" "$IOWAIT_SAMPLE_WARN" || ge "$a" "$IOWAIT_AVG_WARN"; then
          finding WARN "sar iowait avg ${a}%, worst ${b}% at ${c}."
        fi
        if ge "$e" "$STEAL_SAMPLE_CRIT" || ge "$d" "$STEAL_SAMPLE_WARN"; then
          if ge "$e" "$STEAL_SAMPLE_CRIT"; then
            finding CRIT "sar steal avg ${d}%, worst ${e}% at ${f}. The hypervisor is not giving this guest CPU."
          else
            finding WARN "sar steal avg ${d}%, worst ${e}% at ${f}."
          fi
        fi
        if ge "$h" "$BUSY_SAMPLE_CRIT" || ge "$g" "$BUSY_AVG_CRIT"; then
          finding CRIT "sar user+system avg ${g}%, worst ${h}% at ${i}. The node is CPU bound."
        elif ge "$h" "$BUSY_SAMPLE_WARN" || ge "$g" "$BUSY_AVG_WARN"; then
          finding WARN "sar user+system avg ${g}%, worst ${h}% at ${i}."
        fi
        ;;
      LOAD)
        detail "  load ldavg-1 avg=${a} worst=${b} at ${c}  blocked worst=${d} at ${e}"
        if [ "$ncpu" -gt 0 ]; then
          ratio=$(awk -v l="$b" -v n="$ncpu" 'BEGIN { printf "%.2f", l / n }')
          if ge "$ratio" "$LOAD_RATIO_CRIT"; then
            finding CRIT "sar 1-minute load peaked at ${b} on ${ncpu} cpus (${ratio} per cpu) at ${c}."
          elif ge "$ratio" "$LOAD_RATIO_WARN"; then
            finding WARN "sar 1-minute load peaked at ${b} on ${ncpu} cpus (${ratio} per cpu) at ${c}."
          fi
        else
          detail "  cpu count missing, load not scored"
        fi
        if ge "$d" "$BLOCKED_CRIT"; then
          finding CRIT "sar shows ${d} blocked tasks at ${e}. Those tasks are waiting on I/O."
        elif ge "$d" "$BLOCKED_WARN"; then
          finding WARN "sar shows ${d} blocked tasks at ${e}."
        fi
        ;;
      MEM)
        detail "  memory used avg=${a}% worst=${b}% at ${c}"
        if ge "$b" "$MEM_USED_CRIT" || ge "$a" "$MEM_USED_CRIT"; then
          finding CRIT "sar memory used avg ${a}%, worst ${b}% at ${c}."
        elif ge "$b" "$MEM_USED_WARN" || ge "$a" "$MEM_USED_WARN"; then
          finding WARN "sar memory used avg ${a}%, worst ${b}% at ${c}."
        fi
        ;;
      SWAP)
        detail "  swap used worst=${a}% at ${b}"
        if ge "$a" "$SWAP_USED_WARN"; then
          finding WARN "sar swap used peaked at ${a}% at ${b}."
        fi
        ;;
      PAGING)
        detail "  paging pswpin/s worst=${a} pswpout/s worst=${b} at ${c}"
        if ge "$a" 100 || ge "$b" 100; then
          finding WARN "sar shows paging (pswpin/s ${a}, pswpout/s ${b}) at ${c}. The node is swapping."
        fi
        ;;
      DISK)
        printf '%s|%s|%s|%s|%s|%s|%s\n' "$a" "$b" "$c" "$d" "$e" "$f" "$g" >> "$out.disks"
        ;;
      NET)
        detail "  nic ${a} peak %ifutil=${b} at ${c}"
        if ge "$b" "$IFUTIL_CRIT"; then
          finding CRIT "Interface ${a} peaked at ${b}% utilized at ${c}."
        elif ge "$b" "$IFUTIL_WARN"; then
          finding WARN "Interface ${a} peaked at ${b}% utilized at ${c}."
        fi
        ;;
      NETERR)
        detail "  nic ${a} rxdrop/s=${b} txdrop/s=${c} at ${d}"
        drop_sum=$(awk -v x="$b" -v y="$c" 'BEGIN { printf "%.2f", x + y }')
        if ge "$drop_sum" "$DROP_CRIT"; then
          finding CRIT "Interface ${a} is dropping packets (rx ${b}/s, tx ${c}/s) at ${d}."
        elif ge "$drop_sum" "$DROP_WARN"; then
          finding WARN "Interface ${a} is dropping packets (rx ${b}/s, tx ${c}/s) at ${d}."
        fi
        ;;
    esac
  done < "$out"

  if [ -f "$out.disks" ]; then
    detail "  slowest disks by peak await (top 8):"
    sort -t'|' -k2,2nr "$out.disks" | head -n 8 | while IFS='|' read -r dev await atime aavg util utime uavg; do
      detail "    ${dev}  peak await ${await} ms at ${atime} (avg ${aavg})  peak util ${util}% at ${utime} (avg ${uavg})"
    done
    shown=0
    sort -t'|' -k2,2nr "$out.disks" | while IFS='|' read -r dev await atime aavg util utime uavg; do
      sev=""
      why=""
      if ge "$await" "$AWAIT_CRIT" || ge "$util" "$UTIL_CRIT"; then
        sev=CRIT
      elif ge "$await" "$AWAIT_WARN" || ge "$util" "$UTIL_WARN"; then
        sev=WARN
      fi
      [ -n "$sev" ] || continue
      shown=$((shown + 1))
      if [ "$shown" -le 15 ]; then
        finding "$sev" "Disk ${dev} peak await ${await} ms at ${atime}, peak util ${util}% at ${utime}."
      fi
      echo "$shown" > "$out.diskcount"
    done
    if [ -f "$out.diskcount" ]; then
      shown=$(cat "$out.diskcount")
      [ "$shown" -gt 15 ] && finding WARN "${shown} disks are over the latency or util threshold. The first 15 are listed; the rest are in the sar section."
    fi
  fi

  rm -f "$text" "$text.kind" "$combined" "$out" "$out.disks" "$out.diskcount"
}

storage_path() {
  local root="$1" f ready bad state dir
  f=""
  for dir in "$root/sos_commands/multipath" "$root/sos_commands/devicemapper"; do
    [ -d "$dir" ] || continue
    f=$(find "$dir" -type f -name '*multipath*' 2>/dev/null | head -n 1)
    [ -n "$f" ] && break
  done
  if [ -n "$f" ]; then
    ready=$(grep -c -E 'active ready|active ghost' "$f" 2>/dev/null || true)
    bad=$(grep -c -E 'failed|faulty|shaky' "$f" 2>/dev/null || true)
    ready=${ready:-0}
    bad=${bad:-0}
    detail ""
    detail "multipath: active-ready/ghost lines ${ready}, failed/faulty/shaky lines ${bad} ($(basename "$f"))"
    [ "$bad" -gt 0 ] && finding WARN "multipath shows ${bad} failed, faulty, or shaky path line(s). A single slow node is often a bad path."
  fi
  f=""
  if [ -d "$root/sos_commands/iscsi" ]; then
    f=$(find "$root/sos_commands/iscsi" -type f -name '*iscsiadm*' 2>/dev/null | head -n 1)
  fi
  if [ -n "$f" ]; then
    state=$(grep -E 'session state:' "$f" 2>/dev/null || true)
    detail "iSCSI sessions:"
    if [ -z "$state" ]; then
      detail "  no session state lines in $(basename "$f")"
    else
      printf '%s\n' "$state" | sed 's/^/  /' >> "$DETAIL"
      if printf '%s\n' "$state" | grep -v 'LOGGED IN' | grep -q 'session state:'; then
        finding WARN "An iSCSI session is not LOGGED IN. Storage I/O on this node will stall."
      fi
    fi
    if grep -E -i -q 'recovery|connection[0-9].*error|session.*fail' "$f" 2>/dev/null; then
      finding WARN "iSCSI session output contains recovery or connection errors."
    fi
  fi
}

tuned_and_systemd() {
  local root="$1" f
  f=""
  if [ -d "$root/sos_commands/tuned" ]; then
    f=$(find "$root/sos_commands/tuned" -type f -name '*tuned-adm*' 2>/dev/null | head -n 1)
  fi
  if [ -n "$f" ]; then
    detail ""
    detail "tuned: $(head -n 2 "$f" | tr '\n' ' ')"
    if grep -q 'powersave' "$f"; then
      finding WARN "tuned profile is powersave, which caps CPU and makes a node feel slow."
    fi
  fi
  f=""
  if [ -d "$root/sos_commands/systemd" ]; then
    f=$(find "$root/sos_commands/systemd" -type f -name '*failed*' 2>/dev/null | head -n 1)
  fi
  if [ -n "$f" ]; then
    if grep -q '0 loaded units' "$f"; then
      detail "systemd: no failed units"
    elif grep -E -q 'failed|not-found' "$f"; then
      finding WARN "systemd lists failed units. See the systemd section of the sos-report."
      detail ""
      detail "failed units:"
      sed 's/^/  /' "$f" | head -n 40 >> "$DETAIL"
    fi
  fi
}

log_signals() {
  local root="$1" files f tmp count last sev label pattern
  files=$(mktemp)
  : > "$files"
  for f in \
    "$root/var/log/messages" \
    "$root/var/log/messages."[0-9] \
    "$root/sos_commands/kernel/dmesg" \
    "$root/sos_commands/kernel/dmesg_-T"
  do
    [ -f "$f" ] && echo "$f" >> "$files"
  done
  if [ -d "$root/sos_commands/logs" ]; then
    find "$root/sos_commands/logs" -type f -name 'journalctl*' 2>/dev/null >> "$files"
  fi
  if [ -d "$root/var/log" ]; then
    find "$root/var/log" -maxdepth 1 -type f -name 'messages*.gz' 2>/dev/null >> "$files"
  fi
  if [ ! -s "$files" ]; then
    finding INFO "messages, dmesg, and journal were not in the report."
    rm -f "$files"
    return 0
  fi

  detail ""
  detail "log signals (count and the newest matching line):"
  tmp=$(mktemp)
  cat > "$tmp.patterns" <<'EOF'
OOM|CRIT|out of memory|oom-kill|Killed process
I/O errors|WARN|I/O error|blk_update_request|task abort|Medium Error
blocked task|CRIT|blocked for more than|soft lockup|hard LOCKUP
NFS stall|WARN|nfs:.*not responding|nfs:.*timed out
iSCSI errors|WARN|nexus reset|session recovery|Connection.*error
EOF
  while IFS='|' read -r label sev p1 p2 p3 p4; do
    [ -n "$label" ] || continue
    pattern="$p1"
    [ -n "$p2" ] && pattern="${pattern}|${p2}"
    [ -n "$p3" ] && pattern="${pattern}|${p3}"
    [ -n "$p4" ] && pattern="${pattern}|${p4}"
    : > "$tmp"
    while read -r f; do
      [ -f "$f" ] || continue
      case "$f" in
        *.gz)
          if command -v zgrep >/dev/null 2>&1; then
            zgrep -E -i -h "$pattern" "$f" >> "$tmp" 2>/dev/null || true
          elif command -v gzip >/dev/null 2>&1; then
            gzip -dc "$f" 2>/dev/null | grep -E -i "$pattern" >> "$tmp" || true
          fi
          ;;
        *)
          grep -E -i -h "$pattern" "$f" >> "$tmp" 2>/dev/null || true
          ;;
      esac
    done < "$files"
    count=$(wc -l < "$tmp" | tr -d ' ')
    if [ "$count" -gt 0 ]; then
      last=$(tail -n 1 "$tmp")
      last=$(printf '%s' "$last" | cut -c 1-220)
      finding "$sev" "Log ${label}: ${count} line(s). Newest: ${last}"
      detail "  ${label}: ${count}"
      detail "    ${last}"
    else
      detail "  ${label}: 0"
    fi
  done < "$tmp.patterns"
  rm -f "$files" "$tmp" "$tmp.patterns"
}

print_report() {
  local sev msg color reset
  echo "================================================================"
  echo "NODE SLOWNESS CHECK"
  echo "================================================================"
  if [ -s "$HEADER" ]; then
    cat "$HEADER"
  fi
  echo
  echo "FINDINGS"
  echo "----------------------------------------------------------------"
  if ! grep -q -E '^(CRIT|WARN)	' "$FINDINGS"; then
    finding OK "No threshold was crossed in the data this report contains."
  fi
  for sev in CRIT WARN INFO OK; do
    grep "^${sev}	" "$FINDINGS" 2>/dev/null | while IFS='	' read -r sev msg; do
      color=""
      reset=""
      if [ -t 1 ]; then
        case "$sev" in
          CRIT) color=$(printf '\033[31m') ;;
          WARN) color=$(printf '\033[33m') ;;
          OK) color=$(printf '\033[32m') ;;
        esac
        [ -n "$color" ] && reset=$(printf '\033[0m')
      fi
      printf '%s%-4s%s  %s\n' "$color" "$sev" "$reset" "$msg"
    done
  done
  echo
  echo "DETAIL"
  echo "----------------------------------------------------------------"
  cat "$DETAIL"
  echo
  echo "Thresholds: iowait sample ${IOWAIT_SAMPLE_WARN}/${IOWAIT_SAMPLE_CRIT}%, steal ${STEAL_SAMPLE_WARN}/${STEAL_SAMPLE_CRIT}%, load per cpu ${LOAD_RATIO_WARN}/${LOAD_RATIO_CRIT}, disk await ${AWAIT_WARN}/${AWAIT_CRIT} ms, disk util ${UTIL_WARN}/${UTIL_CRIT}%, filesystem ${DF_WARN}/${DF_CRIT}%."
  echo "A CRIT line is the first place to look. It is not by itself the root cause."
}

main() {
  local input root ncpu pretty uname_f osrel
  FINDINGS=$(mktemp)
  DETAIL=$(mktemp)
  HEADER=$(mktemp)
  : > "$FINDINGS"
  : > "$DETAIL"
  : > "$HEADER"

  if [ $# -ne 1 ]; then
    usage
    exit 3
  fi
  input="$1"
  if [ "$input" = "-h" ] || [ "$input" = "--help" ]; then
    usage
    exit 0
  fi

  if [ "$input" = "--live" ]; then
    root=$(mktemp -d)
    CLEAN_DIRS[${#CLEAN_DIRS[@]}]="$root"
    gather_live "$root"
    echo "source: live system ($(hostname 2>/dev/null || echo unknown))" >> "$HEADER"
  elif [ -d "$input" ]; then
    root=$(find_root "$input")
    echo "source: $root" >> "$HEADER"
  elif [ -f "$input" ]; then
    case "$input" in
      *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tbz|*.tar.xz|*.txz|*.tar.zst|*.tzst)
        root=$(mktemp -d)
        CLEAN_DIRS[${#CLEAN_DIRS[@]}]="$root"
        tar -xf "$input" -C "$root" || die "could not extract $input"
        root=$(find_root "$root")
        echo "source: $input" >> "$HEADER"
        echo "extracted root: $root" >> "$HEADER"
        ;;
      *)
        die "unsupported file. Pass an extracted sos directory or a tar archive."
        ;;
    esac
  else
    die "path not found: $input"
  fi

  [ -d "$root" ] || die "could not find the sos-report root under $input"

  {
    [ -f "$root/hostname" ] && echo "hostname: $(head -n 1 "$root/hostname")"
    [ -f "$root/date" ] && echo "collected: $(head -n 1 "$root/date")"
    [ -f "$root/uptime" ] && echo "uptime: $(head -n 1 "$root/uptime")"
    uname_f=$(first_file "$root/sos_commands/kernel/uname_-a" "$root/uname" || true)
    [ -n "$uname_f" ] && echo "kernel: $(head -n 1 "$uname_f")"
    osrel=$(first_file "$root/etc/os-release" "$root/etc/redhat-release" || true)
    if [ -n "$osrel" ]; then
      pretty=$(grep '^PRETTY_NAME=' "$osrel" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"')
      [ -n "$pretty" ] && echo "os: $pretty"
    fi
  } >> "$HEADER"

  ncpu=$(ncpu_of "$root")
  echo "cpus: $ncpu" >> "$HEADER"

  snapshot_load "$root" "$ncpu"
  snapshot_mem "$root"
  snapshot_psi "$root"
  snapshot_top "$root"
  snapshot_vmstat "$root"
  snapshot_ps "$root"
  snapshot_df "$root"
  parse_sar_files "$root" "$ncpu"
  storage_path "$root"
  tuned_and_systemd "$root"
  log_signals "$root"

  print_report

  if grep -q '^CRIT	' "$FINDINGS"; then
    exit 2
  fi
  if grep -q '^WARN	' "$FINDINGS"; then
    exit 1
  fi
  exit 0
}

main "$@"
