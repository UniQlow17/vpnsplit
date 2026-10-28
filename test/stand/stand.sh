#!/usr/bin/env bash
# Network stand for vpnsplit: runs INSIDE a `docker run --privileged` container
# (see run.ps1). Builds a small internet out of network namespaces and checks
# the lifecycle of a vpnsplit session. Exit code 1 if any check fails.
#
#   client ──eth0── isp (NAT) ── inet (1.1.1.1 DNS, 203.0.113.10-13)
#     │ wgcorp ───────────────── corp (wg server, 10.10.0.0/16, corp.example DNS)
#     │ wghome ───────────────── home (wg server, NAT into inet)
#
# 203.0.113.10-13 exist in inet, corp and home; each answers HTTP with its own
# name, so `curl` shows the path a packet took.
set -u

STAND=/stand
BIN=/usr/local/bin/vpnsplit
WORK=/tmp/stand
VARIANT=${HOME_VARIANT:-a}
ONLY=${ONLY:-}
mkdir -p "$WORK"
install -m 755 "$STAND/.build/vpnsplit" "$BIN"

PASS=0
FAIL=0
FAILED=()

say() { printf '\n== %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf '   ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); FAILED+=("$CUR: $*"); printf '   FAIL %s\n' "$*"; }
check() { # description command...
  local d=$1
  shift
  if "$@"; then ok "$d"; else bad "$d"; fi
}

cl() { ip netns exec client env HOME=/root "$@"; }
vs() { cl "$BIN" "$@"; }

# ---------------------------------------------------------------- topology
setup() {
  for n in client isp inet corp home; do
    ip netns add $n
    ip -n $n link set lo up
    ip netns exec $n sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
  done
  link() { # nsA ifA addrA nsB ifB addrB
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"
    ip -n "$4" addr add "$6" dev "$5"
    ip -n "$1" link set "$2" up
    ip -n "$4" link set "$5" up
  }
  link client eth0 192.168.1.2/24 isp c0 192.168.1.1/24
  link isp u0 198.18.0.1/30 inet i0 198.18.0.2/30
  link inet i1 198.18.1.1/30 corp eth0 198.18.1.2/30
  link inet i2 198.18.2.1/30 home eth0 198.18.2.2/30

  ip -n client route add default via 192.168.1.1
  ip -n isp route add default via 198.18.0.2
  ip -n corp route add default via 198.18.1.1
  ip -n home route add default via 198.18.2.1
  ip netns exec isp iptables -t nat -A POSTROUTING -o u0 -j MASQUERADE
  ip netns exec home iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

  ip -n inet addr add 1.1.1.1/32 dev lo
  ip -n corp addr add 10.10.1.1/32 dev lo
  for n in inet corp home; do
    for i in 10 11 12 13; do ip -n $n addr add 203.0.113.$i/32 dev lo; done
  done

  # WireGuard: the UDP sockets live in the namespaces where the devices are created
  local d=$WORK/keys
  mkdir -p $d
  for k in client_corp corp client_home home; do wg genkey | tee $d/$k.key | wg pubkey > $d/$k.pub; done
  ip -n corp link add wgcorp type wireguard
  ip -n corp addr add 10.200.0.1/24 dev wgcorp
  ip netns exec corp wg set wgcorp listen-port 51820 private-key $d/corp.key peer "$(cat $d/client_corp.pub)" allowed-ips 10.200.0.2/32
  ip -n corp link set wgcorp up
  ip -n home link add wghome type wireguard
  ip -n home addr add 10.201.0.1/24 dev wghome
  ip netns exec home wg set wghome listen-port 51820 private-key $d/home.key peer "$(cat $d/client_home.pub)" allowed-ips 10.201.0.2/32
  ip -n home link set wghome up

  ip -n client link add wgcorp type wireguard
  ip -n client addr add 10.200.0.2/24 dev wgcorp
  ip netns exec client wg set wgcorp private-key $d/client_corp.key peer "$(cat $d/corp.pub)" allowed-ips 0.0.0.0/0 endpoint 198.18.1.2:51820
  ip -n client link set wgcorp up
  ip -n client link add wghome type wireguard
  ip -n client addr add 10.201.0.2/24 dev wghome
  ip netns exec client wg set wghome private-key $d/client_home.key peer "$(cat $d/home.pub)" allowed-ips 0.0.0.0/0 endpoint 198.18.2.2:51820
  ip -n client link set wghome up
  # what a VPN client does: its own servers stay reachable past the tunnels
  ip -n client route add 198.18.1.2/32 via 192.168.1.1 dev eth0
  ip -n client route add 198.18.2.2/32 via 192.168.1.1 dev eth0

  case "$VARIANT" in
    b) # wg-quick style: default through a table, everything but the tunnel's own packets
      ip netns exec client wg set wghome fwmark 51820
      ip -n client route add default dev wghome table 51820
      ip -n client rule add not fwmark 51820 table 51820
      ip -n client rule add table main suppress_prefixlength 0 ;;
    c) # a rule that sends everything to a table with the home tunnel
      ip -n client route add default dev wghome table 100
      ip -n client rule add from all lookup 100 priority 100 ;;
  esac

  # services
  for n in inet corp home; do
    ip netns exec $n python3 $STAND/httpname.py $n >/dev/null 2>&1 &
  done
  ip netns exec inet dnsmasq --user=root --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
    --listen-address=1.1.1.1 --address=/direct.example/203.0.113.12 --pid-file=$WORK/dns-inet.pid
  ip netns exec corp dnsmasq --user=root --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
    --listen-address=10.200.0.1 --address=/corp.example/10.10.1.1 --pid-file=$WORK/dns-corp.pid
  mkdir -p /etc/netns/client
  echo "nameserver 1.1.1.1" > /etc/netns/client/resolv.conf
  sleep 1
}

configure() {
  vs set corp wgcorp && vs set home wghome && vs set corp-dns 10.200.0.1 &&
    vs set home-default yes && vs set split-dns yes &&
    vs add 203.0.113.11 corp.example && vs add --direct direct.example
}

# ------------------------------------------------------------------ helpers
snap() { # the routing state of the client
  { ip -n client -4 route show table all | grep -v -E '^(local|broadcast|multicast)'; ip -n client -4 rule show; } | sort
}

dest_dev() { ip -n client -4 route get "$1" 2>/dev/null | grep -o 'dev [^ ]*' | head -1 | cut -d' ' -f2; }

path_of() { ip netns exec client curl -s --max-time 4 "http://$1/" 2>/dev/null; }

wait_for() { # seconds command...
  local t=$1 i
  shift
  for ((i = 0; i < t * 5; i++)); do
    "$@" && return 0
    sleep 0.2
  done
  return 1
}

dev_is() { [ "$(dest_dev "$1")" = "$2" ]; }
applied() { dev_is 203.0.113.13 wghome && dev_is 203.0.113.11 wgcorp; }
pid_gone() { ! kill -0 "$1" 2>/dev/null; }
base_state() { [ "$(snap)" = "$BASE" ]; }

# start_run <name> <vpnsplit args...>: leaves RPID (the process), RLOG
start_run() {
  local name=$1
  shift
  RLOG=$WORK/$name.log
  rm -f "$WORK/$name.pid"
  : > "$RLOG"
  ip netns exec client env HOME=/root sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$WORK/$name.pid" "$BIN" "$@" > "$RLOG" 2>&1 &
  RBG=$!
  wait_for 5 test -s "$WORK/$name.pid"
  RPID=$(cat "$WORK/$name.pid" 2>/dev/null)
}

# wait for the process, return its exit code in RCODE (it is a child of this shell)
reap() {
  local i
  for ((i = 0; i < 100; i++)); do
    if pid_gone "$RPID"; then
      wait "$RBG" 2>/dev/null
      RCODE=$?
      return 0
    fi
    sleep 0.1
  done
  RCODE=timeout
  return 1
}

show_log() { sed 's/^/        | /' "$RLOG"; }

fresh() { # a clean start: nothing applied, journal gone
  vs reset >/dev/null 2>&1
  rm -f /var/lib/vpnsplit/state.json
  base_state || bad "the base state is not clean before the scenario"
}

routes_ok() { # the three classes + the corp domain, by route lookup and by curl
  check "corp rule 203.0.113.11 -> wgcorp" dev_is 203.0.113.11 wgcorp
  check "corp domain corp.example (10.10.1.1) -> wgcorp" dev_is 10.10.1.1 wgcorp
  check "direct domain direct.example (203.0.113.12) -> eth0" dev_is 203.0.113.12 eth0
  check "the rest 203.0.113.13 -> wghome" dev_is 203.0.113.13 wghome
  check "curl 203.0.113.11 answers corp" test "$(path_of 203.0.113.11)" = corp
  check "curl 203.0.113.12 answers inet (direct)" test "$(path_of 203.0.113.12)" = inet
  check "curl 203.0.113.13 answers home" test "$(path_of 203.0.113.13)" = home
  check "curl 203.0.113.10 answers home" test "$(path_of 203.0.113.10)" = home
}

want() { [ -z "$ONLY" ] || [[ "$1" == *"$ONLY"* ]]; }

# --------------------------------------------------------------- scenarios
s_baseline() {
  CUR=S0
  say "S0 baseline: without vpnsplit everything goes to inet"
  for ip in 10 11 12 13; do check "curl 203.0.113.$ip answers inet" test "$(path_of 203.0.113.$ip)" = inet; done
  check "tunnels work: wgcorp reaches the corp DNS" ip netns exec client curl -s --max-time 3 -o /dev/null http://10.200.0.1/
}

s_signal() { # name signal
  CUR=$1
  say "$1: run, $2, the routing table is back to the snapshot"
  fresh
  start_run "$1" run
  check "routes applied" wait_for 20 applied
  routes_ok
  check "the table differs from the snapshot while running" test "$(snap)" != "$BASE"
  kill -"$2" "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  grep -q "full tunnel 0/1+128/1 removed" "$RLOG" && ok "reported: full tunnel removed" || bad "no 'full tunnel removed' in the output"
  grep -q "All traffic now goes straight through your ISP" "$RLOG" && ok "said where the traffic goes now" || bad "no note about direct traffic"
  grep -q "removing: " "$RLOG" && ok "progress was shown" || bad "no progress lines"
  check "the outcome is written down" grep -q "removed" /var/lib/vpnsplit/last-session.log
  show_log
}

s_kill9() {
  CUR=S3
  say "S3: kill -9, then the next run recovers"
  fresh
  start_run s3a run
  check "routes applied" wait_for 20 applied
  kill -9 "$RPID"
  reap
  check "the table still differs after kill -9" test "$(snap)" != "$BASE"
  check "the journal says session, with an owner" bash -c 'grep -q "\"session\"" /var/lib/vpnsplit/state.json && grep -q "\"owner\"" /var/lib/vpnsplit/state.json'
  vs status | grep -q "not running any more" && ok "status explains the dead session" || bad "status does not mention the dead session"
  start_run s3b run
  check "routes applied again" wait_for 20 applied
  grep -q "did not clean up" "$RLOG" && ok "recovery was announced" || bad "no recovery message"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  show_log

  CUR=S3b
  say "S3b: kill -9, then 'reset' recovers"
  start_run s3c run
  wait_for 20 applied
  kill -9 "$RPID"
  reap
  check "the table differs after kill -9" test "$(snap)" != "$BASE"
  out=$(vs reset 2>&1)
  echo "$out" | sed 's/^/        | /'
  check "the routing table equals the snapshot after reset" base_state
}

s_persistent() {
  CUR=S4
  say "S4: apply (persistent) leaves routes; run takes them over and removes them at exit"
  fresh
  check "apply succeeds" vs apply >"$WORK/s4.apply.log" 2>&1
  check "routes stay after apply exited" applied
  check "the journal says persistent" grep -q '"persistent"' /var/lib/vpnsplit/state.json
  start_run s4 run
  check "run keeps the routes" wait_for 20 applied
  grep -q "took over" "$RLOG" && ok "take-over was announced" || bad "no take-over message"
  check "the journal says session now" grep -q '"session"' /var/lib/vpnsplit/state.json
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  show_log
}

s_second() {
  CUR=S5
  say "S5: a second copy does not change the network"
  fresh
  start_run s5a run
  check "routes applied" wait_for 20 applied
  local before
  before=$(snap)
  out=$(vs run 2>&1)
  rc=$?
  echo "$out" | sed 's/^/        | /'
  check "second run refuses (exit $rc)" test "$rc" != 0
  echo "$out" | grep -q "is running" && ok "message explains why" || bad "message does not say that another copy is running"
  out=$(vs reset 2>&1)
  rc=$?
  check "reset refuses while a session owns the routes (exit $rc)" test "$rc" != 0
  out=$(vs apply 2>&1)
  rc=$?
  check "apply refuses while a session owns the routes (exit $rc)" test "$rc" != 0
  check "the table did not change" test "$(snap)" = "$before"
  check "routes still work" applied
  kill -TERM "$RPID"
  reap
  check "the first copy ends cleanly (exit $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
}

s_tui() { # mode
  CUR=S6-$1
  say "S6: the menu (TUI on a terminal) ends by '$1'"
  fresh
  out=$(python3 $STAND/tuirun.py "$1" 'ip -n client -4 route get 203.0.113.13 | grep -q "dev wghome"' "$BIN" 2>&1)
  echo "$out" | head -1 | sed 's/^/        | /'
  if [ "$1" = hangup ]; then
    check "exited" bash -c "echo '$out' | grep -q 'EXIT=[0-9]'"
  else
    echo "$out" | grep -q 'EXIT=0' && ok "exit code 0" || bad "exit code: $(echo "$out" | head -1)"
    echo "$out" | grep -q "full tunnel\|полный туннель 0/1+128/1 снят" && ok "reported: full tunnel removed" || bad "no 'full tunnel removed' on the screen"
  fi
  check "the routing table equals the snapshot" base_state
}

s_tui_second() {
  CUR=S6-second
  say "S6: a menu started while a session runs is view-only"
  fresh
  start_run s6a run
  wait_for 20 applied
  local before
  before=$(snap)
  out=$(python3 $STAND/tuirun.py q 'sleep 7' "$BIN" 2>&1)
  echo "$out" | grep -q 'EXIT=0' && ok "the view-only menu quits with q" || bad "the view-only menu did not quit: $(echo "$out" | head -1)"
  check "the table did not change" test "$(snap)" = "$before"
  check "routes still work" applied
  kill -TERM "$RPID"
  reap
  check "the first copy ends cleanly (exit $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
}

s_tui_foreign() {
  CUR=S7
  say "S7: the menu over routes of apply (persistent): q leaves them, t then q removes them"
  fresh
  check "apply succeeds" vs apply >"$WORK/s7.apply.log" 2>&1
  check "routes stay after apply exited" applied
  local before
  before=$(snap)
  out=$(python3 $STAND/tuirun.py q 'screen:Забрать' "$BIN" 2>&1)
  echo "$out" | head -1 | sed 's/^/        | /'
  echo "$out" | grep -q 'EXIT=0' && ok "exit code 0 on q" || bad "exit code: $(echo "$out" | head -1)"
  echo "$out" | grep -q "оставлены" && ok "the exit says the routes were left" || bad "no 'оставлены' on the screen"
  check "the table did not change (nothing removed without the confirmation)" test "$(snap)" = "$before"
  check "routes still work" applied
  check "the journal is still persistent" grep -q '"persistent"' /var/lib/vpnsplit/state.json

  say "S7b: the same routes, now t (take over) and q"
  out=$(python3 $STAND/tuirun.py tq 'screen:Забрать' "$BIN" 2>&1)
  echo "$out" | head -1 | sed 's/^/        | /'
  echo "$out" | grep -q 'EXIT=0' && ok "exit code 0 on t, q" || bad "exit code: $(echo "$out" | head -1)"
  echo "$out" | grep -q "полный туннель 0/1+128/1 снят" && ok "reported: full tunnel removed" || bad "no 'full tunnel removed' on the screen"
  echo "$out" | grep -q "Весь трафик теперь идёт напрямую" && ok "said where the traffic goes now" || bad "no note about direct traffic"
  check "the routing table equals the snapshot" base_state
  check "the outcome is written down" grep -q "снято" /var/lib/vpnsplit/last-session.log
}

# a slow `ip route del` (8 s): the cleanup is still running when the next signal comes.
# vpnsplit finds `ip` in the system directories only, so the wrapper goes there.
SLOWIP=/usr/sbin/ip
slow_ip_on() {
  REALIP=$(command -v ip)
  if [ "$REALIP" = "$SLOWIP" ]; then
    mv "$SLOWIP" "$SLOWIP.orig"
    REALIP=$SLOWIP.orig
    MOVED=1
  else
    MOVED=0
  fi
  printf '#!/bin/sh\ncase "$*" in *"route del"*) sleep 8;; esac\nexec %s "$@"\n' "$REALIP" > "$SLOWIP"
  chmod 755 "$SLOWIP"
}
slow_ip_off() {
  rm -f "$SLOWIP"
  [ "${MOVED:-0}" = 1 ] && mv "$SLOWIP.orig" "$SLOWIP"
  return 0
}
sleepers_gone() { ! pgrep -f 'sleep 8' >/dev/null 2>&1; }

s_cleanup_signals() {
  CUR=S8
  say "S8: a second Ctrl+C during the cleanup ends it at once, the journal keeps the rest"
  fresh
  start_run s8 run
  check "routes applied" wait_for 20 applied
  slow_ip_on
  kill -INT "$RPID"
  sleep 1.5
  check "the cleanup is in progress (the process is alive)" kill -0 "$RPID"
  kill -INT "$RPID"
  reap
  check "the process ended quickly with exit 130 (got $RCODE)" test "$RCODE" = 130
  grep -q "second signal" "$RLOG" && ok "the second signal was answered" || bad "no message about the second signal"
  check "the journal keeps the entries" bash -c 'grep -q "\"session\"" /var/lib/vpnsplit/state.json && grep -q "10.10.1\|203.0.113\|0.0.0.0/1" /var/lib/vpnsplit/state.json'
  check "the routes were not removed yet" dev_is 203.0.113.13 wghome
  show_log
  slow_ip_off
  wait_for 15 sleepers_gone
  start_run s8b run
  check "routes applied again" wait_for 20 applied
  grep -q "did not clean up" "$RLOG" && ok "the next start finished the job" || bad "no recovery message"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state

  CUR=S8-term
  say "S8-term: SIGTERM (a closed window) with a slow cleanup: ~4.5 s from the signal, then it gives up"
  fresh
  start_run s8t run
  check "routes applied" wait_for 20 applied
  slow_ip_on
  t0=$EPOCHREALTIME
  kill -TERM "$RPID"
  reap
  t1=$EPOCHREALTIME
  el=$(awk "BEGIN{printf \"%.1f\", $t1 - $t0}")
  check "it exited non-zero, the cleanup is incomplete (got $RCODE)" test "$RCODE" != 0 -a "$RCODE" != timeout
  check "within the budget: 3.5 s < ${el} s < 6.5 s" awk "BEGIN{exit !($el > 3.5 && $el < 6.5)}"
  grep -q "could not remove everything" "$RLOG" && ok "the failure is loud" || bad "no loud message"
  check "the journal keeps the entries" grep -q '"session"' /var/lib/vpnsplit/state.json
  check "the outcome is written down" grep -q "NOT everything" /var/lib/vpnsplit/last-session.log
  vs status 2>&1 | grep -q "last session:.*NOT everything" && ok "status shows the last session" || bad "status does not show the last session"
  show_log
  slow_ip_off
  wait_for 15 sleepers_gone
  out=$(vs reset 2>&1)
  check "reset finishes the job" base_state
}

# --------------------------------------------------------------------- main
say "setting up the network (home VPN variant: $VARIANT)"
setup
configure || { echo "cannot configure vpnsplit"; exit 1; }
BASE=$(snap)

if [ "$VARIANT" != a ]; then
  say "variant $VARIANT: only the topology is built; vpnsplit supports policy routing from stage 2/3"
  echo "$BASE"
  exit 0
fi

want S0 && s_baseline
want S1 && s_signal S1 TERM
want S2 && { s_signal S2-INT INT; s_signal S2-HUP HUP; }
want S3 && s_kill9
want S4 && s_persistent
want S5 && s_second
want S6 && { s_tui q; s_tui ctrlc; s_tui sigterm; s_tui sighup; s_tui hangup; s_tui_second; }
want S7 && s_tui_foreign
want S8 && s_cleanup_signals

say "result: $PASS ok, $FAIL failed"
for f in "${FAILED[@]+"${FAILED[@]}"}"; do echo "  FAIL $f"; done
[ "$FAIL" = 0 ]
