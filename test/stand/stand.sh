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
# The home VPN client at the start (HOME_VARIANT):
#   a  0/1 + 128/1 in the main table (what vpnsplit itself does without a client), its server pinned
#   b  sing-box style: tunnel sockets are marked 2022, "pref 9000 not fwmark 2022 lookup 2022",
#      table 2022 has the default route through wghome. The main table is not looked at.
#   c  wg-quick style: fwmark 51820, "not fwmark 51820 lookup 51820" and, before it,
#      "lookup main suppress_prefixlength 0"
# In b and c the clients keep their own packets off the tunnel by the mark, not by a host route.
# With b vpnsplit puts its corp and direct routes into table 247 and adds one rule "lookup 247" before the client's.
home_client_a() {
  ip -n client route add 198.18.1.2/32 via 192.168.1.1 dev eth0
  ip -n client route add 198.18.2.2/32 via 192.168.1.1 dev eth0
}
home_client_b() {
  ip netns exec client wg set wgcorp fwmark 2022
  ip netns exec client wg set wghome fwmark 2022
  ip -n client route add default dev wghome table 2022
  ip -n client rule add pref 9000 not fwmark 2022 table 2022
}
home_client_c() {
  ip netns exec client wg set wgcorp fwmark 51820
  ip netns exec client wg set wghome fwmark 51820
  ip -n client route add default dev wghome table 51820
  ip -n client rule add not fwmark 51820 table 51820
  ip -n client rule add table main suppress_prefixlength 0
}
# the corp client brings its tunnel back (the same, for wgcorp)
corp_up() {
  ip -n client link add wgcorp type wireguard
  ip -n client addr add 10.200.0.2/24 dev wgcorp
  ip netns exec client wg set wgcorp private-key $WORK/keys/client_corp.key peer "$(cat $WORK/keys/corp.pub)" allowed-ips 0.0.0.0/0 endpoint 198.18.1.2:51820
  case "$VARIANT" in
    b) ip netns exec client wg set wgcorp fwmark 2022 ;;
    c) ip netns exec client wg set wgcorp fwmark 51820 ;;
  esac
  ip -n client link set wgcorp up
}
# what the client does again after its tunnel was recreated
home_up() {
  ip -n client link add wghome type wireguard
  ip -n client addr add 10.201.0.2/24 dev wghome
  ip netns exec client wg set wghome private-key $WORK/keys/client_home.key peer "$(cat $WORK/keys/home.pub)" allowed-ips 0.0.0.0/0 endpoint 198.18.2.2:51820
  case "$VARIANT" in
    b) ip netns exec client wg set wghome fwmark 2022 ;;
    c) ip netns exec client wg set wghome fwmark 51820 ;;
  esac
  ip -n client link set wghome up
  case "$VARIANT" in
    b) ip -n client route add default dev wghome table 2022 ;;
    c) ip -n client route add default dev wghome table 51820 ;;
  esac
}

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
  home_client_$VARIANT

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
# every class is routed as wanted and the journal says the apply is over
applied() {
  dev_is 203.0.113.11 wgcorp && dev_is 10.10.1.1 wgcorp && dev_is 203.0.113.12 eth0 && dev_is 203.0.113.13 wghome &&
    ! grep -q '"sig": "pending"' /var/lib/vpnsplit/state.json 2>/dev/null
}
# the same for a shell command (the menu runner starts it with sh -c)
READY='for p in "203.0.113.11 wgcorp" "10.10.1.1 wgcorp" "203.0.113.12 eth0" "203.0.113.13 wghome"; do set -- $p; ip -n client -4 route get $1 | grep -q "dev $2" || exit 1; done; ! grep -q pending /var/lib/vpnsplit/state.json'
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
  rm -f /var/lib/vpnsplit/state.json /var/lib/vpnsplit/snapshot.json
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

want() { [ -z "$ONLY" ] || [ "$1" = "$ONLY" ]; }

# --------------------------------------------------------------- scenarios
s_baseline() {
  CUR=S0
  say "S0 baseline: without vpnsplit everything goes to inet (variants b, c: the home client takes everything)"
  local want=inet
  [ "$VARIANT" = a ] || want=home
  for ip in 10 11 12 13; do check "curl 203.0.113.$ip answers $want" test "$(path_of 203.0.113.$ip)" = $want; done
  # in b the client's rule catches the corp tunnel's own network too: that is what vpnsplit's rules are for
  [ "$VARIANT" = b ] || check "tunnels work: wgcorp reaches the corp DNS" ip netns exec client curl -s --max-time 3 -o /dev/null http://10.200.0.1/
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
  if [ "$VARIANT" = a ]; then
    grep -q "full tunnel 0/1+128/1 removed" "$RLOG" && ok "reported: full tunnel removed" || bad "no 'full tunnel removed' in the output"
    grep -q "All traffic now goes straight through your ISP" "$RLOG" && ok "said where the traffic goes now" || bad "no note about direct traffic"
  else
    grep -q "full tunnel" "$RLOG" && bad "full tunnel reported although the home client routes everything itself" || ok "no full tunnel of ours: the home client does it"
  fi
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
  grep -q "state before the earlier run: Restored to the state before the start" "$RLOG" && ok "the recovery compared with the snapshot of the dead session: restored" || bad "no verdict about the state before the dead session"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  grep -q "Restored to the state before the start" "$RLOG" && ok "the end says: restored to the state before the start" || bad "no 'Restored' verdict at the end"
  check "the last session note says it" grep -q "Restored to the state before the start" /var/lib/vpnsplit/last-session.log
  check "the snapshot file is gone with the session" test ! -e /var/lib/vpnsplit/snapshot.json
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
  out=$(python3 $STAND/tuirun.py "$1" "$READY" "$BIN" 2>&1)
  echo "$out" | head -1 | sed 's/^/        | /'
  if [ "$1" = hangup ]; then
    check "exited" bash -c "echo '$out' | grep -q 'EXIT=[0-9]'"
  else
    echo "$out" | grep -q 'EXIT=0' && ok "exit code 0" || bad "exit code: $(echo "$out" | head -1)"
    [ "$VARIANT" != a ] || { echo "$out" | grep -q "full tunnel\|полный туннель 0/1+128/1 снят" && ok "reported: full tunnel removed" || bad "no 'full tunnel removed' on the screen"; }
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
  echo "$out" | head -${DBG:-1} | sed 's/^/        | /'
  echo "$out" | grep -q 'EXIT=0' && ok "exit code 0 on t, q" || bad "exit code: $(echo "$out" | head -1)"
  if [ "$VARIANT" = a ]; then
    echo "$out" | grep -q "полный туннель 0/1+128/1 снят" && ok "reported: full tunnel removed" || bad "no 'full tunnel removed' on the screen"
    echo "$out" | grep -q "Весь трафик теперь идёт напрямую" && ok "said where the traffic goes now" || bad "no note about direct traffic"
  fi
  check "the routing table equals the snapshot" base_state
  check "the outcome is written down" grep -q "снято" /var/lib/vpnsplit/last-session.log
}

# Slow removals (8 s each): the cleanup is still running when the next signal comes. The stand's
# binary is built with -tags vpnsplit_stand, which makes it look at /tmp/stand/slow-del.
slow_ip_on() {
  mkdir -p /tmp/stand
  echo 8 > /tmp/stand/slow-del
}
slow_ip_off() { rm -f /tmp/stand/slow-del; }

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
  check "the routes were not removed yet" dev_is 203.0.113.11 wgcorp
  show_log
  slow_ip_off
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
  out=$(vs reset 2>&1)
  check "reset finishes the job" base_state
}

# S9: the home VPN reconnects under the same name (a new interface index, the routes of the old
# one are gone). The routes must be back within 5 s, with no help from outside.
s_reconnect() {
  CUR=S9
  say "S9: the home VPN is deleted and created again with the same name: the routes are back in 5 s"
  fresh
  start_run s9 run
  check "routes applied" wait_for 20 applied
  local idx0 t0 t1
  idx0=$(ip -n client -o link show wghome | cut -d: -f1)
  ip -n client link del wghome
  home_up
  t0=$EPOCHREALTIME
  check "the interface has another index" test "$(ip -n client -o link show wghome | cut -d: -f1)" != "$idx0"
  check "routes restored within 5 s" wait_for 5 applied
  t1=$EPOCHREALTIME
  echo "        | restored after $(awk "BEGIN{printf \"%.1f\", $t1 - $t0}") s"
  routes_ok

  say "S9b: the same, but the home VPN is away for 3 s (the routes are removed and added again)"
  ip -n client link del wghome
  sleep 3
  home_up
  check "routes restored within 5 s" wait_for 5 applied
  routes_ok
  say "S9c: the corp VPN reconnects the same way"
  ip -n client link del wgcorp
  corp_up
  check "routes restored within 5 s" wait_for 5 applied
  routes_ok
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  show_log
  # the next scenarios need the BASE interface (the index is not part of the snapshot)
}

# S10: 2000 corp prefixes. Apply is fast, the cleanup on SIGTERM fits the 4.5 s budget.
s_many() {
  CUR=S10
  say "S10: 2000 corp prefixes: apply in a reasonable time, SIGTERM cleanup within 4.5 s"
  local cfg=/root/.config/vpnsplit/config.json
  cp "$cfg" "$WORK/config.json.bak"
  for ((i = 0; i < 2000; i++)); do echo "172.$((16 + i / 256)).$((i % 256)).0/24"; done > "$WORK/big.rules"
  vs import "$WORK/big.rules" >/dev/null 2>&1 || bad "import of the rules failed"
  BASE=$(snap)
  fresh
  local t0 t1 el
  t0=$EPOCHREALTIME
  start_run s10 run
  check "routes applied" wait_for 60 applied
  t1=$EPOCHREALTIME
  el=$(awk "BEGIN{printf \"%.1f\", $t1 - $t0}")
  check "apply took ${el} s (< 15 s)" awk "BEGIN{exit !($el < 15)}"
  check "a prefix from the middle goes through wgcorp" dev_is 172.19.3.7 wgcorp
  check "the last prefix goes through wgcorp" dev_is 172.23.207.9 wgcorp
  check "curl 203.0.113.13 answers home" test "$(path_of 203.0.113.13)" = home
  local n
  n=$(ip -n client -4 route show table all | grep -c 'proto 247')
  check "all routes carry the tag: $n lines with proto 247 (>= 2000)" test "$n" -ge 2000
  if [ "$VARIANT" = b ]; then
    n=$(ip -n client -4 route show table 247 | grep -c 'proto 247')
    check "the routes are in table 247: $n (>= 2000)" test "$n" -ge 2000
    n=$(ip -n client -4 rule show | grep -c 'lookup 247')
    check "one policy rule for all prefixes: $n" test "$n" = 1
    n=$(ip -n client -4 rule show | grep -c 'lookup main')
    check "no rule per prefix: $n 'lookup main' rules (the system's own: 1)" test "$n" = 1
  fi
  check "the journal is a few hundred KB, not rewritten per route" test "$(stat -c %s /var/lib/vpnsplit/state.json)" -gt 100000
  # a second pass over the same rules changes nothing (the poll interval is 2 s)
  sleep 5
  [ "$(grep -cE "applying|restoring" "$RLOG")" = 1 ] && ok "no re-apply while nothing changed" || bad "run re-applied without a reason"
  t0=$EPOCHREALTIME
  kill -TERM "$RPID"
  reap
  t1=$EPOCHREALTIME
  el=$(awk "BEGIN{printf \"%.1f\", $t1 - $t0}")
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "SIGTERM cleanup of 2000 prefixes took ${el} s (< 4.5 s)" awk "BEGIN{exit !($el < 4.5)}"
  check "the routing table equals the snapshot" base_state
  grep -v "^  [+-] " "$RLOG" | sed "s/^/        | /" | head -40
  cp "$WORK/config.json.bak" "$cfg"
  BASE=$(snap)
}

# traffic to the corp targets that leaves through eth0 (what must never happen: eth0 is the way
# around every VPN). Prints the number of such packets seen while curl tries both targets.
leak_packets() {
  local f=$WORK/leak.pcap tp
  rm -f "$f"
  ip netns exec client tcpdump -i eth0 -n -U -w "$f" "dst host 203.0.113.11 or dst host 10.10.1.1 or dst host 10.200.0.1" >/dev/null 2>&1 &
  tp=$!
  sleep 0.7
  for t in 203.0.113.11 10.10.1.1; do ip netns exec client curl -s --max-time 2 -o /dev/null "http://$t/"; done
  sleep 0.5
  kill "$tp" 2>/dev/null
  wait "$tp" 2>/dev/null
  tcpdump -nr "$f" 2>/dev/null | wc -l
}

# S11: the corp adapter disappears (the VPN client crashed): what the corp prefixes lead to is the
# client's own policy routing (the home VPN), never eth0 around it.
s_leak() {
  CUR=S11
  say "S11: the corp adapter is deleted: traffic meant for corp does not leak to eth0 past the home VPN"
  fresh
  start_run s11 run
  check "routes applied" wait_for 20 applied
  local n
  if [ "$VARIANT" = b ]; then
    # control: a rule "to <prefix> lookup main" (what an earlier design added) does leak, and the probe sees it
    ip -n client rule add pref 4999 to 203.0.113.11/32 lookup main
    ip -n client link del wgcorp
    n=$(leak_packets)
    check "control: a 'to <prefix> lookup main' rule leaks ($n packets on eth0)" test "$n" -gt 0
    ip -n client rule del pref 4999
    corp_up
    check "routes restored after the control" wait_for 15 applied
  fi
  ip -n client link del wgcorp
  check "203.0.113.11 does not go out through eth0" bash -c "[ \"\$(ip -n client -4 route get 203.0.113.11 | grep -o 'dev [^ ]*' | head -1)\" != 'dev eth0' ]"
  n=$(leak_packets)
  check "no packet to the corp targets left through eth0 ($n)" test "$n" = 0
  local who
  who=$(path_of 203.0.113.11)
  check "curl 203.0.113.11 answers home or nothing, never inet (got '${who}')" test "$who" != inet
  sleep 3 # the watch has applied again by now, without the corp VPN
  n=$(leak_packets)
  check "still no packet through eth0 after the apply without corp ($n)" test "$n" = 0
  corp_up
  check "routes restored when the corp VPN is back" wait_for 15 applied
  routes_ok
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  show_log
}

# S12: a corp network that covers the servers of the VPNs is not applied: it would send the packets of
# the tunnels into a tunnel. The clients keep their servers off the tunnels by host routes through eth0
# (variant a does that itself; for b and c the scenario adds them, like a client that pins would).
s_endpoint() {
  CUR=S12
  say "S12: a corp network over the servers of the VPNs (198.18.0.0/16) is not applied, the home tunnel stays up"
  local cfg=/root/.config/vpnsplit/config.json
  cp "$cfg" "$WORK/config.json.bak"
  vs add 198.18.0.0/16 >/dev/null 2>&1 || bad "cannot add the rule"
  fresh
  if [ "$VARIANT" != a ]; then
    ip -n client route add 198.18.1.2/32 via 192.168.1.1 dev eth0
    ip -n client route add 198.18.2.2/32 via 192.168.1.1 dev eth0
  fi
  start_run s12 run
  check "routes applied" wait_for 20 applied
  check "the corp network 198.18.0.0/16 is not in any table" bash -c "! ip -n client -4 route show table all | grep -q '198.18.0.0/16'"
  grep -q "covers 198.18.2.2" "$RLOG" && ok "the warning names the home server" || bad "no warning about 198.18.2.2"
  grep -q "covers 198.18.1.2" "$RLOG" && ok "the warning names the corp server" || bad "no warning about 198.18.1.2"
  # the packets of the clients' own sockets carry their mark (b, c); everything else follows the client's rules
  local mark=
  case "$VARIANT" in b) mark="mark 2022" ;; c) mark="mark 51820" ;; esac
  check "198.18.2.2 (the home server), as the client's own packets, goes out through eth0"     bash -c "[ \"\$(ip -n client -4 route get 198.18.2.2 $mark | grep -o 'dev [^ ]*' | head -1)\" = 'dev eth0' ]"
  check "198.18.1.2 (the corp server), as the client's own packets, goes out through eth0"     bash -c "[ \"\$(ip -n client -4 route get 198.18.1.2 $mark | grep -o 'dev [^ ]*' | head -1)\" = 'dev eth0' ]"
  routes_ok
  # the tunnel is alive: a handshake in the last minute on both
  check "the home tunnel has a recent handshake" bash -c "t=\$(ip netns exec client wg show wghome latest-handshakes | awk '{print \$2}'); [ -n \"\$t\" ] && [ \$((\$(date +%s) - t)) -lt 60 ]"
  check "the corp tunnel has a recent handshake" bash -c "t=\$(ip netns exec client wg show wgcorp latest-handshakes | awk '{print \$2}'); [ -n \"\$t\" ] && [ \$((\$(date +%s) - t)) -lt 60 ]"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  if [ "$VARIANT" != a ]; then
    ip -n client route del 198.18.1.2/32
    ip -n client route del 198.18.2.2/32
  fi
  check "the routing table equals the snapshot" base_state
  show_log
  cp "$WORK/config.json.bak" "$cfg"
}

# S13: both VPNs reconnect under the same names, more than once (new interface indexes, the routes of the
# old adapters are gone), then the session ends: the system is what it was before the start, and
# the end says so.
s_reconnect_base() {
  CUR=S13
  say "S13: adapters reconnect (same names, new indexes) during the session; at the end ip route/rule == the snapshot"
  fresh
  start_run s13 run
  check "routes applied" wait_for 20 applied
  local idx0 idx1
  idx0=$(ip -n client -o link show wghome | cut -d: -f1)
  ip -n client link del wghome
  home_up
  check "routes restored" wait_for 8 applied
  ip -n client link del wgcorp
  corp_up
  check "routes restored again" wait_for 8 applied
  ip -n client link del wghome
  sleep 2.5
  home_up
  check "routes restored after a longer absence" wait_for 8 applied
  idx1=$(ip -n client -o link show wghome | cut -d: -f1)
  check "the home adapter has another index now ($idx0 -> $idx1)" test "$idx0" != "$idx1"
  out=$(vs diff 2>&1)
  echo "$out" | sed 's/^/        | /' | head -12
  echo "$out" | grep -q "<- ours" && ok "diff shows what is ours while the session runs" || bad "diff does not list our routes"
  echo "$out" | grep -q "<- not set by vpnsplit" && bad "diff blames a client for a route of ours" || ok "diff finds nothing foreign"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "ip route show table all + ip rule equal the snapshot" base_state
  grep -q "Restored to the state before the start" "$RLOG" && ok "the end says: restored to the state before the start" || bad "no 'Restored' verdict"
  check "the last session note says it" grep -q "Restored to the state before the start" /var/lib/vpnsplit/last-session.log
  check "the snapshot file is gone" test ! -e /var/lib/vpnsplit/snapshot.json
  show_log
}

# S14: the budget runs out (slow removals, SIGTERM): the journal stays, the next start finishes the job
# AND compares with the snapshot of the run that did not finish.
s_budget_base() {
  CUR=S14
  say "S14: SIGTERM with slow removals leaves a rest; the next start recovers and compares with the snapshot"
  fresh
  start_run s14 run
  check "routes applied" wait_for 20 applied
  slow_ip_on
  kill -TERM "$RPID"
  reap
  check "it exited non-zero (got $RCODE)" test "$RCODE" != 0 -a "$RCODE" != timeout
  check "the table still differs" test "$(snap)" != "$BASE"
  check "the journal keeps the entries" grep -q '"session"' /var/lib/vpnsplit/state.json
  check "the snapshot stays for the next start" test -s /var/lib/vpnsplit/snapshot.json
  slow_ip_off
  start_run s14b run
  check "routes applied again" wait_for 20 applied
  grep -q "did not clean up" "$RLOG" && ok "recovery was announced" || bad "no recovery message"
  grep -q "state before the earlier run: Restored to the state before the start" "$RLOG" && ok "the recovery compared with the snapshot: restored" || bad "no verdict about the state before the unfinished run"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "ip route show table all + ip rule equal the snapshot" base_state
  check "the snapshot file is gone" test ! -e /var/lib/vpnsplit/snapshot.json
  show_log
}

# S15: routes of an old version (metric 1, no protocol tag) for prefixes of the rules, and the old version's
# journal in the user's profile. The session takes them over and removes them; nothing of them stays.
s_legacy_base() {
  CUR=S15
  say "S15: routes and journal of an old version (metric 1, untagged, journal in the profile) are removed"
  fresh
  ip -n client route add 203.0.113.11/32 dev wgcorp metric 1
  ip -n client route add 203.0.113.12/32 via 192.168.1.1 dev eth0 metric 1
  mkdir -p /root/.config/vpnsplit
  cat > /root/.config/vpnsplit/state.json <<'JSON'
{"routes":[{"dest":"203.0.113.11/32","iface":"wgcorp","via":"corp"},{"dest":"203.0.113.12/32","iface":"eth0","gateway":"192.168.1.1","via":"direct"}],"sig":"old"}
JSON
  check "the old routes are in the table" test "$(snap)" != "$BASE"
  start_run s15 run
  check "routes applied" wait_for 20 applied
  grep -q "took over" "$RLOG" && ok "the old version's routes were taken over" || bad "no take-over message"
  check "the old journal was moved out of the profile" test ! -e /root/.config/vpnsplit/state.json
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "ip route show table all + ip rule equal the snapshot (the old routes are gone)" base_state
  grep -q "Restored to the state before the start" "$RLOG" && ok "the end says: restored to the state before the start" || bad "no 'Restored' verdict"
  show_log
}

# S16: a route that a "client" adds during the session is not ours: it stays, and the end names it.
# A route of ours that the journal never heard of (tag 247), on an adapter that no VPN client owns, is removed.
s_client_route() {
  CUR=S16
  say "S16: a client's route added during the session stays and is reported; a tagged route the journal lost (not on a client's adapter) is removed"
  fresh
  start_run s16 run
  check "routes applied" wait_for 20 applied
  ip -n client route add 192.0.2.0/24 dev wgcorp
  ip -n client route add 198.51.100.0/24 via 192.168.1.1 dev eth0 proto 247 metric 1
  out=$(vs diff 2>&1)
  echo "$out" | sed 's/^/        | /' | head -12
  echo "$out" | grep -q "192.0.2.0/24.*not set by vpnsplit: adapter wgcorp" && ok "diff names the client's route and its adapter" || bad "diff does not blame the client's route"
  echo "$out" | grep -q "198.51.100.0/24.*<- ours" && ok "diff knows the tagged route is ours" || bad "diff does not know the tagged route"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the client's route stays" bash -c "ip -n client -4 route show 192.0.2.0/24 | grep -q wgcorp"
  check "the tagged route of ours is gone" bash -c "! ip -n client -4 route show table all | grep -q 198.51.100.0/24"
  grep -q "Differences left: 1" "$RLOG" && ok "the end counts the difference" || bad "no 'Differences left: 1'"
  grep -q "not set by vpnsplit" "$RLOG" && ok "the end says it is not vpnsplit's" || bad "no 'not set by vpnsplit'"
  grep -q "192.0.2.0/24" "$RLOG" && ok "the end names the route" || bad "the route is not named"
  check "the last session note says it" grep -q "Differences left: 1" /var/lib/vpnsplit/last-session.log
  ip -n client route del 192.0.2.0/24
  check "the routing table equals the snapshot once the client's route is deleted" base_state
  show_log
}

# S17: after the snapshot a "client" puts a route with the very key of one of our planned routes into the
# main table (variant b: ours are in table 247, the client's is proto boot, metric 1, the shape of an old
# version's route; variants a and c, where ours are in main too, use another metric: the kernel holds
# one route per destination and metric). It is not ours and no plan makes it ours: it stays after the
# session, and the end names it as not set by vpnsplit.
s_same_key() {
  CUR=S17
  say "S17: a client's route with the key of our plan (main table, proto boot) survives the session and is named"
  fresh
  start_run s17 run
  check "routes applied" wait_for 20 applied
  local m=1
  [ "$VARIANT" = b ] || m=7
  ip -n client route add 203.0.113.11/32 dev wgcorp proto boot metric $m
  check "the client's route is in the table" bash -c "ip -n client -4 route show table main 203.0.113.11/32 | grep -q 'metric $m'"
  out=$(vs diff 2>&1)
  echo "$out" | sed 's/^/        | /' | head -12
  echo "$out" | grep -q "203.0.113.11/32.*proto 3.*not set by vpnsplit" && ok "diff names the client's route" || bad "diff does not blame the client's route"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the client's route stays" bash -c "ip -n client -4 route show table main 203.0.113.11/32 | grep -q 'metric $m'"
  check "our own routes are gone" bash -c "! ip -n client -4 route show table all | grep -q 'proto 247'"
  grep -q "not set by vpnsplit" "$RLOG" && ok "the end says it is not vpnsplit's" || bad "no 'not set by vpnsplit'"
  grep -q "203.0.113.11/32" "$RLOG" && ok "the end names the route" || bad "the route is not named"
  grep -q "OF OURS NOT REMOVED" "$RLOG" && bad "the end blames us for the client's route" || ok "the end does not call it ours"
  check "the last session note says it" grep -q "not set by vpnsplit" /var/lib/vpnsplit/last-session.log
  ip -n client route del 203.0.113.11/32 dev wgcorp proto boot metric $m
  check "the routing table equals the snapshot once the client's route is deleted" base_state
  show_log
}

# S18: a route that carries our tag but that the journal does not list, on the adapter of a recognized VPN client, is
# not removed (the comparison does not take such a route away from a client on the strength of a tag alone),
# and the end says it is probably ours and why it was left.
s_tag_on_client() {
  CUR=S18
  say "S18: a tagged route the journal lost, on a client's adapter (happ0), is left and reported"
  fresh
  # an adapter that vpnsplit recognizes as a VPN client's by its name (Happ)
  ip -n client link add happ0 type dummy
  ip -n client link set happ0 up
  start_run s18 run
  check "routes applied" wait_for 20 applied
  ip -n client route add 198.51.101.0/24 dev happ0 proto 247 metric 1
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the route stays" bash -c "ip -n client -4 route show table main 198.51.101.0/24 | grep -q happ0"
  grep -q "198.51.101.0/24" "$RLOG" && ok "the end names the route" || bad "the route is not named"
  grep -q "VPN client" "$RLOG" && ok "the end says why it was left" || bad "no reason given"
  ip -n client route del 198.51.101.0/24 dev happ0
  ip -n client link del happ0
  check "the routing table equals the snapshot once the route is deleted" base_state
  show_log
}

# --------------------------------------------------------------------- main
say "setting up the network (home VPN variant: $VARIANT)"
setup
configure || { echo "cannot configure vpnsplit"; exit 1; }
BASE=$(snap)

want S0 && s_baseline
want S1 && s_signal S1 TERM
want S2 && { s_signal S2-INT INT; s_signal S2-HUP HUP; }
want S3 && s_kill9
want S4 && s_persistent
want S5 && s_second
want S6 && { s_tui q; s_tui ctrlc; s_tui sigterm; s_tui sighup; s_tui hangup; s_tui_second; }
want S7 && s_tui_foreign
want S8 && s_cleanup_signals
want S9 && s_reconnect
want S10 && s_many
want S11 && s_leak
want S12 && s_endpoint
want S13 && s_reconnect_base
want S14 && s_budget_base
want S15 && s_legacy_base
want S16 && s_client_route
want S17 && s_same_key
want S18 && s_tag_on_client

say "result: $PASS ok, $FAIL failed"
for f in "${FAILED[@]+"${FAILED[@]}"}"; do echo "  FAIL $f"; done
[ "$FAIL" = 0 ]
