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
    --listen-address=1.1.1.1 --address=/direct.example/203.0.113.12 --address=/fake.example/198.19.5.5 --address=/fake28.example/28.5.5.5 --pid-file=$WORK/dns-inet.pid
  ip netns exec corp dnsmasq --user=root --conf-file=/dev/null --no-resolv --no-hosts --bind-interfaces \
    --listen-address=10.200.0.1 --address=/corp.example/10.10.1.1 --pid-file=$WORK/dns-corp.pid
  mkdir -p /etc/netns/client
  echo "nameserver 1.1.1.1" > /etc/netns/client/resolv.conf
  sleep 1
}

configure() {
  vs set corp wgcorp && vs set home wghome && vs set corp-dns 10.200.0.1 &&
    vs set rest home && vs set split-dns yes &&
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

# ------------------------------------------------------------ stage 3: DNS and IPv6
# A stand-in for systemd-resolved (the container has none): `resolvectl` keeps the per-link DNS servers and
# domains in files. vpnsplit asks it the way it asks the real one, so what it sets can be seen and "the
# network manager overwrote it" can be played. It exists only inside the stage-3 scenarios.
fake_resolved_on() {
  local d=$WORK/resolved
  rm -rf "$d"
  mkdir -p "$d"
  echo "1.1.1.1" > "$d/eth0.dns"
  echo "10.200.0.1" > "$d/wgcorp.dns"
  echo "10.201.0.1" > "$d/wghome.dns"
  : > "$d/eth0.domain"
  : > "$d/wgcorp.domain"
  : > "$d/wghome.domain"
  cp "$STAND/fake-resolvectl.sh" /usr/sbin/resolvectl
  chmod +x /usr/sbin/resolvectl
}
fake_resolved_off() { rm -f /usr/sbin/resolvectl; rm -rf "$WORK/resolved"; }
rdns() { cat "$WORK/resolved/$1.dns" 2>/dev/null; }
rdomain() { cat "$WORK/resolved/$1.domain" 2>/dev/null; }
resolved_base() { [ "$(rdns eth0)|$(rdns wgcorp)|$(rdns wghome)|$(rdomain eth0)|$(rdomain wgcorp)|$(rdomain wghome)" = "1.1.1.1|10.200.0.1|10.201.0.1|||" ]; }
has_dom() { # link domain
  grep -q -F -- "$2" "$WORK/resolved/$1.domain" 2>/dev/null
}

# packets seen on an interface of the client: cap_start <name> <iface> <tcpdump filter>; cap_stop <name>; cap_count <name>
cap_start() {
  : > "$WORK/cap.$1"
  ip netns exec client tcpdump -i "$2" -nn -l -U "$3" > "$WORK/cap.$1" 2> "$WORK/cap.$1.err" &
  eval "CAP_$1=$!"
}
cap_stop() {
  eval "local p=\$CAP_$1"
  kill "$p" 2>/dev/null
  wait "$p" 2>/dev/null
  return 0
}
cap_count() { grep -c . "$WORK/cap.$1"; }
cap_has() { grep -q -- "$2" "$WORK/cap.$1"; }

snap6() { { ip -n client -6 route show table all | grep -v -E "^(local|broadcast|multicast|anycast)|^fe80:"; ip -n client -6 rule show; } | sort; }
v6_on() { # the home VPN has a global IPv6 address and a host in its network; "v4only": its client takes IPv4 by its rules, not IPv6
  ip -n client addr add 2001:db8:77::2/64 dev wghome nodad
  ip -n home addr add 2001:db8:77::1/64 dev wghome nodad
  ip -n home addr add 2001:db8:ff::10/128 dev lo
  ip netns exec client wg set wghome peer "$(cat $WORK/keys/home.pub)" allowed-ips 0.0.0.0/0,::/0
  ip netns exec home wg set wghome peer "$(cat $WORK/keys/client_home.pub)" allowed-ips 10.201.0.2/32,2001:db8:77::2/128
  [ "${1:-}" = v4only ] && return 0
  case "$VARIANT" in
    b) ip -n client -6 route add default dev wghome table 2022; ip -n client -6 rule add pref 9000 not fwmark 2022 table 2022 ;;
    c) ip -n client -6 route add default dev wghome table 51820; ip -n client -6 rule add not fwmark 51820 table 51820; ip -n client -6 rule add table main suppress_prefixlength 0 ;;
  esac
}
v6_off() {
  case "$VARIANT" in
    b) ip -n client -6 rule del pref 9000 not fwmark 2022 table 2022 2>/dev/null; ip -n client -6 route del default dev wghome table 2022 2>/dev/null ;;
    c) ip -n client -6 rule del not fwmark 51820 table 51820 2>/dev/null; ip -n client -6 rule del table main suppress_prefixlength 0 2>/dev/null; ip -n client -6 route del default dev wghome table 51820 2>/dev/null ;;
  esac
  ip -n client addr del 2001:db8:77::2/64 dev wghome 2>/dev/null
  ip -n home addr del 2001:db8:77::1/64 dev wghome 2>/dev/null
  ip -n home addr del 2001:db8:ff::10/128 dev lo 2>/dev/null
  ip netns exec client wg set wghome peer "$(cat $WORK/keys/home.pub)" allowed-ips 0.0.0.0/0
  ip netns exec home wg set wghome peer "$(cat $WORK/keys/client_home.pub)" allowed-ips 10.201.0.2/32
}
path6() { ip netns exec client curl -6 -s --max-time 4 "http://[$1]/" 2>/dev/null; }

# S19: the names that go direct are asked of the provider's DNS, over the physical adapter; the corp names of
# the corp DNS, through the corp tunnel; no DNS question goes into the home VPN; a fake-ip answer
# (198.18.0.0/15) is dropped and reported, and no route is made for it.
s_dns_paths() {
  CUR=S19
  say "S19: DNS paths: direct names -> the provider's DNS (/32 over eth0), corp names -> the corp DNS (/32 over wgcorp), fake-ip dropped"
  fresh
  fake_resolved_on
  vs add --direct fake.example >/dev/null
  cap_start eth0 eth0 'udp port 53'
  cap_start home wghome 'udp port 53'
  cap_start corp wgcorp 'udp port 53'
  sleep 1
  start_run s19 run
  check "routes applied" wait_for 20 applied
  sleep 1
  cap_stop eth0
  cap_stop home
  cap_stop corp
  check "a /32 route to the provider's DNS 1.1.1.1 over eth0 and the gateway" bash -c "ip -n client -4 route show table all | grep -E '^1\.1\.1\.1 via 192\.168\.1\.1 dev eth0.*proto 247'"
  check "a /32 route to the corp DNS 10.200.0.1 over wgcorp" bash -c "ip -n client -4 route show table all | grep -E '^10\.200\.0\.1 dev wgcorp.*proto 247'"
  check "direct.example was asked of 1.1.1.1 on eth0" cap_has eth0 "direct.example"
  check "fake.example was asked of 1.1.1.1 on eth0" cap_has eth0 "fake.example"
  check "the questions on eth0 went to 1.1.1.1" cap_has eth0 "1.1.1.1.53"
  check "corp.example was asked of 10.200.0.1 on wgcorp" cap_has corp "10.200.0.1.53"
  check "no DNS question went into the home VPN (0 packets on wghome)" test "$(cap_count home)" = 0
  check "no question to 1.1.1.1 went into the corp tunnel" bash -c "! grep -q '1.1.1.1.53' $WORK/cap.corp"
  check "no question to the corp DNS went to eth0" bash -c "! grep -q '10.200.0.1' $WORK/cap.eth0"
  check "the fake-ip answer 198.19.5.5 got no route of its own" bash -c "! ip -n client -4 route show table all | grep -E '^198\.19\.5\.5'"
  check "the zone of the direct name is routed to the provider's DNS (domain ~direct.example on eth0)" has_dom eth0 "~direct.example"
  check "the journal lists the zone on eth0" grep -q 'domain eth0 direct.example' /var/lib/vpnsplit/state.json
  check "the provider's own DNS server of eth0 is kept" test "$(rdns eth0)" = 1.1.1.1
  grep -q "fake-ip answers (198.18.0.0/15.*) dropped" "$RLOG" && ok "the report names the fake-ip answer" || bad "no fake-ip note in the output"
  grep -q "fake.example=198.19.5.5" "$RLOG" && ok "the report names the name and the address" || bad "name and address not in the output"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  check "the DNS of the links is as before" resolved_base
  vs remove --direct fake.example >/dev/null
  fake_resolved_off
  show_log
}

# S20: DNS of the rest goes to the home VPN (~. on its link, systemd-resolved), the corp zone to the corp link;
# a network manager that wipes the domain is answered by a repair in the loop of `run`; the end restores the links.
s_dns_rest() {
  CUR=S20
  say "S20: '~.' on the home link, repair after the domain is wiped, clean end"
  fresh
  fake_resolved_on
  start_run s20 run
  check "routes applied" wait_for 20 applied
  check "the home link routes everything else (~.)" has_dom wghome "~."
  check "the home link kept its own DNS server" test "$(rdns wghome)" = 10.201.0.1
  check "the corp zone is on the corp link" has_dom wgcorp "~corp.example"
  check "the journal lists the entry for the rest" grep -q 'domain wghome \.' /var/lib/vpnsplit/state.json
  : > "$WORK/resolved/wghome.domain" # the network manager rewrites the link
  check "the domain was put back by the loop (<= 45 s)" wait_for 45 has_dom wghome "~."
  check "the journal lists the entry once" test "$(tr ',' '\n' < /var/lib/vpnsplit/state.json | grep -c '^ *"domain wghome \. [0-9]*"')" = 1
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  check "the DNS of the links is as before" resolved_base
  fake_resolved_off
  show_log
}

# S21: the home VPN has a global IPv6 address: ::/1 and 8000::/1 go through it, a host reachable only over it
# answers (curl -6), and the end restores the IPv6 table. Without IPv6 on the home VPN and with it on eth0 `status`
# announces the leak and nothing is made for IPv6.
s_ipv6() {
  CUR=S21
  say "S21: IPv6 into the home VPN, and the announced leak"
  fresh
  v6_on
  local base6
  base6=$(snap6)
  if [ "$VARIANT" = a ]; then
    check "without vpnsplit the v6-only host is unreachable" test -z "$(path6 2001:db8:ff::10)"
  else
    check "without vpnsplit the home client takes IPv6 itself" test "$(path6 2001:db8:ff::10)" = home
  fi
  cap_start h6 wghome 'ip6 and host 2001:db8:ff::10'
  cap_start e6 eth0 'ip6 and host 2001:db8:ff::10'
  sleep 1
  start_run s21 run
  check "routes applied" wait_for 20 applied
  if [ "$VARIANT" = a ]; then
    check "::/1 through wghome, tagged" bash -c "ip -n client -6 route show table all | grep -E '^::/1 dev wghome.*proto 247'"
    check "8000::/1 through wghome, tagged" bash -c "ip -n client -6 route show table all | grep -E '^8000::/1 dev wghome.*proto 247'"
  else # the home client has taken IPv6 itself (as it takes IPv4): no halves of ours
    check "no IPv6 route of ours (the home client has them)" bash -c "! ip -n client -6 route show table all | grep -q 'proto 247'"
  fi
  check "the v6 host is routed through wghome" bash -c "ip -n client -6 route get 2001:db8:ff::10 | grep -q 'dev wghome'"
  check "curl -6 answers home" test "$(path6 2001:db8:ff::10)" = home
  sleep 1
  cap_stop h6
  cap_stop e6
  check "the IPv6 packets to the v6 host were seen on wghome" cap_has h6 "2001:db8:ff::10"
  check "no IPv6 packet to the v6 host went out of eth0" test "$(cap_count e6)" = 0
  vs status 2>&1 | grep -q 'IPv6 goes into the home VPN' && ok "status says IPv6 is tunnelled" || bad "status does not mention the IPv6 tunnel"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the IPv4 routing table equals the snapshot" base_state
  check "the IPv6 routing table equals the snapshot" test "$(snap6)" = "$base6"
  v6_off

  say "S21b: the home VPN has no IPv6, eth0 has: the leak is announced, no IPv6 route is made"
  ip -n client addr add 2001:db8:1::2/64 dev eth0 nodad
  ip -n isp addr add 2001:db8:1::1/64 dev c0 nodad
  base6=$(snap6)
  out=$(vs status 2>&1)
  echo "$out" | grep -E "IPv6|!!!" | sed 's/^/        | /'
  echo "$out" | grep -q "IPv6 goes past the home VPN" && ok "status announces that IPv6 goes past the home VPN" || bad "status does not announce the IPv6 leak"
  start_run s21b run
  check "routes applied" wait_for 20 applied
  check "no IPv6 route through wghome" bash -c "! ip -n client -6 route show table all | grep -q 'dev wghome.*proto 247'"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the IPv6 routing table equals the snapshot" test "$(snap6)" = "$base6"
  ip -n client addr del 2001:db8:1::2/64 dev eth0
  ip -n isp addr del 2001:db8:1::1/64 dev c0
  check "the routing table equals the snapshot" base_state
}

# the rest goes direct: corp and --home rules are in place
rest_direct_ready() {
  dev_is 203.0.113.11 wgcorp && dev_is 203.0.113.13 wghome && dev_is 203.0.113.10 eth0 && ! grep -q pending /var/lib/vpnsplit/state.json
}
# the rest is left to the client: corp and direct rules are in place
rest_keep_ready() {
  dev_is 203.0.113.11 wgcorp && dev_is 203.0.113.12 eth0 && ! grep -q pending /var/lib/vpnsplit/state.json
}

# S22: "the rest" goes direct, the rules "through the home VPN" decide what still goes there; direct rules do not
# apply (everything else is direct anyway) and cannot be added.
s_rest_direct() {
  CUR=S22
  say "S22: rest = direct: 0/1 + 128/1 over eth0, --home rules into wghome, the home VPN gets no DNS"
  fresh
  fake_resolved_on
  vs set rest direct >/dev/null
  vs add --home 203.0.113.13 >/dev/null
  out=$(vs add --direct 192.0.2.77 2>&1)
  rc=$?
  check "a --direct rule is refused while the rest goes direct (exit $rc)" test "$rc" != 0
  echo "$out" | grep -q "no meaning" && ok "the refusal says why" || bad "no explanation for the refused rule"
  cap_start home wghome 'host 203.0.113.10 or host 203.0.113.13'
  cap_start eth0 eth0 'host 203.0.113.10'
  sleep 1
  start_run s22 run
  check "routes applied" wait_for 20 rest_direct_ready
  check "203.0.113.10 (the rest) goes over eth0" bash -c "ip -n client -4 route get 203.0.113.10 | grep -q 'dev eth0'"
  check "curl 203.0.113.10 answers inet" test "$(path_of 203.0.113.10)" = inet
  check "curl 203.0.113.13 (--home rule) answers home" test "$(path_of 203.0.113.13)" = home
  check "curl 203.0.113.11 (corp) answers corp" test "$(path_of 203.0.113.11)" = corp
  sleep 1 # tcpdump reads what the kernel queued before it is stopped
  cap_stop eth0
  cap_stop home
  check "the capture on wghome works (it saw the packets to 203.0.113.13)" cap_has home 203.0.113.13
  check "no packet to 203.0.113.10 went into the home VPN" bash -c "! grep -q '203.0.113.10' $WORK/cap.home"
  check "the packets to 203.0.113.10 went over eth0 ($(cap_count eth0) seen)" test "$(cap_count eth0)" -gt 0
  check "the home link has no routing domain for everything" bash -c "! grep -q -F '~.' $WORK/resolved/wghome.domain"
  check "the journal has no DNS entry for the rest" bash -c "! grep -q 'domain wghome' /var/lib/vpnsplit/state.json"
  vs rules 2>&1 | grep -q "^direct" && bad "rules shows the kind that does not matter" || ok "rules shows only the kinds that matter"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  check "the DNS of the links is as before" resolved_base
  vs remove --home 203.0.113.13 >/dev/null
  vs set rest home >/dev/null
  fake_resolved_off
  show_log
}

# S23: "do not touch": the corp and direct rules apply, no 0/1 + 128/1 and no DNS for the rest; whatever the home
# client does stays as it is (variant a: nothing, so the rest goes over eth0, as in S0).
s_rest_keep() {
  CUR=S23
  say "S23: rest = keep: no default halves, no DNS for the rest, the rules apply"
  fresh
  fake_resolved_on
  vs set rest keep >/dev/null
  start_run s23 run
  check "routes applied" wait_for 20 rest_keep_ready
  check "no 0.0.0.0/1 or 128.0.0.0/1 of ours" bash -c "! ip -n client -4 route show table all | grep -E '^(0.0.0.0/1|128.0.0.0/1) .*proto 247'"
  local want=inet
  [ "$VARIANT" = a ] || want=home
  check "the rest is left to the client: curl 203.0.113.10 answers $want" test "$(path_of 203.0.113.10)" = $want
  check "curl 203.0.113.11 answers corp" test "$(path_of 203.0.113.11)" = corp
  check "curl 203.0.113.12 answers inet (direct)" test "$(path_of 203.0.113.12)" = inet
  check "the home link has no routing domain for everything" bash -c "! grep -q -F '~.' $WORK/resolved/wghome.domain"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  check "the DNS of the links is as before" resolved_base
  vs set rest home >/dev/null
  fake_resolved_off
  show_log
}

# S24: the DNS servers of the provider include the DNS of the home VPN (a router that hands out whatever it was told):
# no /32 route around the tunnel is made for it, the report says so, and the names that go direct are asked of the
# other server of the provider.
s_dns_overlap() {
  CUR=S24
  say "S24: the provider's DNS list holds the home VPN's DNS: no route for it, a warning, the other server is used"
  fresh
  fake_resolved_on
  echo "1.1.1.1 10.201.0.1" > "$WORK/resolved/eth0.dns"
  cap_start eth0 eth0 'udp port 53'
  sleep 1
  start_run s24 run
  check "routes applied" wait_for 20 applied
  sleep 1
  cap_stop eth0
  check "the report names the overlap" grep -q "10.201.0.1 of the provider is the DNS server of the home VPN" "$RLOG"
  check "no /32 route to 10.201.0.1 over eth0" bash -c "! ip -n client -4 route show table all | grep -E '^10\.201\.0\.1 .*dev eth0'"
  check "the route to the other server 1.1.1.1 over eth0 is there" bash -c "ip -n client -4 route show table all | grep -E '^1\.1\.1\.1 via 192\.168\.1\.1 dev eth0.*proto 247'"
  check "direct.example was asked of 1.1.1.1 on eth0" cap_has eth0 "1.1.1.1.53"
  check "the zone of the direct name is set up on eth0" grep -q 'direct.example' "$WORK/resolved/eth0.domain"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state
  echo "1.1.1.1" > "$WORK/resolved/eth0.dns"
  check "the DNS of the links is as before" resolved_base
  fake_resolved_off
  show_log
}

# S25: somebody else has "~." on the home link already: it is left as it is and never taken away, and it is not a
# reason to redo the DNS entries and flush the cache at every apply (a second apply is forced by a changed rule).
s_dns_foreign() {
  CUR=S25
  say "S25: a '~.' that is not ours: left alone, not remade (no repeated '=' and no more flushes), never removed"
  fresh
  fake_resolved_on
  echo "~." > "$WORK/resolved/wghome.domain"
  start_run s25 run
  check "routes applied" wait_for 20 applied
  check "the report says the entry was there already" grep -q "= domain wghome \. [0-9]*: " "$RLOG"
  check "the journal does not list the entry as ours" bash -c "! grep -E '^ +\"domain wghome \. [0-9]+\",?$' /var/lib/vpnsplit/state.json"
  check "the corp zone is set up as usual" has_dom wgcorp "~corp.example"
  local f1 f2 n1 n2 w1 w2
  f1=$(grep -c flush "$WORK/resolved/calls.log")
  w1=$(grep -c wghome "$WORK/resolved/calls.log")
  n1=$(grep -c "= domain wghome \." "$RLOG")
  vs add 192.0.2.0/24 >/dev/null # the rules changed: run applies again
  check "run applied the changed rules" wait_for 20 bash -c "ip -n client -4 route show table all | grep -q '^192\.0\.2\.0/24'"
  sleep 6
  f2=$(grep -c flush "$WORK/resolved/calls.log")
  w2=$(grep -c wghome "$WORK/resolved/calls.log")
  n2=$(grep -c "= domain wghome \." "$RLOG")
  check "the second apply did not flush the DNS cache again ($f1 -> $f2)" test "$f1" = "$f2"
  check "the second apply did not report the foreign entry again ($n1 -> $n2)" test "$n1" = "$n2"
  check "the second apply did not write the home link again ($w1 -> $w2)" test "$w1" = "$w2"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the foreign '~.' is still on the home link" has_dom wghome "~."
  vs remove 192.0.2.0/24 >/dev/null
  check "the routing table equals the snapshot" base_state
  : > "$WORK/resolved/wghome.domain"
  check "the DNS of the links is as before" resolved_base
  fake_resolved_off
  show_log
}

# S26 (variants b and c): the home VPN has IPv6 but its client takes only IPv4 by its rules. IPv6 of eth0 goes past
# the tunnel; `status` announces it prominently; vpnsplit makes no IPv6 routes of its own.
s_ipv6_v4only() {
  CUR=S26
  say "S26: the home client takes IPv4 by its rules, not IPv6: the leak is announced"
  if [ "$VARIANT" = a ]; then
    echo "   (variant a: the halves are vpnsplit's own, covered by S21)"
    return 0
  fi
  fresh
  v6_on v4only
  ip -n client addr add 2001:db8:1::2/64 dev eth0 nodad
  ip -n isp addr add 2001:db8:1::1/64 dev c0 nodad
  local base6
  base6=$(snap6)
  out=$(vs status 2>&1)
  echo "$out" | grep -E "IPv6|!!!" | sed 's/^/        | /'
  echo "$out" | grep -q "!!!.*only IPv4" && ok "status announces that IPv6 goes past the home VPN (its client takes IPv4 only)" || bad "no highlighted IPv6 leak in status"
  start_run s26 run
  check "routes applied" wait_for 20 applied
  check "no IPv6 route of ours" bash -c "! ip -n client -6 route show table all | grep -q 'proto 247'"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the IPv6 routing table equals the snapshot" test "$(snap6)" = "$base6"
  ip -n client addr del 2001:db8:1::2/64 dev eth0
  ip -n isp addr del 2001:db8:1::1/64 dev c0
  v6_off
  check "the routing table equals the snapshot" base_state
}

# S27: resolvectl does not answer when asked (a timeout, resolved restarting): that is not "the link has no DNS
# servers" and not "the link has no such domain". Nothing is planned for the links, nothing is written; and when
# the answer is missing at the end, the entries stay in the journal and the domains stay as they are, until
# `reset` is able to ask.
s_dns_readfail() {
  CUR=S27
  say "S27: resolvectl fails when read: no DNS entries are made, the domains of the links are not wiped"
  fresh
  fake_resolved_on
  echo "existing.local" > "$WORK/resolved/eth0.domain"
  touch "$WORK/resolved/fail"
  start_run s27 run
  check "routes applied" wait_for 20 applied
  check "resolvectl was never asked to change anything" bash -c "! grep -q -E '^(dns|domain) ' $WORK/resolved/calls.log 2>/dev/null"
  check "the domains of eth0 are as they were" test "$(rdomain eth0)" = existing.local
  check "the DNS servers of eth0 are as they were" test "$(rdns eth0)" = 1.1.1.1
  check "the journal has no DNS entry" bash -c "! grep -q -E '\"(dns|domain) ' /var/lib/vpnsplit/state.json"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the domains of eth0 are still as they were" test "$(rdomain eth0)" = existing.local
  check "the routing table equals the snapshot" base_state
  rm -f "$WORK/resolved/fail"
  : > "$WORK/resolved/eth0.domain"

  say "S27b: the entries are made, then resolvectl stops answering: the end leaves them and the journal keeps them"
  start_run s27b run
  check "routes applied" wait_for 20 applied
  check "the corp zone is on the corp link" has_dom wgcorp "~corp.example"
  touch "$WORK/resolved/fail"
  kill -TERM "$RPID"
  reap
  check "the corp zone is left on the corp link (not asked, not touched)" has_dom wgcorp "~corp.example"
  check "the journal keeps the entry" grep -q 'domain wgcorp corp.example' /var/lib/vpnsplit/state.json
  rm -f "$WORK/resolved/fail"
  vs reset >/dev/null 2>&1
  check "reset removed the entry once resolvectl answers" bash -c "! grep -q 'domain wgcorp' /var/lib/vpnsplit/state.json"
  check "the DNS of the links is as before" resolved_base
  check "the routing table equals the snapshot" base_state
  fake_resolved_off
  show_log
}

# ------------------------------------------------------------ stage 4: detection and warnings
# The diagnostics only read. Each scenario puts the "client" into a state that has a finding, looks at what
# `vpnsplit status` says about it, and checks that nothing changed in the routing table (or, in the scenarios
# that run a session, that the end restores the snapshot).
diag_out() { vs status 2>&1; }
has_diag() { # level code (the output of status is in $DIAG)
  printf '%s\n' "$DIAG" | grep -q -E "^  \[$1\] $2:"
}
no_diag() { ! printf '%s\n' "$DIAG" | grep -q -E "^  \[[a-z]+\] $1:"; }
show_diag() { printf '%s\n' "$DIAG" | grep -E '^diagnostics|^  \[|^      ->' | sed 's/^/        | /'; }
no_warn() { ! printf '%s\n' "$DIAG" | grep -q -E '^  \[(warn|danger)\]'; }
cfg_save() { cp /root/.config/vpnsplit/config.json "$WORK/config.json.bak"; }
cfg_back() { cp "$WORK/config.json.bak" /root/.config/vpnsplit/config.json; }

# S28: the setup of the stand has nothing to warn about (the home client of variants b and c is a full tunnel
# by its policy table, which is a note, not a warning)
s_diag_quiet() {
  CUR=S28
  say "S28: nothing to warn about in the plain setup; status changes nothing"
  fresh
  local before
  before=$(snap)
  DIAG=$(diag_out)
  show_diag
  check "no warning or danger" no_warn
  if [ "$VARIANT" = a ]; then
    check "no WG finding in variant a" no_diag WG_FULL_TUNNEL
  else
    check "the home client's full tunnel is a note (policy table)" has_diag info WG_FULL_TUNNEL
    printf '%s\n' "$DIAG" | grep -q "policy table" && ok "the note names the policy table" || bad "no policy table in the WG note"
  fi
  check "the routing table is unchanged by status" test "$(snap)" = "$before"
  check "the routing table equals the snapshot" base_state
}

# S29: WireGuard with AllowedIPs 0.0.0.0/0 takes all the traffic (a: the client's halves in the main table)
s_diag_wg() {
  CUR=S29
  say "S29: the home WireGuard is a full tunnel (wg-quick table, or the halves in the main table)"
  fresh
  if [ "$VARIANT" = a ]; then
    ip -n client route add 0.0.0.0/1 dev wghome
    ip -n client route add 128.0.0.0/1 dev wghome
  fi
  local before
  before=$(snap)
  DIAG=$(diag_out)
  show_diag
  check "WG_FULL_TUNNEL is reported as a note" has_diag info WG_FULL_TUNNEL
  check "the routing table is unchanged by status" test "$(snap)" = "$before"
  # a third WireGuard that takes everything is a warning
  ip -n client link add wg9 type wireguard
  ip -n client addr add 10.99.0.2/24 dev wg9
  ip -n client link set wg9 up
  ip -n client route add 0.0.0.0/1 dev wg9 metric 5
  ip -n client route add 128.0.0.0/1 dev wg9 metric 5
  DIAG=$(diag_out)
  show_diag
  check "a third WireGuard with a full tunnel is a warning" has_diag warn WG_FULL_TUNNEL
  ip -n client link del wg9
  if [ "$VARIANT" = a ]; then
    ip -n client route del 0.0.0.0/1 dev wghome
    ip -n client route del 128.0.0.0/1 dev wghome
  fi
  check "the routing table equals the snapshot" base_state
}

# S30: the corp VPN takes the whole address space
s_diag_corp_full() {
  CUR=S30
  say "S30: the corp VPN in a full tunnel (0/1 + 128/1 through wgcorp) is a warning"
  fresh
  ip -n client route add 0.0.0.0/1 dev wgcorp
  ip -n client route add 128.0.0.0/1 dev wgcorp
  local before
  before=$(snap)
  DIAG=$(diag_out)
  show_diag
  check "CORP_FULL_TUNNEL is a warning" has_diag warn CORP_FULL_TUNNEL
  printf '%s\n' "$DIAG" | grep -q "0.0.0.0/1 + 128.0.0.0/1" && ok "it names the halves" || bad "the halves are not named"
  check "the routing table is unchanged by status" test "$(snap)" = "$before"
  ip -n client route del 0.0.0.0/1 dev wgcorp
  ip -n client route del 128.0.0.0/1 dev wgcorp
  ip -n client route del default via 192.168.1.1 dev eth0
  ip -n client route add default via 192.168.1.1 dev eth0 metric 100
  ip -n client route add default dev wgcorp metric 50
  DIAG=$(diag_out)
  check "a default route with a better metric than eth0 is a warning too" has_diag warn CORP_FULL_TUNNEL
  ip -n client route del default dev wgcorp metric 50
  ip -n client route add default dev wgcorp metric 5000
  DIAG=$(diag_out)
  check "a default route that loses to eth0 is not" no_diag CORP_FULL_TUNNEL
  ip -n client route del default dev wgcorp metric 5000
  ip -n client route del default via 192.168.1.1 dev eth0 metric 100
  ip -n client route add default via 192.168.1.1 dev eth0
  check "the routing table equals the snapshot" base_state
}

# S31: rules that overlap the local network, a docker bridge, CGNAT; a session runs and ends clean
s_diag_overlap() {
  CUR=S31
  say "S31: a corp rule over the LAN (192.168.0.0/16), docker (172.16.0.0/12) and CGNAT (100.64.0.0/10)"
  cfg_save
  fresh
  ip -n client link add docker0 type dummy
  ip -n client addr add 172.17.0.1/16 dev docker0
  ip -n client link set docker0 up
  vs add 192.168.0.0/16 >/dev/null
  vs add 172.16.0.0/12 >/dev/null
  vs add 100.64.0.0/10 >/dev/null
  start_run s31 run
  check "routes applied" wait_for 20 applied
  DIAG=$(diag_out)
  show_diag
  check "the rule over the LAN of eth0" has_diag warn OVERLAP_LAN
  check "the rule over docker0" has_diag warn OVERLAP_ADAPTER
  printf '%s\n' "$DIAG" | grep -q "docker0" && ok "docker0 is named" || bad "docker0 not named"
  check "the rule over CGNAT" has_diag info OVERLAP_WELLKNOWN
  routes_ok
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  ip -n client link del docker0
  check "the routing table equals the snapshot" base_state
  cfg_back
  show_log
}

# S32: a corp rule that covers the address of the home VPN's server
s_diag_endpoint() {
  CUR=S32
  say "S32: a corp network over the server of the home VPN is reported"
  cfg_save
  fresh
  local added=0
  if [ "$VARIANT" != a ]; then
    ip -n client route add 198.18.2.2/32 via 192.168.1.1 dev eth0 && added=1
  fi
  vs add 198.18.0.0/16 >/dev/null
  local before
  before=$(snap)
  DIAG=$(diag_out)
  show_diag
  check "ENDPOINT_COVERED is a warning" has_diag warn ENDPOINT_COVERED
  printf '%s\n' "$DIAG" | grep -q "198.18.2.2" && ok "the server is named" || bad "the server address is not named"
  check "the routing table is unchanged by status" test "$(snap)" = "$before"
  [ "$added" = 1 ] && ip -n client route del 198.18.2.2/32
  cfg_back
  check "the routing table equals the snapshot" base_state
}

# S33: fake-ip-range of a mihomo config narrows the answers that are accepted. Control: without the file the
# answer 28.5.5.5 gets a /32 route.
s_diag_fakeip() {
  CUR=S33
  say "S33: fake-ip-range 28.0.0.0/8 from a mihomo config (client running): the answer 28.5.5.5 is dropped"
  cfg_save
  fresh
  vs add --direct fake28.example >/dev/null
  start_run s33a run
  check "routes applied" wait_for 20 applied
  check "control: without the config the answer 28.5.5.5 gets a route" bash -c "ip -n client -4 route show table all | grep -q -E '^28\.5\.5\.5 '"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state

  mkdir -p /root/.config/mihomo
  printf '%s\n' 'mixed-port: 7890' 'tun:' '  enable: true' '  stack: mixed' '  strict-route: true' \
    'dns:' '  enable: true' '  enhanced-mode: fake-ip' '  fake-ip-range: 28.0.0.1/8' > /root/.config/mihomo/config.yaml
  # the config of a client that is not running (no adapter of it) says nothing about the DNS: the answer is routed
  start_run s33n run
  check "routes applied" wait_for 20 applied
  check "no mihomo adapter: the config is not used (28.5.5.5 gets a route)" bash -c "ip -n client -4 route show table all | grep -q -E '^28\.5\.5\.5 '"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state

  # the adapter of the client is up: its fake-ip range counts (the adapter and its route are taken
  # away before the table is compared with the snapshot: they are not ours)
  mihomo_up() { ip -n client link add mihomo0 type dummy && ip -n client addr add 172.19.0.1/30 dev mihomo0 && ip -n client link set mihomo0 up; }
  mihomo_up
  start_run s33b run
  check "routes applied" wait_for 20 applied
  if grep -q "direct DNS (provider)" "$RLOG"; then
    # the provider's DNS is asked explicitly: a range of a config is only a guess about the DNS of the
    # client and does not apply to what another server answers
    check "provider DNS asked explicitly: the answer 28.5.5.5 keeps its route" bash -c "ip -n client -4 route show table all | grep -q -E '^28\.5\.5\.5 '"
  else
    check "the answer 28.5.5.5 got no route" bash -c "! ip -n client -4 route show table all | grep -q -E '^28\.5\.5\.5'"
    grep -q "fake28.example=28.5.5.5" "$RLOG" && ok "the report names the dropped answer" || bad "the dropped answer is not in the output"
  fi
  routes_ok
  DIAG=$(diag_out)
  show_diag
  check "FAKE_IP is reported" has_diag warn FAKE_IP
  printf '%s\n' "$DIAG" | grep -q "28.0.0.0/8" && ok "the range of the config is named" || bad "the range is not named"
  check "STRICT_ROUTE is reported" has_diag warn STRICT_ROUTE
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  ip -n client link del mihomo0
  check "the routing table equals the snapshot" base_state

  # a range that is not allowed (too wide) is not taken: the answer is routed as before
  sed -i 's#fake-ip-range: .*#fake-ip-range: 0.0.0.0/1#' /root/.config/mihomo/config.yaml
  mihomo_up
  start_run s33c run
  check "routes applied" wait_for 20 applied
  check "a too wide range is not taken (28.5.5.5 gets a route again)" bash -c "ip -n client -4 route show table all | grep -q -E '^28\.5\.5\.5 '"
  kill -TERM "$RPID"
  reap
  rm -rf /root/.config/mihomo
  ip -n client link del mihomo0
  cfg_back
  check "the routing table equals the snapshot" base_state
  show_log
}

# S34: the corp VPN has no next hop (its routes are on-link); the plan works, the note is shown
s_diag_onlink() {
  CUR=S34
  say "S34: the corp gateway without a next hop: routes are on-link, the note is shown"
  fresh
  ip -n client route add 10.30.0.0/16 dev wgcorp
  start_run s34 run
  check "routes applied" wait_for 20 applied
  routes_ok
  check "the corp route has no 'via'" bash -c "[ -z \"\$(ip -n client -4 route get 203.0.113.11 | grep -o 'via [^ ]*')\" ]"
  DIAG=$(diag_out)
  show_diag
  check "CORP_ONLINK is a note" has_diag info CORP_ONLINK
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  ip -n client route del 10.30.0.0/16 dev wgcorp
  check "the routing table equals the snapshot" base_state
  show_log
}

# S35: the DNS servers we set on a link that had none stay while the plan is applied again (the old code saw
# a link with servers in the next cycle, planned nothing, and took its own entry away)
s_dns_keep() {
  CUR=S35
  say "S35: the 'dns' entry we made stays after a second apply"
  cfg_save
  fresh
  fake_resolved_on
  : > "$WORK/resolved/wgcorp.dns"
  start_run s35 run
  check "routes applied" wait_for 20 applied
  check "the corp link got the corp DNS" test "$(rdns wgcorp)" = 10.200.0.1
  check "the journal has the dns entry" grep -q '"dns wgcorp ' /var/lib/vpnsplit/state.json
  vs add 203.0.113.19 >/dev/null
  check "the new rule was applied by the loop" wait_for 20 dev_is 203.0.113.19 wgcorp
  sleep 3
  check "the corp link still has the corp DNS" test "$(rdns wgcorp)" = 10.200.0.1
  check "the journal still has the dns entry" grep -q '"dns wgcorp ' /var/lib/vpnsplit/state.json
  check "the servers were set once and never cleared" bash -c "[ \"\$(grep -c '^dns wgcorp' $WORK/resolved/calls.log)\" = 1 ]"
  kill -TERM "$RPID"
  reap
  check "exit code 0 (got $RCODE)" test "$RCODE" = 0
  check "the corp link has no DNS servers again, as before" test -z "$(rdns wgcorp)"
  check "the routing table equals the snapshot" base_state
  cfg_back
  fake_resolved_off
  show_log
}


# S36-S39: stage 5 (menu switch, recover, install-recover, window size)
s_tui_switch() {
  CUR=S36
  say "S36: the switch 'Разделение' in the menu: OFF removes at once (session, lock, snapshot stay), ON applies again, q ends clean"
  fresh
  snap > "$WORK/base.snap"
  local offchk='{ ip -n client -4 route show table all | grep -v -E "^(local|broadcast|multicast)"; ip -n client -4 rule show; } | sort | cmp -s - /tmp/stand/base.snap'
  local lockchk='ip netns exec client env HOME=/root /usr/local/bin/vpnsplit reset >/dev/null 2>&1; [ $? -ne 0 ]'
  out=$(TUI_CHECK_OFF="$offchk" TUI_CHECK_OFF2="$lockchk" TUI_CHECK_ON="$READY" python3 $STAND/tuirun.py offon "$READY" "$BIN" 2>&1)
  echo "$out" | grep -E '^(OFF|ON|EXIT)' | sed 's/^/        | /'
  echo "$out" | grep -q 'OFF_CHECK=0' && ok "OFF: the table equals the snapshot while the menu is still open" || bad "OFF: the table differs from the snapshot"
  echo "$out" | grep -q 'OFF_CHECK2=0' && ok "OFF: the lock is still held (a second copy is refused)" || bad "OFF: a second copy was not refused"
  echo "$out" | grep -q 'OFF_STATUS=1' && ok "OFF: the status line says so" || bad "OFF: no OFF in the status line"
  echo "$out" | grep -q 'ON_CHECK=0' && ok "ON: the rules are applied again" || bad "ON: routes were not applied again"
  echo "$out" | grep -q 'EXIT=0' && ok "q after ON ends with exit code 0" || bad "exit: $(echo "$out" | grep EXIT)"
  check "the routing table equals the snapshot" base_state
  check "the snapshot file is gone with the session" test ! -e /var/lib/vpnsplit/snapshot.json

  CUR=S36b
  say "S36b: the exit after the switch was turned on again: the table equals the snapshot (second round)"
  fresh
  snap > "$WORK/base.snap"
  out=$(TUI_CHECK_OFF="$offchk" TUI_CHECK_OFF2="$lockchk" TUI_CHECK_ON="$READY" python3 $STAND/tuirun.py offon "$READY" "$BIN" 2>&1)
  echo "$out" | grep -q 'EXIT=0' && ok "exit code 0" || bad "exit: $(echo "$out" | grep EXIT)"
  check "the routing table equals the snapshot" base_state

  CUR=S36c
  say "S36c: over the routes of apply the switch refuses (nothing is taken without t)"
  fresh
  check "apply succeeds" vs apply >"$WORK/s36c.apply.log" 2>&1
  local before
  before=$(snap)
  out=$(python3 $STAND/tuirun.py key1q 'screen:Забрать' "$BIN" 2>&1)
  echo "$out" | grep -E '^(REFUSED|EXIT)' | sed 's/^/        | /'
  echo "$out" | grep -q 'REFUSED=1' && ok "the menu says to press [t] first" || bad "no refusal on the screen"
  echo "$out" | grep -q 'EXIT=0' && ok "exit code 0" || bad "exit: $(echo "$out" | grep EXIT)"
  check "the table did not change" test "$(snap)" = "$before"
  check "routes still work" applied
  check "the journal is still persistent" grep -q '"persistent"' /var/lib/vpnsplit/state.json
  vs reset >/dev/null 2>&1
  check "reset cleans up" base_state
}

s_recover() {
  CUR=S37
  say "S37: 'vpnsplit recover' after kill -9 removes what the dead session left, applies nothing"
  fresh
  start_run s37a run
  check "routes applied" wait_for 20 applied
  kill -9 "$RPID"
  reap
  check "the table differs after kill -9" test "$(snap)" != "$BASE"
  out=$(vs recover 2>&1)
  rc=$?
  echo "$out" | sed 's/^/        | /'
  check "recover exits 0 (got $rc)" test "$rc" = 0
  check "the routing table equals the snapshot" base_state
  echo "$out" | grep -q "recovered after an earlier run" && ok "the report names what was removed" || bad "no report"
  echo "$out" | grep -q "Restored to the state before the start" && ok "the report compares with the state before the dead run" || bad "no verdict about the state before the dead run"
  check "the snapshot file is gone" test ! -e /var/lib/vpnsplit/snapshot.json
  check "the journal holds no routes" bash -c '! grep -q "\"dest\"" /var/lib/vpnsplit/state.json'

  say "S37b: recover with nothing to do, and next to a running copy"
  out=$(vs recover 2>&1)
  rc=$?
  check "nothing to recover: exit 0 (got $rc)" test "$rc" = 0
  echo "$out" | grep -q "nothing to recover" && ok "says so" || bad "no 'nothing to recover'"
  start_run s37b run
  check "routes applied" wait_for 20 applied
  out=$(vs recover 2>&1)
  rc=$?
  check "recover refuses while a session runs (exit $rc)" test "$rc" != 0
  check "routes still work" applied
  kill -TERM "$RPID"
  reap
  check "the first copy ends cleanly (exit $RCODE)" test "$RCODE" = 0
  check "the routing table equals the snapshot" base_state

  CUR=S37c
  say "S37c: recover leaves the routes of apply (persistent) alone"
  fresh
  check "apply succeeds" vs apply >"$WORK/s37c.apply.log" 2>&1
  out=$(vs recover 2>&1)
  rc=$?
  echo "$out" | sed 's/^/        | /'
  check "recover exits 0 (got $rc)" test "$rc" = 0
  check "routes of apply stay" applied
  echo "$out" | grep -q "left in place" && ok "says that they stay" || bad "no 'left in place'"
  vs reset >/dev/null 2>&1
  check "reset cleans up" base_state
}

# systemctl is not in the container: a stub that logs its calls stands for it
fake_systemd_on() {
  mkdir -p /etc/systemd/system
  chmod 755 /etc /etc/systemd /etc/systemd/system
  printf '#!/bin/sh\necho "$@" >> /tmp/stand/systemctl.calls\nexit 0\n' > /usr/sbin/systemctl
  chmod 755 /usr/sbin/systemctl
  rm -f /tmp/stand/systemctl.calls
}
fake_systemd_off() {
  rm -f /usr/sbin/systemctl /etc/systemd/system/vpnsplit-recover.service
  rmdir /etc/systemd/system /etc/systemd 2>/dev/null
}

s_install_recover() {
  CUR=S38
  say "S38: install-recover copies the program into /usr/local/libexec/vpnsplit and the unit starts the copy; --remove deletes only its own"
  fake_systemd_on
  local unit=/etc/systemd/system/vpnsplit-recover.service
  local cdir=/usr/local/libexec/vpnsplit
  local copy=$cdir/vpnsplit
  rm -rf "$cdir"
  out=$(vs install-recover 2>&1)
  rc=$?
  echo "$out" | sed 's/^/        | /'
  check "the install succeeds (exit $rc)" test "$rc" = 0
  check "the copy is there, identical to the program, root 755" bash -c "cmp -s $BIN $copy && [ \"\$(stat -c '%a %U' $copy)\" = '755 root' ]"
  check "the directory is root's and 755, with the marker" bash -c "[ \"\$(stat -c '%a %U' $cdir)\" = '755 root' ] && grep -q vpnsplit-managed $cdir/vpnsplit.managed"
  check "the unit is written" test -f "$unit"
  check "the unit starts the copy at boot, once" bash -c "grep -q 'ExecStart=\"$copy\" recover' $unit && grep -q 'Type=oneshot' $unit && grep -q 'WantedBy=multi-user.target' $unit"
  check "the unit carries the mark" bash -c "head -1 $unit | grep -q 'vpnsplit-managed'"
  check "the unit is not writable by others" bash -c "[ \"\$(stat -c %a $unit)\" = 644 ]"
  check "systemctl enable was called, nothing was started" bash -c "grep -q 'enable vpnsplit-recover.service' /tmp/stand/systemctl.calls && ! grep -q 'start' /tmp/stand/systemctl.calls"
  vs install-recover >/dev/null 2>&1
  check "installing again replaces the copy and the unit" bash -c "test -f $unit && cmp -s $BIN $copy && test ! -e $copy.tmp"

  say "S38b: a program anywhere is copied (the copy is what runs); the places of the copy must be root's"
  mkdir -p /tmp/untrusted && cp "$BIN" /tmp/untrusted/vpnsplit && chmod 755 /tmp/untrusted/vpnsplit
  rm -f "$unit"; rm -rf "$cdir"
  out=$(ip netns exec client env HOME=/root /tmp/untrusted/vpnsplit install-recover 2>&1)
  rc=$?
  echo "$out" | head -3 | sed 's/^/        | /'
  check "a program in a user-writable directory is fine now, the copy is used (exit $rc)" test "$rc" = 0
  check "the unit points at the copy, not at /tmp" bash -c "grep -q 'ExecStart=\"$copy\" recover' $unit && ! grep -q /tmp/untrusted $unit"
  rm -rf /tmp/untrusted
  rm -f "$unit"
  chmod 777 /usr/local/libexec
  out=$(vs install-recover 2>&1)
  rc=$?
  chmod 755 /usr/local/libexec
  check "a world-writable /usr/local/libexec is refused (exit $rc)" test "$rc" != 0
  check "the unit is not written" test ! -e "$unit"
  rm -rf "$cdir"; mkdir -p /tmp/elsewhere
  ln -s /tmp/elsewhere "$cdir"
  out=$(vs install-recover 2>&1)
  rc=$?
  check "a link in place of the directory is refused (exit $rc)" test "$rc" != 0
  check "nothing was written through it" bash -c "[ -z \"\$(ls -A /tmp/elsewhere)\" ] && [ ! -e $unit ]"
  rm -f "$cdir"; rm -rf /tmp/elsewhere
  mkdir -p "$cdir" && printf 'theirs' > "$copy" && chmod 755 "$copy"
  out=$(vs install-recover 2>&1)
  rc=$?
  check "a file of that name without our marker is not replaced (exit $rc)" bash -c "[ $rc != 0 ] && [ \"\$(cat $copy)\" = theirs ] && [ ! -e $unit ]"
  out=$(vs install-recover --remove 2>&1)
  check "and --remove leaves it too" test "$(cat $copy)" = theirs
  rm -rf "$cdir"

  say "S38c: --remove deletes its own unit and copy and leaves a foreign unit"
  check "install again" vs install-recover >/dev/null 2>&1
  out=$(vs install-recover --remove 2>&1)
  rc=$?
  check "remove exits 0 (got $rc)" test "$rc" = 0
  check "the unit is gone" test ! -e "$unit"
  check "the copy, the marker and the directory are gone" test ! -e "$cdir"
  printf '[Service]\nExecStart=/bin/true\n' > "$unit"
  out=$(vs install-recover --remove 2>&1)
  rc=$?
  check "somebody else's unit is not removed (exit $rc)" test "$rc" != 0
  check "it is still there, unchanged" grep -q 'ExecStart=/bin/true' "$unit"
  out=$(vs install-recover 2>&1)
  rc=$?
  check "and not overwritten either (exit $rc)" test "$rc" != 0
  check "still unchanged" grep -q 'ExecStart=/bin/true' "$unit"
  rm -rf "$cdir"
  fake_systemd_off
  out=$(vs install-recover 2>&1)
  rc=$?
  check "without systemd nothing is written (exit $rc)" bash -c "[ $rc != 0 ] && [ ! -e $unit ] && [ ! -e $cdir ]"
  echo "$out" | grep -q "systemd" && ok "the message names systemd" || bad "no mention of systemd"
}

s_resize() {
  CUR=S39
  say "S39: the window is enlarged for the menu where the terminal allows it (xterm: CSI 8;rows;cols t) and put back"
  fresh
  out=$(TUI_ROWS=24 TUI_COLS=70 TUI_ENV='XTERM_VERSION=XTerm(380)' TUI_EMULATE_CSI=1 python3 $STAND/tuirun.py q "$READY" "$BIN" 2>&1)
  echo "$out" | grep -E '^(RESIZE|EXIT)' | sed 's/^/        | /'
  first=$(echo "$out" | grep '^RESIZE=' | head -1)
  last=$(echo "$out" | grep '^RESIZE=' | tail -1)
  case "$first" in RESIZE=2[5-9]x80 | RESIZE=[3-9][0-9]x80) ok "the window was asked to grow to 80 columns and more rows ($first)" ;; *) bad "no growth request: '$first'" ;; esac
  [ "$last" = "RESIZE=24x70" ] && ok "the original size 24x70 was put back at the end" || bad "last request: '$last'"
  echo "$out" | grep -q 'EXIT=0' && ok "exit code 0" || bad "exit: $(echo "$out" | grep EXIT)"
  check "the routing table equals the snapshot" base_state

  say "S39b: tmux and an unknown terminal are not resized, the user is asked; --no-resize and VPNSPLIT_NO_RESIZE leave the window alone"
  for e in 'TMUX=/tmp/tmux-0/default,1,0 XTERM_VERSION=XTerm(380)' 'TERM_PROGRAM=somethingelse'; do
    out=$(TUI_ROWS=24 TUI_COLS=70 TUI_ENV="$e" TUI_EMULATE_CSI=1 python3 $STAND/tuirun.py q "$READY" "$BIN" 2>&1)
    echo "$out" | grep -q '^RESIZE=' && bad "[$e] a resize request was sent" || ok "[$e] no resize request"
    echo "$out" | grep -q 'HINT=1' && ok "[$e] the user is asked to enlarge the window" || bad "[$e] no request on the screen"
  done
  out=$(TUI_ROWS=24 TUI_COLS=70 TUI_ENV='XTERM_VERSION=XTerm(380)' TUI_ARGS=--no-resize TUI_EMULATE_CSI=1 python3 $STAND/tuirun.py q "$READY" "$BIN" 2>&1)
  echo "$out" | grep -q '^RESIZE=' && bad "--no-resize: a request was sent" || ok "--no-resize: the window is left alone"
  echo "$out" | grep -q 'HINT=1' && bad "--no-resize: the user was still asked" || ok "--no-resize: no request either"
  out=$(TUI_ROWS=24 TUI_COLS=70 TUI_ENV='XTERM_VERSION=XTerm(380) VPNSPLIT_NO_RESIZE=1' TUI_EMULATE_CSI=1 python3 $STAND/tuirun.py q "$READY" "$BIN" 2>&1)
  echo "$out" | grep -q '^RESIZE=' && bad "VPNSPLIT_NO_RESIZE=1: a request was sent" || ok "VPNSPLIT_NO_RESIZE=1: the window is left alone"
  check "the routing table equals the snapshot" base_state

  say "S39c: a window that is big enough is not touched"
  out=$(TUI_ROWS=50 TUI_COLS=130 TUI_ENV='XTERM_VERSION=XTerm(380)' TUI_EMULATE_CSI=1 python3 $STAND/tuirun.py q "$READY" "$BIN" 2>&1)
  echo "$out" | grep -q '^RESIZE=' && bad "a request was sent for a big window" || ok "no request for a big window"
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
want S19 && s_dns_paths
want S20 && s_dns_rest
want S21 && s_ipv6
want S22 && s_rest_direct
want S23 && s_rest_keep
want S24 && s_dns_overlap
want S25 && s_dns_foreign
want S26 && s_ipv6_v4only
want S27 && s_dns_readfail
want S28 && s_diag_quiet
want S29 && s_diag_wg
want S30 && s_diag_corp_full
want S31 && s_diag_overlap
want S32 && s_diag_endpoint
want S33 && s_diag_fakeip
want S34 && s_diag_onlink
want S35 && s_dns_keep
want S36 && s_tui_switch
want S37 && s_recover
want S38 && s_install_recover
want S39 && s_resize

say "result: $PASS ok, $FAIL failed"
for f in "${FAILED[@]+"${FAILED[@]}"}"; do echo "  FAIL $f"; done
[ "$FAIL" = 0 ]
