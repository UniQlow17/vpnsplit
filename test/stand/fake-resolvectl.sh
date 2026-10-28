#!/bin/sh
# A stand-in for systemd-resolved's resolvectl, for the stand (see stand.sh: fake_resolved_on).
# The DNS servers and domains of each link are kept in files under /tmp/stand/resolved.
d=/tmp/stand/resolved
# every call that changes something is logged (the scenarios count flushes and writes)
case "$1" in
  flush-caches) echo "flush" >> "$d/calls.log" ;;
  dns|domain) [ $# -gt 2 ] && echo "$*" >> "$d/calls.log" ;;
esac
case "$1" in
  status) echo "Global"; exit 0 ;;
  flush-caches) exit 0 ;;
  dns|domain)
    kind=$1
    link=$2
    [ -n "$link" ] || exit 1
    if [ $# -le 2 ]; then
      # reading fails (S27): resolved does not answer, which is not the same as "the link has none"
      [ -e "$d/fail" ] && { echo "Failed to get $kind: Connection timed out" >&2; exit 1; }
      i=$(ip -o link show "$link" 2>/dev/null | cut -d: -f1)
      echo "Link ${i:-0} ($link): $(cat "$d/$link.$kind" 2>/dev/null)"
      exit 0
    fi
    shift 2
    echo "$*" | tr -s ' ' > "$d/$link.$kind"
    # an empty argument clears the list
    [ -z "$(tr -d ' \n' < "$d/$link.$kind")" ] && : > "$d/$link.$kind"
    exit 0 ;;
  revert)
    : > "$d/$2.dns"
    : > "$d/$2.domain"
    exit 0 ;;
esac
exit 1
