#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 James (JameZUK)
#
# Print the last N lines of the kea-unbound activity log for the Status page.
# Spans the rotated (bzip2/gzip) archives so "Load more" can page back through
# history, but only decompresses them when N exceeds the current log — the common
# live-tail case just tails the current file.
#
# Arg 1: number of lines (default 200, capped at 20000).

LOGDIR=/var/log/keaunbound
LOG="$LOGDIR/keaunbound.log"

n=$(printf '%s' "${1:-200}" | tr -cd '0-9')
[ -n "$n" ] || n=200
[ "$n" -gt 20000 ] && n=20000

cur=$(wc -l < "$LOG" 2>/dev/null | tr -d ' ')
[ -n "$cur" ] || cur=0

# fast path: enough in the current log, no need to touch archives
if [ -f "$LOG" ] && [ "$n" -le "$cur" ]; then
    tail -n "$n" "$LOG"
    exit 0
fi

# need older history: rotated archives oldest-first (highest index), then current
{
    for f in $(ls -1 "$LOGDIR"/keaunbound.log.*.bz2 "$LOGDIR"/keaunbound.log.*.gz 2>/dev/null \
               | sort -t. -k3 -rn); do
        case "$f" in
            *.bz2) bzcat "$f" 2>/dev/null ;;
            *.gz)  zcat  "$f" 2>/dev/null ;;
        esac
    done
    [ -f "$LOG" ] && cat "$LOG"
} | tail -n "$n"
