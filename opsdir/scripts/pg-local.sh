#!/usr/bin/env bash
# Private, throwaway Postgres cluster for the demo. Lives in ./.pgdata, listens only on a
# unix socket in ./.pgsock (port 54329). Never touches a system Postgres.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}
DATA=$PWD/.pgdata; SOCK=$PWD/.pgsock; PORT=54329
case "${1:-}" in
  start)
    mkdir -p "$SOCK"
    [ -d "$DATA" ] || "$BIN/initdb" -D "$DATA" -U opsdir -A trust >/dev/null
    "$BIN/pg_ctl" -D "$DATA" -l "$DATA/server.log" \
      -o "-k $SOCK -p $PORT -c listen_addresses=''" start >/dev/null
    "$BIN/createdb" -h "$SOCK" -p $PORT -U opsdir opsdir 2>/dev/null || true
    echo "export OPSDIR_DSN='host=$SOCK port=$PORT user=opsdir dbname=opsdir'" ;;
  stop)  "$BIN/pg_ctl" -D "$DATA" stop >/dev/null && echo stopped ;;
  destroy) "$BIN/pg_ctl" -D "$DATA" stop >/dev/null 2>&1 || true; rm -rf "$DATA" "$SOCK"; echo destroyed ;;
  *) echo "usage: $0 start|stop|destroy"; exit 1 ;;
esac
