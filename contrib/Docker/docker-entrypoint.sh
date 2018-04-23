#!/bin/sh
set -e

if [ $(echo "$1" | cut -c1) = "-" ]; then
  echo "$0: assuming arguments for bitcoindiamond"

  set -- bitcoindiamond "$@"
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "bitcoindiamond" ]; then
  mkdir -p "$BITCOINDIAMOND_DATA"
  chmod 700 "$BITCOINDIAMOND_DATA"
  chown -R bitcoin "$BITCOINDIAMOND_DATA"

  echo "$0: setting data directory to $BITCOINDIAMOND_DATA"

  set -- "$@" -datadir="$BITCOINDIAMOND_DATA" -upnp="$UPNP"
fi

if [ "$1" = "bitcoindiamondd" ] || [ "$1" = "bitcoindiamond-cli" ] || [ "$1" = "bitcoindiamond-tx" ]; then
  echo
  exec gosu bitcoin "$@"
fi

echo
exec "$@"
