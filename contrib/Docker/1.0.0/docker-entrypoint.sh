#!/bin/sh
set -e

if [ $(echo "$1" | cut -c1) = "-" ]; then
  echo "$0: assuming arguments for bitcoindiamond"

  set -- bitcoindiamondd "$@"
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "bitcoindiamondd" ]; then
  mkdir -p "$BITCOINDIAMOND_DATA"
  chmod 700 "$BITCOINDIAMOND_DATA"
  chown -R BitcoinDiamond "$BITCOINDIAMOND_DATA"

  echo "$0: setting data directory to $BITCOINDIAMOND_DATA"
  if [ $UPNP == -1 ]
  then
    set -- "$@" -datadir="$BITCOINDIAMOND_DATA"
  else
    set -- "$@" -datadir="$BITCOINDIAMOND_DATA" -upnp="$UPNP"
  fi

fi

if [ "$1" = "bitcoindiamondd" ] || [ "$1" = "bitcoindiamond-cli" ] || [ "$1" = "bitcoindiamond-tx" ]; then
  echo
  exec gosu BitcoinDiamond "$@"
fi

echo
exec "$@"
