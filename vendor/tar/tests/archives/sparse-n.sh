#!/bin/sh
set -eu
T="$(mktemp)"
trap 'rm "$T"' EXIT
for i in $(seq 0 "$1"); do
  truncate -s "${i}M" a.big
  echo "${i}MB through" >> a.big
 done
tar -cf sparse-"$1".tar --sparse a.big
