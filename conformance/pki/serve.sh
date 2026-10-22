#!/bin/sh
# Entrypoint of the bench's PKI container (ADR-0011). The PKI is mounted read-only at
# /pki; the TSA increments a serial file, so the responders work on a writable copy.
set -eu

SOURCE="${NACRE_PKI_SOURCE:-/pki}"
STATE="${NACRE_PKI_STATE:-/run/nacre-pki}"
ROOT=/srv/nacre-pki

rm -rf "$STATE"
mkdir -p "$STATE" "$ROOT/crl"
cp -R "$SOURCE"/. "$STATE"/
cp "$STATE/root.crl" "$STATE/intermediate.crl" "$ROOT/crl/"
echo ".crl:application/pkix-crl" > "$STATE/httpd.conf"

export NACRE_PKI_STATE="$STATE"
exec busybox-extras httpd -f -v -p 127.0.0.1:18081 -h "$ROOT" -c "$STATE/httpd.conf"
