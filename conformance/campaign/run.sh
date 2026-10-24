#!/bin/sh
# Runs the campaign of crates/nacre-validate/tests/campaign.rs against a started bench
# (conformance/README.md), then keeps its two tables and DSS's XML report of every case in
# conformance/campaign/reports/, with the status and body of each HTTP error DSS answered.
# Exits non-zero when the campaign fails, keeping nothing; at once when DSS does not answer.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
target=${CARGO_TARGET_DIR:-target}
case $target in
/*) ;;
*) target=$root/$target ;;
esac
reports=$target/conformance

rm -f "$reports"/campaign-*
cargo test -p nacre-validate --all-features --test campaign -- --ignored

kept=$root/conformance/campaign/reports
rm -rf "$kept"
mkdir -p "$kept"
cp "$reports"/campaign-dss.md "$reports"/campaign-strict.md "$kept"/
cp "$reports"/campaign-*.xml "$kept"/
for error in "$reports"/campaign-*.error.txt; do
	if [ -e "$error" ]; then cp "$error" "$kept"/; fi
done
echo "kept $(ls "$kept" | wc -l) files in conformance/campaign/reports/"
