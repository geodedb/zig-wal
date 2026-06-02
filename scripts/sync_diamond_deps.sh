#!/usr/bin/env bash
# sync_diamond_deps.sh — thin wrapper around sync_diamond_deps.py.
#
# This is the script the `detect-diamond-deps` pre-commit hook points at when
# it finds a diamond. With no arguments it runs the safe LOCAL resolver for the
# current repo (no pushes); maintainers pass --cascade ... to propagate a leaf
# bump across the local DevNW sibling ecosystem. See sync_diamond_deps.py.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/sync_diamond_deps.py" "$@"
