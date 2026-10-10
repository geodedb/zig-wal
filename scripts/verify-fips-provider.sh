#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 CodePros
set -euo pipefail
PREFIX="${OPENSSL_PREFIX:-/usr/local/ssl}"
OSSL="${PREFIX}/bin/openssl"
CNF="${PREFIX}/ssl/openssl.cnf"
export OPENSSL_CONF="${CNF}"
# NB: OpenSSL 3.6.x prints provider blocks as name/version/status (three
# lines), so -A3 is required to reach `status: active` under the `fips`
# header (a -A2 window stops at the version line).
"${OSSL}" list -providers | grep -A3 -i '^[[:space:]]*fips$' | grep -qi 'status: active' \
  || { echo "FAIL: fips provider not active"; exit 1; }
"${OSSL}" list -kem-algorithms | grep -qi 'ML-KEM-768' \
  || { echo "FAIL: ML-KEM-768 not listed"; exit 1; }
"${OSSL}" list -signature-algorithms | grep -qi 'ML-DSA-65' \
  || { echo "FAIL: ML-DSA-65 not listed"; exit 1; }
"${OSSL}" list -signature-algorithms | grep -qi 'SLH-DSA-SHA2-128s' \
  || { echo "FAIL: SLH-DSA not listed"; exit 1; }
echo "OK: fips provider active; PQC algorithms present at ${PREFIX}"
