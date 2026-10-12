#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 CodePros
#
# Build + install the LATEST OpenSSL 3.x with the FIPS provider, run
# fipsinstall, write an openssl.cnf activating fips+base, and verify.
# Idempotent + re-runnable; ALWAYS upgrades to the latest 3.x release.
set -euo pipefail

PREFIX="${OPENSSL_PREFIX:-/usr/local/ssl}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
WORK="${WORK:-$(mktemp -d)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '\033[0;34m==>\033[0m %s\n' "$*"; }

have_build_tools() {
  command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 \
    && command -v make >/dev/null 2>&1 \
    && command -v perl >/dev/null 2>&1 \
    && { command -v wget >/dev/null 2>&1 || command -v curl >/dev/null 2>&1; }
}

install_prereqs() {
  # Skip the package-manager step entirely when the toolchain is already
  # present (idempotent + survives hosts with a broken third-party apt
  # source). Only shell out to the package manager on a host that is
  # actually missing a build tool.
  if have_build_tools; then
    log "Build prerequisites already present; skipping package-manager install"
    return 0
  fi
  case "$(uname -s)" in
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y build-essential perl wget ca-certificates
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y gcc make perl-core wget
      fi ;;
    Darwin)
      command -v brew >/dev/null 2>&1 && brew install perl wget || true ;;
    MINGW*|MSYS*|CYGWIN*)
      log "Windows: install OpenSSL+FIPS via vcpkg (vcpkg install openssl[fips]); skipping source build"
      exit 0 ;;
  esac
}

# Resolve the latest OpenSSL 3.x tag from the GitHub releases API. If the
# API is unreachable/rate-limited, fall back to the system openssl
# version (still a 3.x) so a transient network blip cannot wedge the
# always-latest gate.
resolve_latest() {
  local tag
  tag="$(wget -qO- https://api.github.com/repos/openssl/openssl/releases/latest 2>/dev/null \
    | grep -oE '"tag_name": *"openssl-3\.[0-9.]+"' \
    | grep -oE '3\.[0-9.]+' | head -n1)"
  if [ -z "${tag}" ] && command -v openssl >/dev/null 2>&1; then
    tag="$(openssl version 2>/dev/null | grep -oE '3\.[0-9.]+' | head -n1)"
    [ -n "${tag}" ] && log "GitHub API unavailable; falling back to system openssl version ${tag}" >&2
  fi
  [ -n "${tag}" ] || { echo "could not resolve latest OpenSSL 3.x"; exit 1; }
  echo "${tag}"
}

VER="${OPENSSL_VERSION:-$(resolve_latest)}"
log "Latest OpenSSL 3.x resolved: ${VER}"

# IDEMPOTENCY GATE — ALWAYS check latest (resolve_latest ran above), but
# SKIP the rebuild when BOTH conditions hold:
#   (a) installed openssl version == latest 3.x (${VER}), AND
#   (b) the fips provider is loaded AND reports `status: active`.
# Otherwise rebuild from source. The check uses the SAME active-status
# probe as verify-fips-provider.sh (a plain `grep fips` is NOT enough —
# the provider can be listed but inactive/failed self-test).
if [ -x "${PREFIX}/bin/openssl" ]; then
  CUR="$("${PREFIX}/bin/openssl" version | grep -oE '3\.[0-9.]+' | head -n1 || true)"
  FIPS_ACTIVE=no
  if [ "${CUR}" = "${VER}" ]; then
    if OPENSSL_CONF="${PREFIX}/ssl/openssl.cnf" \
       "${PREFIX}/bin/openssl" list -providers 2>/dev/null \
       | grep -A3 -i '^[[:space:]]*fips$' | grep -qi 'status: active'; then
      FIPS_ACTIVE=yes
    fi
  fi
  if [ "${CUR}" = "${VER}" ] && [ "${FIPS_ACTIVE}" = "yes" ]; then
    log "OpenSSL ${VER} already installed with fips provider ACTIVE at ${PREFIX}; skipping rebuild (verify only)"
    exec bash "${SCRIPT_DIR}/verify-fips-provider.sh"
  fi
  log "Rebuild required (installed=${CUR:-none}, latest=${VER}, fips_active=${FIPS_ACTIVE}); upgrading"
fi

install_prereqs

log "Fetching openssl-${VER}"
cd "${WORK}"
BASE_URL="https://github.com/openssl/openssl/releases/download/openssl-${VER}"
TARBALL="openssl-${VER}.tar.gz"
wget -q "${BASE_URL}/${TARBALL}"

# ---------------------------------------------------------------------------
# INTEGRITY / AUTHENTICITY VERIFICATION — fail closed.
#
# OpenSSL release signing keys (from https://www.openssl.org/source/):
#   Current (3.x/4.x releases):
#     B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40
#   Previous (still used for some 3.x series releases):
#     BA54 73A2 B058 7B07 FB27  CF2D 2160 94DF D0CB 81EF
# ---------------------------------------------------------------------------
OPENSSL_RELEASE_KEY_CURRENT="B146647E45A7B33947AB226B2A2C87D161692D40"  # gitleaks:allow -- public OpenSSL release-signing key fingerprint, not a secret
OPENSSL_RELEASE_KEY_PREVIOUS="BA5473A2B0587B07FB27CF2D216094DFD0CB81EF"  # gitleaks:allow -- public OpenSSL release-signing key fingerprint, not a secret

SHA256_VERIFIED=no
GPG_VERIFIED=no

# --- SHA-256 verification ---------------------------------------------------
if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; then
  if wget -q "${BASE_URL}/${TARBALL}.sha256" -O "${TARBALL}.sha256"; then
    # The .sha256 file contains "HASH *filename" with the bare filename; we
    # rewrite the path to match our working-directory copy so sha256sum/shasum
    # can verify without a directory mismatch.
    EXPECTED_HASH="$(awk '{print $1}' "${TARBALL}.sha256")"
    if command -v sha256sum >/dev/null 2>&1; then
      printf '%s  %s\n' "${EXPECTED_HASH}" "${TARBALL}" | sha256sum --check --strict
    else
      printf '%s  %s\n' "${EXPECTED_HASH}" "${TARBALL}" | shasum -a 256 -c -
    fi
    SHA256_VERIFIED=yes
  else
    log "WARNING: could not download ${TARBALL}.sha256 — SHA-256 check skipped"
  fi
fi

# --- GPG signature verification ---------------------------------------------
if command -v gpg >/dev/null 2>&1; then
  if wget -q "${BASE_URL}/${TARBALL}.asc" -O "${TARBALL}.asc"; then
    # Import pinned OpenSSL release signing keys from the canonical keyserver.
    # We import both the current and previous keys so that any 3.x release in
    # the field (some older series use the previous key) can be verified.
    gpg --batch --keyserver hkps://keys.openpgp.org \
      --recv-keys "${OPENSSL_RELEASE_KEY_CURRENT}" "${OPENSSL_RELEASE_KEY_PREVIOUS}" 2>/dev/null || true
    # Match GnuPG's verified primary fingerprint, including signatures from
    # certified signing subkeys. Human diagnostics format fingerprints with
    # spaces and primarily name the subkey, so they are not a trust API.
    bash "${SCRIPT_DIR}/verify-release-signature.sh" "${TARBALL}.asc" "${TARBALL}" \
      "${OPENSSL_RELEASE_KEY_CURRENT}" "${OPENSSL_RELEASE_KEY_PREVIOUS}" || {
      log "ERROR: GPG signature verification FAILED for ${TARBALL}"
      exit 1
    }
    GPG_VERIFIED=yes
  else
    log "WARNING: could not download ${TARBALL}.asc — GPG check skipped"
    if [ "${REQUIRE_GPG:-}" = "1" ]; then
      log "ERROR: REQUIRE_GPG=1 is set — refusing to continue without GPG authenticity check"
      exit 1
    fi
  fi
else
  # gpg binary is absent: SHA-256 still guards integrity, but AUTHENTICITY
  # (binding the tarball to the OpenSSL project's signing key) has NOT been
  # verified.  An attacker who can serve a MITM SHA-256 file alongside a
  # crafted tarball would pass this check.
  printf '\033[0;31m!!!\033[0m \033[1;33mWARNING: gpg not found — AUTHENTICITY NOT VERIFIED.\033[0m\n'
  printf '\033[0;31m!!!\033[0m \033[1;33m         SHA-256 guards integrity only; the tarball has NOT been\033[0m\n'
  printf '\033[0;31m!!!\033[0m \033[1;33m         authenticated against the OpenSSL release signing key.\033[0m\n'
  printf '\033[0;31m!!!\033[0m \033[1;33m         Install gnupg (apt-get install -y gnupg) to enable full verification.\033[0m\n'
  if [ "${REQUIRE_GPG:-}" = "1" ]; then
    log "ERROR: REQUIRE_GPG=1 is set — refusing to continue without GPG authenticity check"
    exit 1
  fi
fi

# --- Fail closed: require at least one verification to have succeeded -------
if [ "${SHA256_VERIFIED}" = "no" ] && [ "${GPG_VERIFIED}" = "no" ]; then
  log "ERROR: neither SHA-256 nor GPG verification could be performed for ${TARBALL}"
  log "       Install sha256sum (or shasum) and/or gpg, or ensure the release"
  log "       assets (.sha256 / .asc) are reachable over HTTPS."
  exit 1
fi

log "Verification passed (sha256=${SHA256_VERIFIED}, gpg=${GPG_VERIFIED}) for ${TARBALL}"

tar xzf "${TARBALL}"
cd "openssl-${VER}"

log "Configuring with enable-fips (prefix=${PREFIX})"
./Configure enable-fips --prefix="${PREFIX}" --openssldir="${PREFIX}/ssl" \
  -Wl,-rpath,"${PREFIX}/lib64" -Wl,-rpath,"${PREFIX}/lib"
make -j"${JOBS}"
sudo make install_sw install_ssldirs
sudo make install_fips

# Locate the installed fips module + lib dir (lib64 on most x86_64).
LIBDIR="${PREFIX}/lib64"; [ -d "${LIBDIR}/ossl-modules" ] || LIBDIR="${PREFIX}/lib"

log "Running openssl fipsinstall"
sudo "${PREFIX}/bin/openssl" fipsinstall \
  -out "${PREFIX}/ssl/fipsmodule.cnf" \
  -module "${LIBDIR}/ossl-modules/fips.so"

log "Writing openssl.cnf activating fips + base providers"
sudo tee "${PREFIX}/ssl/openssl.cnf" >/dev/null <<EOF
config_diagnostics = 1
openssl_conf = openssl_init

.include ${PREFIX}/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
EOF

log "Verifying"
exec bash "${SCRIPT_DIR}/verify-fips-provider.sh"
