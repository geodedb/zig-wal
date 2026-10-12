#!/usr/bin/env bash
# Verify one detached OpenPGP signature against exact primary-key fingerprints.
# GnuPG's VALIDSIG status reports the certified primary for signing subkeys.
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: verify-release-signature.sh SIGNATURE PAYLOAD PRIMARY_FINGERPRINT..." >&2
    exit 2
fi
signature=$1
payload=$2
shift 2
for fingerprint in "$@"; do
    [[ $fingerprint =~ ^([A-F0-9]{40}|[A-F0-9]{64})$ ]] || {
        echo "ERROR: expected a full primary-key fingerprint" >&2
        exit 2
    }
done

# Keep machine status separate from human diagnostics. Never retrieve keys
# implicitly: the caller must supply the public keys matching its trust anchors.
status=$(gpg --batch --no-auto-key-retrieve --status-fd=1 \
    --verify "$signature" "$payload") || {
    echo "ERROR: release signature verification failed" >&2
    exit 1
}
primary=$(awk '
    $1 != "[GNUPG:]" { next }
    $2 == "GOODSIG" { good++ }
    $2 == "VALIDSIG" { valid++; primary = (NF >= 12 ? $12 : $3) }
    $2 ~ /^(BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|NO_PUBKEY|NODATA|FAILURE|ERROR)$/ { bad = 1 }
    END {
        if (good != 1 || valid != 1 || bad) exit 1
        print primary
    }
' <<< "$status") || {
    echo "ERROR: expected exactly one valid, current release signature" >&2
    exit 1
}
for fingerprint in "$@"; do
    if [[ $primary == "$fingerprint" ]]; then
        echo "Verified release signature from primary key $primary"
        exit 0
    fi
done
echo "ERROR: release signature does not match a pinned primary key" >&2
exit 1
