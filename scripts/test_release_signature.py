#!/usr/bin/env python3
"""Real GnuPG signatures qualify primary-key and certified-subkey verification."""

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

VERIFY = Path(__file__).with_name("verify-release-signature.sh")


class ReleaseSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="fips-release-signature-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        keyring = cls.root / "keyring"
        keyring.mkdir(mode=0o700)
        cls.env = {"PATH": os.defpath, "GNUPGHOME": str(keyring)}
        cls.addClassCleanup(
            subprocess.run,
            ["gpgconf", "--kill", "gpg-agent"],
            env=cls.env,
            capture_output=True,
            check=False,
        )
        cls.gpg(
            "--quick-generate-key",
            "Allowed <allowed@example.invalid>",
            "ed25519",
            "cert,sign",
            "0",
        )
        cls.primary = cls.fingerprints("allowed@example.invalid")[0]
        cls.gpg("--quick-add-key", cls.primary, "ed25519", "sign", "0")
        cls.subkey = cls.fingerprints("allowed@example.invalid")[1]
        cls.gpg(
            "--quick-generate-key",
            "Other <other@example.invalid>",
            "ed25519",
            "cert,sign",
            "0",
        )
        cls.other = cls.fingerprints("other@example.invalid")[0]
        cls.payload = cls.root / "release.tar.gz"
        cls.payload.write_bytes(b"immutable release fixture\n")
        for label, key in [
            ("primary", cls.primary),
            ("subkey", cls.subkey),
            ("other", cls.other),
        ]:
            cls.gpg(
                "--local-user",
                key + "!",
                "--output",
                str(cls.root / (label + ".sig")),
                "--detach-sign",
                str(cls.payload),
            )
        past = int(time.time()) - 2 * 24 * 60 * 60
        cls.gpg(
            "--faked-system-time",
            str(past),
            "--quick-generate-key",
            "Expired <expired@example.invalid>",
            "ed25519",
            "cert,sign",
            "1d",
        )
        cls.expired = cls.fingerprints("expired@example.invalid")[0]
        cls.gpg(
            "--faked-system-time",
            str(past + 60),
            "--local-user",
            cls.expired + "!",
            "--output",
            str(cls.root / "expired.sig"),
            "--detach-sign",
            str(cls.payload),
        )

    @classmethod
    def gpg(cls, *args):
        return subprocess.check_output(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                *args,
            ],
            env=cls.env,
            text=True,
            stderr=subprocess.PIPE,
        )

    @classmethod
    def fingerprints(cls, identity):
        return [
            line.split(":")[9]
            for line in cls.gpg(
                "--with-colons",
                "--with-fingerprint",
                "--with-subkey-fingerprint",
                "--list-keys",
                identity,
            ).splitlines()
            if line.startswith("fpr:")
        ]

    def verify(self, signature, *allowed, payload=None, env=None):
        return subprocess.run(
            [
                "bash",
                str(VERIFY),
                str(self.root / signature),
                str(payload or self.payload),
                *(allowed or [self.primary]),
            ],
            env=env or self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_direct_primary_signature(self):
        result = self.verify("primary.sig")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_certified_subkey_matches_pinned_primary(self):
        result = self.verify("subkey.sig")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.primary, result.stdout)

    def test_unrelated_primary_is_rejected(self):
        self.assertNotEqual(self.verify("other.sig").returncode, 0)

    def test_subkey_fingerprint_does_not_substitute_for_primary(self):
        self.assertNotEqual(self.verify("subkey.sig", self.subkey).returncode, 0)

    def test_allowlist_can_contain_multiple_exact_primary_keys(self):
        result = self.verify("other.sig", self.primary, self.other)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_fingerprint_is_rejected(self):
        self.assertEqual(self.verify("subkey.sig", self.primary[-16:]).returncode, 2)

    def test_changed_payload_is_rejected(self):
        changed = self.root / "changed.tar.gz"
        changed.write_bytes(self.payload.read_bytes() + b"changed")
        self.assertNotEqual(self.verify("subkey.sig", payload=changed).returncode, 0)

    def test_missing_public_key_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="fips-empty-keyring-") as empty:
            self.assertNotEqual(
                self.verify(
                    "subkey.sig", env=dict(self.env, GNUPGHOME=empty)
                ).returncode,
                0,
            )

    def test_malformed_signature_is_rejected(self):
        (self.root / "invalid.sig").write_bytes(b"not a signature")
        self.assertNotEqual(self.verify("invalid.sig").returncode, 0)

    def test_multiple_signatures_are_rejected_as_ambiguous(self):
        (self.root / "multiple.sig").write_bytes(
            (self.root / "primary.sig").read_bytes()
            + (self.root / "subkey.sig").read_bytes()
        )
        self.assertNotEqual(self.verify("multiple.sig").returncode, 0)

    def test_expired_key_is_rejected_even_when_primary_is_pinned(self):
        self.assertNotEqual(self.verify("expired.sig", self.expired).returncode, 0)

    def test_revoked_key_is_rejected_even_when_primary_is_pinned(self):
        with tempfile.TemporaryDirectory(prefix="fips-revoked-keyring-") as revoked:
            env = dict(self.env, GNUPGHOME=revoked)
            public = self.gpg("--armor", "--export", self.primary)
            certificate = (
                Path(self.env["GNUPGHOME"])
                / "openpgp-revocs.d"
                / (self.primary + ".rev")
            ).read_text()
            certificate = certificate.replace(
                ":-----BEGIN PGP PUBLIC KEY BLOCK-----",
                "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            )
            for data in [public, certificate]:
                subprocess.run(
                    ["gpg", "--batch", "--import"],
                    input=data,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=True,
                )
            self.assertNotEqual(self.verify("subkey.sig", env=env).returncode, 0)


if __name__ == "__main__":
    unittest.main()
