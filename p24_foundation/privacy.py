"""Presence-only secrets, typed keyed equality, encrypted immutable originals.

No raw message is serialized by an inspection API. Secret values are neither
pseudonymized individually nor exposed as reusable equality hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import FoundationError

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, default=str).encode("utf-8")

@dataclass(frozen=True)
class Keys:
    equality: bytes
    encryption: bytes
    version: str

    def __post_init__(self):
        if len(self.equality) != 32 or len(self.encryption) != 32 or not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", self.version):
            raise FoundationError("invalid_private_keys")

    @property
    def fingerprint(self):
        return hmac.new(self.equality, b"p24-foundation-key-binding", hashlib.sha256).hexdigest()

    def token(self, namespace, domain, value):
        digest = hmac.new(self.equality, canonical([namespace, domain, value]), hashlib.sha256).hexdigest()
        return f"{domain}:{self.version}:{digest}"

    def content_digest(self, namespace, value):
        return hmac.new(self.equality, canonical([namespace, "whole_event_content", value]), hashlib.sha256).hexdigest()

    @classmethod
    def read(cls, path):
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
            return cls(bytes.fromhex(value["equality"]), bytes.fromhex(value["encryption"]), value["version"])
        except (OSError, ValueError, KeyError, TypeError):
            raise FoundationError("invalid_private_keys") from None

def generate_keys(path):
    path = Path(path)
    value = dict(equality=os.urandom(32).hex(), encryption=os.urandom(32).hex(), version="local_v1")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise FoundationError("private_keys_not_created") from None

class Vault:
    """Ciphertext is created before the database transaction references it.

    A failed DB transaction can leave an unreferenced encrypted object; no
    automatic garbage collection/deletion is implemented in this batch.
    """
    def __init__(self, directory, keys, namespace):
        self.directory = Path(directory).resolve()
        self.keys = keys
        self.namespace = namespace

    def _path(self, digest, object_scope=None):
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise FoundationError("invalid_archive_reference")
        scope = self.keys.token(self.namespace, "archive_scope", ["namespace", object_scope]).split(":")[-1][:24]
        name = f"{scope}_{self.keys.version}_{digest}.aesgcm"
        path = self.directory / name
        if path.is_symlink():
            raise FoundationError("invalid_archive_reference")
        return path

    def _aad(self, digest, object_scope=None):
        return canonical(["p24-vault.1", self.namespace, self.keys.version, digest, object_scope])

    def read(self, digest, object_scope=None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            blob = self._path(digest, object_scope).read_bytes()
            if blob[:4] != b"P24A":
                raise ValueError
            plain = AESGCM(self.keys.encryption).decrypt(blob[4:16], blob[16:], self._aad(digest, object_scope))
            if hashlib.sha256(plain).hexdigest() != digest:
                raise ValueError
            return plain
        except Exception:
            raise FoundationError("archive_authentication_failed") from None

    def put(self, plaintext, *, object_scope=None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        digest = hashlib.sha256(plaintext).hexdigest()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self._path(digest, object_scope)
        if not path.exists():
            nonce = os.urandom(12)
            blob = b"P24A" + nonce + AESGCM(self.keys.encryption).encrypt(nonce, plaintext, self._aad(digest, object_scope))
            temporary = None
            try:
                fd, temporary = tempfile.mkstemp(prefix=".p24_", dir=self.directory)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(blob)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, path)  # Never replace a previously referenced object.
                except FileExistsError:
                    pass
            except OSError:
                raise FoundationError("archive_write_failed") from None
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
        if self.read(digest, object_scope) != plaintext:
            raise FoundationError("archive_content_conflict")
        return dict(digest=digest, storage_key=path.name,
                    cipher_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), byte_count=len(plaintext))

