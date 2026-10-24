"""MSL spec Section 10 – encryption support.

File layout when encrypted:
    1. File Header (128 B, cleartext) – used as AAD for AEAD
    2. KEM ciphertext (0 or variable, cleartext) – when KeyEncap != 0x00
    3. Encrypted block stream – AEAD ciphertext of Block 0 … EoC
    4. AEAD authentication tag (16 B) – follows the ciphertext
    5. Sealed extension segments / trailing data (optional) – only when
       the header ``CipherLen`` (0x78) is non-zero (spec 1.1.1, §10.2, §10.8)

The AAD is the file header with ``CipherLen`` (0x78–0x7F) zeroed, followed
by any KEM ciphertext, so the length can be patched in after sealing.

Initial implementation scope:
    - Cipher:   AES-256-GCM  (code 0x01, 12 B nonce, 16 B tag)
    - KDF:      Argon2id     (code 0x01) for passphrase-derived keys
    - KeyEncap: None (0x00)  – passphrase / raw-key mode only
"""

from __future__ import annotations

import hmac
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ENC_ALGO_AES_256_GCM: int = 0x01
KDF_TYPE_ARGON2ID: int = 0x01
KEY_ENCAP_NONE: int = 0x00

AES_GCM_NONCE_LEN: int = 12   # bytes
AES_GCM_TAG_LEN: int = 16     # bytes
AES_256_KEY_LEN: int = 32     # bytes
KDF_SALT_LEN: int = 16        # bytes
NONCE_FIELD_LEN: int = 24     # on-disk field width (12 B used, 12 B zero)
EXTENSION_HEADER_LEN: int = 64  # encryption extension header size
CIPHER_LEN_OFFSET: int = 0x78   # CipherLen field in the 128 B file header
CIPHER_LEN_SIZE: int = 8        # u64 little-endian
HKDF_BLAKE3_HASH_LEN: int = 32  # BLAKE3 digest size used by HKDF
SEGMENT_KEY_INFO: bytes = b"MSL-SEG-v1"  # HKDF info prefix (spec §10.8)
MAX_SEGMENT_INDEX: int = 0xFFFF          # SegIndex is a u16


# ---------------------------------------------------------------------------
# Encryption parameters (Table 5)
# ---------------------------------------------------------------------------
@dataclass
class EncryptionParams:
    """Parameters for the encryption extension header (Table 5)."""

    enc_algo: int = ENC_ALGO_AES_256_GCM
    kdf_type: int = KDF_TYPE_ARGON2ID
    key_encap: int = KEY_ENCAP_NONE
    kdf_time: int = 3           # Argon2 time cost
    kdf_memory: int = 65536     # Argon2 memory cost (KiB)
    kdf_lanes: int = 4          # Argon2 parallelism
    kem_ct_len: int = 0         # 0 when KeyEncap == 0x00
    cipher_len: int = 0         # CipherLen (0x78); 0 = not recorded
    nonce: bytes = field(default_factory=lambda: os.urandom(AES_GCM_NONCE_LEN))
    kdf_salt: bytes = field(default_factory=lambda: os.urandom(KDF_SALT_LEN))

    def __post_init__(self) -> None:
        if len(self.nonce) != AES_GCM_NONCE_LEN:
            raise ValueError(
                f"AES-256-GCM nonce must be {AES_GCM_NONCE_LEN} bytes, "
                f"got {len(self.nonce)}"
            )
        if len(self.kdf_salt) != KDF_SALT_LEN:
            raise ValueError(
                f"KDF salt must be {KDF_SALT_LEN} bytes, "
                f"got {len(self.kdf_salt)}"
            )


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def derive_key(passphrase: str, params: EncryptionParams) -> bytes:
    """Derive a 256-bit content-encryption key from *passphrase* via Argon2id.

    Requires the ``argon2-cffi`` package.
    """
    if params.kdf_type != KDF_TYPE_ARGON2ID:
        raise ValueError(f"Unsupported KDF type: 0x{params.kdf_type:02X}")

    from argon2.low_level import Type, hash_secret_raw  # argon2-cffi

    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=params.kdf_salt,
        time_cost=params.kdf_time,
        memory_cost=params.kdf_memory,
        parallelism=params.kdf_lanes,
        hash_len=AES_256_KEY_LEN,
        type=Type.ID,  # Argon2id
    )


# ---------------------------------------------------------------------------
# Extension header serialisation
# ---------------------------------------------------------------------------
def pack_encryption_extension(params: EncryptionParams) -> bytes:
    """Serialize the 64-byte encryption extension header (Table 5).

    Layout (offsets relative to extension start):
        EncAlgo     (1 B)
        KDFType     (1 B)
        KeyEncap    (1 B)
        Reserved    (1 B)
        KDFTime     (4 B)  little-endian uint32
        KDFMemory   (4 B)  little-endian uint32
        KDFLanes    (1 B)
        Reserved2   (1 B)
        KEMCtLen    (2 B)  little-endian uint16
        Nonce       (24 B) – 12 B AES-GCM nonce + 12 B zero padding
        KDFSalt     (16 B)
        CipherLen   (8 B)  little-endian uint64 (spec 1.1.1; 0 = not recorded)
        ─────────────────
        Total = 64 B
    """
    # Pad the 12 B nonce into the 24 B on-disk field
    nonce_padded = params.nonce + b"\x00" * (NONCE_FIELD_LEN - len(params.nonce))

    data = struct.pack(
        "<BBB x II B x H",
        params.enc_algo,     # 1 B
        params.kdf_type,     # 1 B
        params.key_encap,    # 1 B
        # x = 1 B reserved
        params.kdf_time,     # 4 B
        params.kdf_memory,   # 4 B
        params.kdf_lanes,    # 1 B
        # x = 1 B reserved
        params.kem_ct_len,   # 2 B
    )
    data += nonce_padded     # 24 B
    data += params.kdf_salt  # 16 B
    data += struct.pack("<Q", params.cipher_len)  # 8 B CipherLen

    assert len(data) == EXTENSION_HEADER_LEN, (
        f"Encryption extension is {len(data)} bytes, expected {EXTENSION_HEADER_LEN}"
    )
    return data


def unpack_encryption_extension(raw: bytes) -> EncryptionParams:
    """Deserialize a 64-byte encryption extension header back into params."""
    if len(raw) != EXTENSION_HEADER_LEN:
        raise ValueError(
            f"Expected {EXTENSION_HEADER_LEN} bytes, got {len(raw)}"
        )

    (
        enc_algo, kdf_type, key_encap,
        kdf_time, kdf_memory,
        kdf_lanes,
        kem_ct_len,
    ) = struct.unpack_from("<BBB x II B x H", raw, 0)

    nonce_padded = raw[16:40]  # 24 B nonce field
    kdf_salt = raw[40:56]      # 16 B salt
    (cipher_len,) = struct.unpack_from("<Q", raw, 56)  # 8 B CipherLen

    # Extract only the meaningful 12 B from the padded nonce field
    nonce = nonce_padded[:AES_GCM_NONCE_LEN]

    return EncryptionParams(
        enc_algo=enc_algo,
        kdf_type=kdf_type,
        key_encap=key_encap,
        kdf_time=kdf_time,
        kdf_memory=kdf_memory,
        kdf_lanes=kdf_lanes,
        kem_ct_len=kem_ct_len,
        nonce=nonce,
        kdf_salt=kdf_salt,
        cipher_len=cipher_len,
    )


# ---------------------------------------------------------------------------
# CipherLen, AAD and tag location (spec 1.1.1, Sections 10.2 and 10.7)
# ---------------------------------------------------------------------------
def zero_cipher_len(header: bytes) -> bytes:
    """Return *header* with the ``CipherLen`` bytes (0x78–0x7F) set to zero.

    This is the form both the AAD and the EoC ``FileHash`` cover. A header
    too short to hold ``CipherLen`` (the 64 B unencrypted one) is returned
    unchanged.
    """
    end = CIPHER_LEN_OFFSET + CIPHER_LEN_SIZE
    if len(header) < end:
        return bytes(header)
    return bytes(header[:CIPHER_LEN_OFFSET]) + b"\x00" * CIPHER_LEN_SIZE + bytes(header[end:])


def aad_from_header(header: bytes, kem_ciphertext: bytes = b"") -> bytes:
    """Build the primary AEAD associated data (spec Section 10.2).

    The AAD is the file header with ``CipherLen`` zeroed, followed by any
    KEM ciphertext. For ``CipherLen`` = 0 it equals the 1.1.0 AAD.
    """
    return zero_cipher_len(header) + bytes(kem_ciphertext)


def primary_ciphertext_span(
    file_size: int, header_size: int, kem_ct_len: int, cipher_len: int,
) -> tuple[int, int]:
    """Return ``(start, end)`` of the primary ciphertext; the tag follows ``end``.

    ``CipherLen`` = 0 means the tag is the final 16 bytes of the file;
    otherwise the ciphertext is exactly ``cipher_len`` bytes after the
    header and KEM ciphertext (spec Section 10.2, "Locating the tag").

    Raises:
        ValueError: if the file is too short, or ``cipher_len`` points
            past the space left for the tag.
    """
    start = header_size + kem_ct_len
    available = file_size - start - AES_GCM_TAG_LEN
    if available < 0:
        raise ValueError(
            f"truncated encrypted slice: {file_size} bytes, need at least "
            f"{start + AES_GCM_TAG_LEN}"
        )
    if cipher_len == 0:
        return start, start + available
    if cipher_len > available:
        raise ValueError(
            f"CipherLen {cipher_len} at header offset 0x{CIPHER_LEN_OFFSET:X} "
            f"exceeds the {available} byte(s) available before the tag; "
            f"the file is truncated or the header is corrupt"
        )
    return start, start + cipher_len


# ---------------------------------------------------------------------------
# HKDF-BLAKE3 (spec Sections 10.4 and 10.8)
# ---------------------------------------------------------------------------
def hkdf_blake3(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF with HMAC-BLAKE3 (block size 64, digest 32).

    Mirrors MemDiver's ``msl.crypto.hkdf_blake3`` byte for byte: an empty
    *salt* is replaced by 32 zero bytes, as RFC 5869 prescribes.

    Raises:
        ValueError: if *length* is not in 1 .. 255 * 32.
    """
    import blake3

    if not 0 < length <= 255 * HKDF_BLAKE3_HASH_LEN:
        raise ValueError(f"HKDF output length must be 1..{255 * HKDF_BLAKE3_HASH_LEN}, got {length}")
    if not salt:
        salt = b"\x00" * HKDF_BLAKE3_HASH_LEN
    prk = hmac.new(salt, ikm, blake3.blake3).digest()  # extract
    okm, block, counter = b"", b"", 1
    while len(okm) < length:  # expand
        block = hmac.new(prk, block + info + bytes([counter]), blake3.blake3).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_segment_key(cek: bytes, dump_uuid: bytes, index: int) -> bytes:
    """Derive ``SegKey_i`` for sealed extension segment *index* (spec Section 10.8).

    ``SegKey_i = HKDF-BLAKE3(IKM=CEK, salt=DumpUUID, info="MSL-SEG-v1" || LE16(i))``.

    Raises:
        ValueError: if *index* is outside 1 .. 65535.
    """
    if not 1 <= index <= MAX_SEGMENT_INDEX:
        raise ValueError(f"sealed segment index must be 1..{MAX_SEGMENT_INDEX}, got {index}")
    info = SEGMENT_KEY_INFO + index.to_bytes(2, "little")
    return hkdf_blake3(cek, salt=dump_uuid, info=info, length=AES_256_KEY_LEN)


def _validate_key_nonce(key: bytes, nonce: bytes) -> None:
    """Validate key and nonce lengths for AES-256-GCM."""
    if len(key) != AES_256_KEY_LEN:
        raise ValueError(f"Key must be {AES_256_KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != AES_GCM_NONCE_LEN:
        raise ValueError(f"Nonce must be {AES_GCM_NONCE_LEN} bytes, got {len(nonce)}")


# ---------------------------------------------------------------------------
# Streaming encryptor
# ---------------------------------------------------------------------------
class StreamingEncryptor:
    """Streaming AEAD encryptor for MSL block stream.

    Collects all plaintext blocks in memory, then encrypts the entire
    stream with AES-256-GCM at :meth:`finalize` time.  The caller passes
    the AAD, i.e. :func:`aad_from_header` of the 128-byte cleartext header.

    Usage::

        enc = StreamingEncryptor(key, nonce, aad=aad_from_header(header_bytes))
        enc.update(block_bytes)
        enc.update(block_bytes)
        ciphertext, tag = enc.finalize()
    """

    def __init__(self, key: bytes, nonce: bytes, aad: bytes) -> None:
        _validate_key_nonce(key, nonce)
        self._key = key
        self._nonce = nonce
        self._aad = aad
        self._plaintext_chunks: list[bytes] = []
        self._finalized = False

    def update(self, data: bytes) -> None:
        """Buffer plaintext block data for later encryption."""
        if self._finalized:
            raise RuntimeError("Encryptor already finalized")
        self._plaintext_chunks.append(data)

    def finalize(self) -> tuple[bytes, bytes]:
        """Encrypt accumulated plaintext and return *(ciphertext, tag)*.

        The ``cryptography`` AESGCM class appends the 16 B tag to the
        ciphertext.  We split them so the caller can write the tag
        separately at the end of the file.
        """
        if self._finalized:
            raise RuntimeError("Encryptor already finalized")
        self._finalized = True

        plaintext = b"".join(self._plaintext_chunks)
        self._plaintext_chunks.clear()

        aesgcm = AESGCM(self._key)
        ct_with_tag = aesgcm.encrypt(self._nonce, plaintext, self._aad)

        # AESGCM appends the 16 B tag at the end
        ciphertext = ct_with_tag[:-AES_GCM_TAG_LEN]
        tag = ct_with_tag[-AES_GCM_TAG_LEN:]
        return ciphertext, tag


# ---------------------------------------------------------------------------
# Streaming decryptor
# ---------------------------------------------------------------------------
class StreamingDecryptor:
    """Streaming AEAD decryptor for MSL block stream.

    Collects all ciphertext, then decrypts with AES-256-GCM at
    :meth:`finalize` time.

    Usage::

        dec = StreamingDecryptor(key, nonce, aad=aad_from_header(header_bytes))
        dec.update(ciphertext_chunk)
        plaintext = dec.finalize(tag)
    """

    def __init__(self, key: bytes, nonce: bytes, aad: bytes) -> None:
        _validate_key_nonce(key, nonce)
        self._key = key
        self._nonce = nonce
        self._aad = aad
        self._ciphertext_chunks: list[bytes] = []
        self._finalized = False

    def update(self, data: bytes) -> None:
        """Buffer ciphertext data for later decryption."""
        if self._finalized:
            raise RuntimeError("Decryptor already finalized")
        self._ciphertext_chunks.append(data)

    def finalize(self, tag: bytes) -> bytes:
        """Decrypt accumulated ciphertext using the provided 16 B auth *tag*.

        Raises ``cryptography.exceptions.InvalidTag`` if authentication fails.
        """
        if self._finalized:
            raise RuntimeError("Decryptor already finalized")
        if len(tag) != AES_GCM_TAG_LEN:
            raise ValueError(
                f"Tag must be {AES_GCM_TAG_LEN} bytes, got {len(tag)}"
            )
        self._finalized = True

        ciphertext = b"".join(self._ciphertext_chunks)
        self._ciphertext_chunks.clear()

        aesgcm = AESGCM(self._key)
        # AESGCM.decrypt expects ciphertext + tag concatenated
        return aesgcm.decrypt(self._nonce, ciphertext + tag, self._aad)
