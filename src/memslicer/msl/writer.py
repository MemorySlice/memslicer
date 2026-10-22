"""Streaming MSL file writer."""
from __future__ import annotations

import logging
import struct
import uuid
import warnings
from typing import BinaryIO, Callable

from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, ENCRYPTED_HEADER_SIZE,
    BLOCK_HEADER_SIZE, HAS_CHILDREN, COMPRESSED, COMPALGO_MASK,
    CONTINUATION, FLAG_ENCRYPTED, BlockType, CompAlgo, PageState,
    PAGE_SIZE_LOG2_MIN, PAGE_SIZE_LOG2_MAX, valid_page_size,
    RegionType, OmissionReason,
)
from memslicer.msl.types import (
    FileHeader, MemoryRegion, ModuleEntry, ProcessIdentity, SystemContext,
    ProcessEntry, ConnectionEntry, HandleEntry, KeyHint, ImportProvenance,
    RelatedDump, KernelSymbolBundle, PhysicalMemoryMap, ConnectivityTable,
    KernelModuleList, ModuleBuildIdManifest, TargetIntrospection,
    PersistenceManifest, RegionOmissionManifest, RegionOmissionRow,
    VasEntry,
)
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.compression import compress
from memslicer.utils.padding import pad8, pad_bytes, encode_string, encode_string_bounded
from memslicer.utils.timestamps import now_ns

_log = logging.getLogger("memslicer")

_U64_MASK = (1 << 64) - 1


def _u64_wire(value: int) -> int:
    """Map a signed Python int onto the unsigned 64-bit wire field.

    Some counters the kernel exposes are signed by definition even though
    the format stores them in an unsigned ``Value(8)`` field.  The standing
    example is ``/proc/net/snmp`` ``Tcp.MaxConn``: RFC 2012 defines
    ``tcpMaxConn`` as an INTEGER where ``-1`` means "no fixed limit", and
    every Linux kernel reports exactly that -- so every investigation
    capture on a Linux host carried a value ``struct.pack("<Q")`` refuses.

    Two's complement keeps the evidence intact: ``-1`` becomes
    ``0xFFFFFFFFFFFFFFFF`` on the wire and a reader that knows the counter
    is signed recovers ``-1`` exactly.  Saturating or dropping the row
    would record something the target never said.

    Args:
        value: Any Python int, possibly negative.

    Returns:
        ``value`` reduced modulo 2**64, always packable as ``<Q``.
    """
    return value & _U64_MASK


_OMISSION_STR_MAX = 0xFFFF
_OMISSION_ROW_HEAD = struct.Struct("<QQBBBBHH")


def _encode_omission_string(value: str, field_name: str) -> bytes:
    """UTF-8 encode a RegionOmissionManifest string field.

    The on-disk length field is a u16 and the string carries no NUL
    terminator, so an embedded NUL or an oversized value is refused
    instead of silently corrupting the row boundary.

    Args:
        value: The string to encode.
        field_name: Used in the error message only.

    Returns:
        The raw UTF-8 bytes, not yet padded.

    Raises:
        ValueError: if *value* contains NUL or exceeds 65535 bytes.
    """
    if "\x00" in value:
        raise ValueError(f"RegionOmissionManifest {field_name} contains NUL")
    raw = value.encode("utf-8")
    if len(raw) > _OMISSION_STR_MAX:
        raise ValueError(
            f"RegionOmissionManifest {field_name} too long: "
            f"{len(raw)} > {_OMISSION_STR_MAX}"
        )
    return raw


def parse_region_omission_manifest(payload: bytes) -> RegionOmissionManifest:
    """Parse a RegionOmissionManifest (0x005B) block payload.

    Inverse of :meth:`MSLWriter.write_region_omission_manifest`; see
    that method for the on-disk layout. Unknown ``region_type`` or
    ``reason`` values are kept as plain ints so a newer writer's rows
    survive an older reader.

    Args:
        payload: Decompressed block payload (as yielded by
            :func:`memslicer.msl.iterator.iterate_blocks`).

    Returns:
        The reconstructed manifest.

    Raises:
        ValueError: if the payload is truncated.
    """
    if len(payload) < 16:
        raise ValueError("RegionOmissionManifest payload truncated")
    row_count, _reserved = struct.unpack_from("<II", payload, 0)
    scope_len, patterns_len, _reserved2 = struct.unpack_from("<HHI", payload, 8)
    offset = 16
    scope, offset = _read_omission_string(payload, offset, scope_len)
    patterns_raw, offset = _read_omission_string(payload, offset, patterns_len)
    patterns = patterns_raw.split("\n") if patterns_raw else []
    rows: list[RegionOmissionRow] = []
    for _ in range(row_count):
        row, offset = _read_omission_row(payload, offset)
        rows.append(row)
    return RegionOmissionManifest(scope=scope, exclude_patterns=patterns, rows=rows)


def _read_omission_string(
    payload: bytes, offset: int, length: int,
) -> tuple[str, int]:
    """Read a pad8 UTF-8 field; return ``(text, offset_after_padding)``."""
    end = offset + length
    if end > len(payload):
        raise ValueError("RegionOmissionManifest string field truncated")
    text = payload[offset:end].decode("utf-8")
    return text, offset + pad8(length)


def _read_omission_row(payload: bytes, offset: int) -> tuple[RegionOmissionRow, int]:
    """Read one row at *offset*; return ``(row, offset_after_row)``."""
    if offset + _OMISSION_ROW_HEAD.size > len(payload):
        raise ValueError("RegionOmissionManifest row truncated")
    (base_addr, size, protection, region_type, reason, _r1,
     name_len, _r2) = _OMISSION_ROW_HEAD.unpack_from(payload, offset)
    offset += _OMISSION_ROW_HEAD.size
    name, offset = _read_omission_string(payload, offset, name_len)
    row = RegionOmissionRow(
        base_addr=base_addr, size=size, protection=protection,
        region_type=_enum_or_int(RegionType, region_type),
        reason=_enum_or_int(OmissionReason, reason),
        name=name,
    )
    return row, offset


def _enum_or_int(enum_cls, value: int):
    """Return ``enum_cls(value)``, or the bare int for an unknown value."""
    try:
        return enum_cls(value)
    except ValueError:
        return value


def _packed_or_none(
    table: str, label: str, pack: Callable[[], bytes],
) -> bytes | None:
    """Run a row packer, turning an unrepresentable value into a logged drop.

    One row carrying a value outside its field's range must not cost the
    whole capture: raising here loses the memory the examiner actually
    came for, dropping the row loses one line of a system table.  The
    drop is logged so the examiner can see in the ``.msl.log`` that the
    recorded table is shorter than what the target held.

    Args:
        table: Table name as the spec calls it, for the log line.
        label: Short identification of the row (pid, iface, counter ...).
        pack: Zero-argument callable producing the packed row.

    Returns:
        The packed row, or ``None`` when ``struct`` rejected a value.
    """
    try:
        return pack()
    except struct.error as exc:
        _log.warning("%s: dropping row %s (%s)", table, label, exc)
        return None


_VAS_PATH_MAX = 0xFFFF
_VAS_ENTRY_HEAD = struct.Struct("<QQBBH4x")


def _vas_path_bytes(name: str) -> bytes:
    """Return the NUL-terminated UTF-8 VAS path, or ``b""`` if unusable.

    Unusable means empty, containing a NUL, not UTF-8 encodable, or longer
    than the u16 ``path_len`` allows once the terminator is added.
    """
    if not name or "\x00" in name:
        return b""
    try:
        raw = name.encode("utf-8") + b"\x00"
    except UnicodeEncodeError:
        return b""
    return raw if len(raw) <= _VAS_PATH_MAX else b""


def _pack_vas_entry(entry: VasEntry) -> bytes | None:
    """Pack one :class:`VasEntry` (24-byte head + padded NUL-terminated path).

    Returns ``None`` (logged) when an address or size does not fit u64.
    """
    path = _vas_path_bytes(entry.mapped_path)
    head = _packed_or_none("VASMap", f"base 0x{entry.base_addr:x}", lambda: (
        _VAS_ENTRY_HEAD.pack(
            entry.base_addr, entry.region_size,
            int(entry.protection) & 0xFF, int(entry.region_type) & 0xFF,
            len(path),
        )
    ))
    return None if head is None else head + pad_bytes(path)


def parse_vas_map(payload: bytes) -> list[VasEntry]:
    """Parse a VAS Map (0x1001) block payload.

    Inverse of :meth:`MSLWriter.write_vas_map`. Honours a non-zero
    ``entry_size`` (fixed-stride entries) as the spec allows. Unknown
    ``region_type`` values are kept as plain ints.

    Raises:
        ValueError: if the payload is truncated.
    """
    if len(payload) < 8:
        raise ValueError("VASMap payload truncated")
    count, entry_size = struct.unpack_from("<II", payload, 0)
    offset = 8
    entries: list[VasEntry] = []
    for _ in range(count):
        entry, advance = _read_vas_entry(payload, offset)
        entries.append(entry)
        offset += entry_size if entry_size else advance
    return entries


def _read_vas_entry(payload: bytes, offset: int) -> tuple[VasEntry, int]:
    """Read one entry at *offset*; return ``(entry, bytes_consumed)``."""
    if offset + _VAS_ENTRY_HEAD.size > len(payload):
        raise ValueError("VASMap entry truncated")
    base, size, prot, rtype, path_len = _VAS_ENTRY_HEAD.unpack_from(payload, offset)
    start = offset + _VAS_ENTRY_HEAD.size
    if start + path_len > len(payload):
        raise ValueError("VASMap entry path truncated")
    raw = payload[start:start + path_len].split(b"\x00", 1)[0]
    entry = VasEntry(
        base_addr=base, region_size=size, protection=prot,
        region_type=_enum_or_int(RegionType, rtype),
        mapped_path=raw.decode("utf-8", errors="replace"),
    )
    return entry, _VAS_ENTRY_HEAD.size + pad8(path_len)


def _bounded_or_absent(value: str) -> tuple[bytes, int]:
    """Encode an optional string, or report absence as a zero-length field.

    Returns:
        ``(b"", 0)`` for an empty value, otherwise the bounded encoding.
    """
    if not value:
        return b"", 0
    return encode_string_bounded(value)


def _warn_if_truncated(field: str, original: str, stored_len: int) -> None:
    """Log when a string did not fit the length field the format gives it.

    Truncating beats aborting the capture, but it is still evidence lost, so
    it must never happen quietly -- the examiner has to be able to see in the
    log that the recorded value is shorter than what the target held.

    Args:
        field: Field name as the spec calls it, for the log line.
        original: The string before encoding.
        stored_len: Pre-padding length actually written, terminator included.
    """
    if not original:
        return
    raw_len = len(original.encode("utf-8")) + 1
    if stored_len < raw_len:
        _log.warning(
            "%s truncated from %d to %d bytes to fit the format's length field",
            field, raw_len, stored_len,
        )


class MSLWriter:
    """Streaming writer for MSL format files.

    Usage:
        with open("dump.msl", "wb") as f:
            writer = MSLWriter(f, header, CompAlgo.ZSTD)
            writer.write_memory_region(region1)
            writer.write_memory_region(region2)
            writer.write_module_list([mod1, mod2])
            writer.finalize()
    """

    def __init__(
        self,
        output: BinaryIO,
        header: FileHeader,
        comp_algo: CompAlgo = CompAlgo.NONE,
        encryption_key: bytes | None = None,
        encryption_params: "EncryptionParams | None" = None,
    ) -> None:
        self._output = output
        self._header = header
        self._comp_algo = comp_algo
        self._chain = IntegrityChain(hash_algo=header.hash_algo)
        self._block_index: int = 0
        self._encrypted = bool(encryption_key)
        self._encryption_params = None
        self._encryptor = None

        # Pre-compute compression flags (constant per writer instance)
        if comp_algo != CompAlgo.NONE:
            self._comp_flags = COMPRESSED | (int(comp_algo) << 1)
        else:
            self._comp_flags = 0

        if self._encrypted:
            from memslicer.msl.encryption import (
                EncryptionParams, StreamingEncryptor,
                pack_encryption_extension,  # noqa: F811 — used in _write_header
            )
            if encryption_params is None:
                encryption_params = EncryptionParams()
            self._encryption_params = encryption_params
            self._encryption_key = encryption_key

        self._write_header()

        if self._encrypted:
            self._encryptor = StreamingEncryptor(
                key=self._encryption_key,
                nonce=self._encryption_params.nonce,
                aad=self._header_bytes,
            )

    # ------------------------------------------------------------------
    # File header
    # ------------------------------------------------------------------

    def _write_header(self) -> None:
        """Serialize and write the file header (64B or 128B when encrypted)."""
        h = self._header
        header_size = ENCRYPTED_HEADER_SIZE if self._encrypted else HEADER_SIZE

        base_header = struct.pack(
            "<8sBBHIQ16sQHHIBIB2s",
            FILE_MAGIC,                          # 8B magic
            h.endianness,                        # 1B
            header_size,                         # 1B header size (64 or 128)
            (h.version[0] << 8) | h.version[1], # 2B uint16: major in high byte
            h.flags,                             # 4B
            h.cap_bitmap,                        # 8B
            h.dump_uuid,                         # 16B
            h.timestamp_ns,                      # 8B
            h.os_type,                           # 2B
            h.arch_type,                         # 2B
            h.pid,                               # 4B
            h.clock_source,                      # 1B ClockSource
            h.block_count,                       # 4B BlockCount (0=streaming)
            h.hash_algo,                         # 1B HashAlgo (spec Section 4.4)
            b"\x00" * 2,                         # 2B reserved
        )
        assert len(base_header) == HEADER_SIZE

        if self._encrypted:
            from memslicer.msl.encryption import pack_encryption_extension  # noqa: F811
            extension = pack_encryption_extension(self._encryption_params)
            header_bytes = base_header + extension
            assert len(header_bytes) == ENCRYPTED_HEADER_SIZE
        else:
            header_bytes = base_header

        self._header_bytes = header_bytes  # saved for AAD
        self._output.write(header_bytes)
        self._chain.feed_header(header_bytes)

    # ------------------------------------------------------------------
    # Process Identity (Block 0)
    # ------------------------------------------------------------------

    def write_process_identity(self, proc_id: ProcessIdentity) -> bytes:
        """Write a ProcessIdentity block. Must be Block 0 per spec."""
        if self._block_index != 0:
            warnings.warn(
                f"Spec violation: ProcessIdentity should be Block 0, "
                f"but block_index={self._block_index}",
                stacklevel=2,
            )
        # ExePath is always present -- an unknown path is a lone NUL, so
        # ExePathLen is never 0. CmdLine is the opposite: spec Table 17 gives
        # CmdLineLen the value 0 for "unavailable", and then no bytes follow.
        exe_path_encoded, exe_path_len = encode_string_bounded(proc_id.exe_path)
        if proc_id.cmd_line:
            cmd_line_encoded, cmd_line_len = encode_string_bounded(proc_id.cmd_line)
        else:
            cmd_line_encoded, cmd_line_len = b"", 0
        _warn_if_truncated("ExePath", proc_id.exe_path, exe_path_len)
        _warn_if_truncated("CmdLine", proc_id.cmd_line, cmd_line_len)

        payload = struct.pack(
            "<IIQHHI",
            proc_id.ppid,
            proc_id.session_id,
            proc_id.start_time_ns,
            exe_path_len,
            cmd_line_len,
            0,  # Reserved
        )
        payload += exe_path_encoded
        if cmd_line_encoded:
            payload += cmd_line_encoded

        return self._write_block(BlockType.ProcessIdentity, payload)

    # ------------------------------------------------------------------
    # Generic block writer
    # ------------------------------------------------------------------

    def _write_block(
        self,
        block_type: BlockType,
        payload: bytes,
        flags: int = 0,
        parent_uuid: bytes | None = None,
        block_uuid: bytes | None = None,
    ) -> bytes:
        """Write a complete block and update the integrity chain.

        Returns the block's UUID.
        """
        if block_uuid is None:
            block_uuid = uuid.uuid4().bytes
        if parent_uuid is None:
            parent_uuid = b"\x00" * 16

        padded_payload = pad_bytes(payload)

        # Handle compression per spec Section 4.2.1:
        # Entire payload is compressed, prefixed with 8B UncompressedSize
        if flags & COMPRESSED:
            uncompressed_size = len(padded_payload)
            comp_algo = CompAlgo((flags & COMPALGO_MASK) >> 1)
            compressed_data = compress(padded_payload, comp_algo)
            # On-disk: UncompressedSize(8B) + CompressedData, padded to 8B
            on_disk_payload = pad_bytes(
                struct.pack("<Q", uncompressed_size) + compressed_data
            )
        else:
            on_disk_payload = padded_payload

        block_length = BLOCK_HEADER_SIZE + len(on_disk_payload)

        # Spec: BlockLength is uint32, max payload = 2^32 - 1 - 80 bytes
        max_payload = 0xFFFFFFFF - BLOCK_HEADER_SIZE
        if len(on_disk_payload) > max_payload:
            raise ValueError(
                f"Block payload ({len(on_disk_payload)} bytes) exceeds max "
                f"({max_payload} bytes). Use continuation blocks for large regions."
            )

        # Spec Section 4.4: PrevHash MUST be zero when Encrypted is set
        prev_hash = (
            b"\x00" * 32 if self._encrypted
            else self._chain.prev_hash
        )

        block_header = struct.pack(
            "<4sHHIHH16s16s32s",
            BLOCK_MAGIC,            # 4B
            block_type,             # 2B
            flags,                  # 2B
            block_length,           # 4B
            0x0001,                 # 2B PayloadVersion
            0,                      # 2B Reserved
            block_uuid,             # 16B
            parent_uuid,            # 16B
            prev_hash,              # 32B
        )
        assert len(block_header) == BLOCK_HEADER_SIZE

        if self._encrypted and self._encryptor is not None:
            self._encryptor.update(block_header)
            self._encryptor.update(on_disk_payload)
        else:
            self._output.write(block_header)
            self._output.write(on_disk_payload)
        self._chain.feed_block_parts(block_header, on_disk_payload)
        self._block_index += 1
        return block_uuid

    # ------------------------------------------------------------------
    # Memory region
    # ------------------------------------------------------------------

    def write_memory_region(
        self,
        region: MemoryRegion,
        parent_uuid: bytes | None = None,
    ) -> bytes:
        """Write a MemoryRegion block. Returns block UUID.

        Payload layout:
        BaseAddr(8) + RegionSize(8) + Protection(1) + RegionType(1)
        + PageSizeLog2(1) + Reserved(5) + Timestamp(8)
        + PageStateMap(var, pad8) + PageData(var)
        """
        num_pages = len(region.page_states)

        # Build PageStateMap: 2 bits per page, MSB-first packing, padded to 8B
        page_state_map = self._encode_page_state_map(region.page_states)

        # Concatenate page data for CAPTURED pages only
        # (compression is handled by _write_block per spec Section 4.2.1)
        raw_page_data = b"".join(region.page_data_chunks)

        # Spec Table 13 admits only powers of two, within the range one byte of
        # PageSizeLog2 can carry. valid_page_size owns that rule, so producers
        # can reject a bad page size before a capture runs on it rather than
        # discovering it here. The branch below only picks which diagnostic to
        # report -- it does not decide whether the value is acceptable.
        if not valid_page_size(region.page_size):
            if region.page_size <= 0 or (region.page_size & (region.page_size - 1)):
                raise ValueError(
                    f"page_size must be a power of 2, got {region.page_size}"
                )
            raise ValueError(
                f"PageSizeLog2 {region.page_size.bit_length() - 1} outside valid "
                f"range [{PAGE_SIZE_LOG2_MIN}, {PAGE_SIZE_LOG2_MAX}] "
                f"(page_size={region.page_size})"
            )

        # Spec Table 13: RegionSize MUST be a multiple of PageSize
        if region.region_size % region.page_size != 0:
            raise ValueError(
                f"region_size ({region.region_size}) must be a multiple of "
                f"page_size ({region.page_size})"
            )

        # Cross-validate page_states count matches RegionSize / PageSize
        expected_pages = region.region_size // region.page_size
        if len(region.page_states) != expected_pages:
            raise ValueError(
                f"page_states count ({len(region.page_states)}) does not match "
                f"region_size/page_size ({expected_pages})"
            )

        # Already range-checked by valid_page_size above.
        page_size_log2 = region.page_size.bit_length() - 1

        payload = struct.pack("<QQ", region.base_addr, region.region_size)
        payload += struct.pack(
            "<BBB5sQ",
            region.protection,      # 1B
            region.region_type,     # 1B
            page_size_log2,         # 1B PageSizeLog2
            b"\x00" * 5,           # 5B Reserved
            region.timestamp_ns,    # 8B
        )
        payload += pad_bytes(page_state_map)
        payload += raw_page_data  # padded by _write_block via pad_bytes

        return self._write_block(
            BlockType.MemoryRegion, payload, flags=self._comp_flags,
            parent_uuid=parent_uuid,
        )

    # ------------------------------------------------------------------
    # Module list
    # ------------------------------------------------------------------

    def write_module_list(self, modules: list[ModuleEntry]) -> bytes:
        """Write a ModuleListIndex block followed immediately by its children.

        Convenience wrapper over :meth:`write_module_list_index` and
        :meth:`write_module_entries` for callers that do not care where the
        children land. The acquisition engine does care -- spec Section 2.1
        reserves Block 2 for System Context in investigation mode, so it
        defers the children until after the memory regions instead.

        Args:
            modules: Modules to announce and then emit.

        Returns:
            The index block's UUID.
        """
        index_uuid, module_uuids = self.write_module_list_index(modules)
        self.write_module_entries(modules, index_uuid, module_uuids)
        return index_uuid

    def write_module_list_index(
        self, modules: list[ModuleEntry],
    ) -> tuple[bytes, list[bytes]]:
        """Write only the ModuleListIndex block, announcing its children.

        The child UUIDs are generated here rather than when the children are
        written, so the manifest can name blocks that do not exist on disk
        yet. That is what lets the entries be emitted later in the file.

        Args:
            modules: Modules to list. May be empty, in which case the block
                carries a zero count and no HAS_CHILDREN flag -- the block is
                still written, so Block 1 is a Module List either way and the
                positions the spec fixes do not shift with module presence.

        Returns:
            ``(index_uuid, module_uuids)``. Pass both to
            :meth:`write_module_entries` to emit the children.
        """
        if self._block_index != 1:
            warnings.warn(
                f"Spec violation: ModuleListIndex should be Block 1, "
                f"but block_index={self._block_index}",
                stacklevel=2,
            )
        # Pre-generate UUIDs for each module entry
        module_uuids = [uuid.uuid4().bytes for _ in modules]

        # Build manifest payload: count(4) + reserved(4) + per-entry data
        manifest = struct.pack("<II", len(modules), 0)

        for mod, mod_uuid in zip(modules, module_uuids):
            path_raw = mod.path.encode("utf-8") + b"\x00"
            path_padded = encode_string(mod.path)
            manifest += mod_uuid                                    # 16B ModuleUUID
            manifest += struct.pack("<QQHHI",
                mod.base_addr,                                      # 8B BaseAddr
                mod.module_size,                                    # 8B ModuleSize
                len(path_raw),                                      # 2B PathLen (incl. null)
                0,                                                  # 2B Reserved
                0,                                                  # 4B Reserved2
            )
            manifest += path_padded                                 # var Path (pad8)

        index_uuid = self._write_block(
            BlockType.ModuleListIndex, manifest,
            flags=HAS_CHILDREN if modules else 0,
        )
        return index_uuid, module_uuids

    def write_module_entries(
        self,
        modules: list[ModuleEntry],
        index_uuid: bytes,
        module_uuids: list[bytes],
    ) -> None:
        """Emit the ModuleEntry children a ModuleListIndex already announced.

        Each child is written with the UUID the manifest promised, so the
        index stays valid no matter how far downstream this is called.

        Args:
            modules: The same modules passed to
                :meth:`write_module_list_index`, in the same order.
            index_uuid: UUID of the index block, recorded as each child's
                parent.
            module_uuids: The child UUIDs that method returned.
        """
        for mod, mod_uuid in zip(modules, module_uuids):
            self._write_module_entry(mod, parent_uuid=index_uuid, block_uuid=mod_uuid)

    def _write_module_entry(self, mod: ModuleEntry, parent_uuid: bytes, block_uuid: bytes | None = None) -> bytes:
        """Write a single ModuleEntry block.

        Payload:
        BaseAddr(8) + ModuleSize(8) + PathLen(2) + VersionLen(2) + Reserved(4)
        + Path(var, pad8) + Version(var, pad8) + DiskHash(32)
        + BlobLen(4) + Reserved2(4) + NativeBlob(var)
        """
        path_raw = mod.path.encode("utf-8") + b"\x00"
        path_encoded = encode_string(mod.path)

        # Spec: VersionLen = 0 when version is unavailable (empty string)
        if mod.version:
            version_raw = mod.version.encode("utf-8") + b"\x00"
            version_encoded = encode_string(mod.version)
            version_len = len(version_raw)
        else:
            version_encoded = b""
            version_len = 0

        parts = [
            struct.pack(
                "<QQHHI",
                mod.base_addr,
                mod.module_size,
                len(path_raw),        # pre-padding length (incl. null)
                version_len,          # 0 when unavailable per spec
                0,
            ),
            path_encoded,
            version_encoded,
            mod.disk_hash,
            struct.pack("<II", len(mod.native_blob), 0),
        ]
        if mod.native_blob:
            parts.append(mod.native_blob)

        return self._write_block(
            BlockType.ModuleEntry, b"".join(parts), parent_uuid=parent_uuid,
            block_uuid=block_uuid,
        )

    # ------------------------------------------------------------------
    # Investigation Mode: SystemContext (Block 2)
    # ------------------------------------------------------------------

    def write_system_context(self, ctx: SystemContext) -> bytes:
        """Write SystemContext block. Must be Block 2 in Investigation mode."""
        acq_user_raw = ctx.acq_user.encode("utf-8") + b"\x00" if ctx.acq_user else b"\x00"
        hostname_raw = ctx.hostname.encode("utf-8") + b"\x00" if ctx.hostname else b"\x00"
        domain_raw = ctx.domain.encode("utf-8") + b"\x00" if ctx.domain else b""
        os_detail_raw = ctx.os_detail.encode("utf-8") + b"\x00" if ctx.os_detail else b"\x00"
        case_ref_raw = ctx.case_ref.encode("utf-8") + b"\x00" if ctx.case_ref else b""

        # Fixed header: 32 bytes — BootTsn(8) + TCt(1) + TBm(4) + 5xLen(10) + R(9)
        payload = struct.pack(
            "<QBIHHHHH9s",
            ctx.boot_time,          # 8B BootTsn
            ctx.target_count,       # 1B TCt (target count, max 255)
            ctx.table_bitmap,       # 4B TBm (table bitmap)
            len(acq_user_raw),      # 2B AcqUserLen
            len(hostname_raw),      # 2B HostnameLen
            len(domain_raw),        # 2B DomainLen (0 if omitted)
            len(os_detail_raw),     # 2B OSDetailLen
            len(case_ref_raw),      # 2B CaseRefLen (0 if omitted)
            b"\x00" * 9,            # 9B Reserved
        )
        # Variable strings (pad8 each)
        if acq_user_raw:
            payload += pad_bytes(acq_user_raw)
        if hostname_raw:
            payload += pad_bytes(hostname_raw)
        if domain_raw:
            payload += pad_bytes(domain_raw)
        if os_detail_raw:
            payload += pad_bytes(os_detail_raw)
        if case_ref_raw:
            payload += pad_bytes(case_ref_raw)

        return self._write_block(BlockType.SystemContext, payload)

    # ------------------------------------------------------------------
    # Investigation Mode: ProcessTable
    # ------------------------------------------------------------------

    def write_process_table(self, processes: list[ProcessEntry], parent_uuid: bytes) -> bytes:
        """Write ProcessTable block. ParentUUID must reference SystemContext."""
        # Entries are packed first so EntryCount can describe what actually
        # made it in: a row carrying a value the format cannot represent is
        # dropped, and the count must not promise it.
        entries: list[bytes] = []
        for proc in processes:
            # Every one of these is a uint16 length, and cmd_line in
            # particular is unbounded on Linux. This table covers every
            # process on the host, so a single outlier must not be able to
            # abort the capture.
            exe_enc, exe_len = _bounded_or_absent(proc.exe_name)
            cmd_enc, cmd_len = _bounded_or_absent(proc.cmd_line)
            user_enc, user_len = _bounded_or_absent(proc.user)
            _warn_if_truncated("ProcessTable.CmdLine", proc.cmd_line, cmd_len)

            try:
                entry = struct.pack(
                    "<III B3s QQ HHH2s",
                    proc.pid,
                    proc.ppid,
                    proc.uid,
                    0x01 if proc.is_target else 0x00,
                    b"\x00" * 3,           # Reserved
                    proc.start_time,
                    proc.rss,
                    exe_len,
                    cmd_len,
                    user_len,
                    b"\x00" * 2,           # Reserved2
                )
            except struct.error as exc:
                # One unrepresentable row must not cost the whole capture.
                # Dropping it loses a line of the process table; raising
                # here loses the memory the examiner actually came for.
                _log.warning(
                    "ProcessTable: dropping pid %s (%s): %s",
                    proc.pid, proc.exe_name or "?", exc,
                )
                continue
            entry += exe_enc + cmd_enc + user_enc
            entries.append(entry)

        payload = struct.pack("<II", len(entries), 0) + b"".join(entries)

        return self._write_block(
            BlockType.ProcessTable, payload, parent_uuid=parent_uuid,
        )

    # ------------------------------------------------------------------
    # Investigation Mode: ConnectionTable
    # ------------------------------------------------------------------

    def write_connection_table(self, connections: list[ConnectionEntry], parent_uuid: bytes) -> bytes:
        """Write ConnectionTable block. ParentUUID must reference SystemContext."""
        # Entries are packed first so EntryCount describes what actually made
        # it in (same rule as write_process_table): a row the format cannot
        # represent is dropped and logged, never promised by the count.
        entries: list[bytes] = []
        for conn in connections:
            entry = _packed_or_none(
                "ConnectionTable",
                f"pid {conn.pid} local_port {conn.local_port}",
                lambda: struct.pack(
                    "<IBBB1s 16s H2s 16s H2s",
                    conn.pid,
                    conn.family,
                    conn.protocol,
                    conn.state,
                    b"\x00",               # Reserved
                    conn.local_addr,
                    conn.local_port,
                    b"\x00" * 2,           # Reserved2
                    conn.remote_addr,
                    conn.remote_port,
                    b"\x00" * 2,           # Reserved3
                ),
            )
            if entry is None:
                continue
            entries.append(entry)

        # Preamble: EntryCount(4B) + Reserved(4B) per spec Table 22
        payload = struct.pack("<II", len(entries), 0) + b"".join(entries)

        return self._write_block(
            BlockType.ConnectionTable, payload, parent_uuid=parent_uuid,
        )

    # ------------------------------------------------------------------
    # Investigation Mode: HandleTable
    # ------------------------------------------------------------------

    def write_handle_table(self, handles: list[HandleEntry], parent_uuid: bytes) -> bytes:
        """Write HandleTable block. ParentUUID must reference SystemContext.

        ``FD`` is a uint32; a collector that has no descriptor number for a
        row (lsof ``cwd``/``txt``/``mem`` on macOS) must hand over
        ``0xFFFFFFFF``, not ``-1``.  A negative fd is unrepresentable and
        the row is dropped and logged rather than aborting the capture.
        """
        # Entries are packed first so EntryCount describes what actually made
        # it in (same rule as write_process_table).
        entries: list[bytes] = []
        for h in handles:
            path_raw = h.path.encode("utf-8") + b"\x00" if h.path else b""
            entry = _packed_or_none(
                "HandleTable",
                f"pid {h.pid} fd {h.fd}",
                lambda: struct.pack(
                    "<IIB1sH4s",
                    h.pid,
                    h.fd,
                    h.handle_type,
                    b"\x00",               # Reserved
                    len(path_raw),
                    b"\x00" * 4,           # Reserved2
                ),
            )
            if entry is None:
                continue
            if path_raw:
                entry += pad_bytes(path_raw)
            entries.append(entry)

        # Preamble: EntryCount(4B) + Reserved(4B) per spec Table 23
        payload = struct.pack("<II", len(entries), 0) + b"".join(entries)

        return self._write_block(
            BlockType.HandleTable, payload, parent_uuid=parent_uuid,
        )

    # ------------------------------------------------------------------
    # Key Hint (Section 5.6, Table 18)
    # ------------------------------------------------------------------

    def write_key_hint(self, hint: KeyHint) -> bytes:
        """Write a KeyHint block. Returns block UUID.

        Payload layout (36B fixed + variable Note):
        RegionUUID(16) + RegionOffset(8) + KeyLen(4) + KeyType(2)
        + Protocol(2) + Confidence(1) + KeyState(1) + Reserved(2)
        + NoteLen(4) + Reserved2(4) + Note(var, pad8)
        """
        note_raw = hint.note.encode("utf-8") + b"\x00" if hint.note else b""
        note_len = len(note_raw)

        payload = hint.region_uuid                          # 16B RegionUUID
        payload += struct.pack(
            "<QIHH BB 2s I 4s",
            hint.region_offset,                             # 8B RegionOffset
            hint.key_len,                                   # 4B KeyLen
            hint.key_type,                                  # 2B KeyType
            hint.protocol,                                  # 2B Protocol
            hint.confidence,                                # 1B Confidence
            hint.key_state,                                 # 1B KeyState
            b"\x00" * 2,                                    # 2B Reserved
            note_len,                                       # 4B NoteLen
            b"\x00" * 4,                                    # 4B Reserved2
        )
        if note_raw:
            payload += pad_bytes(note_raw)

        return self._write_block(BlockType.KeyHint, payload)

    # ------------------------------------------------------------------
    # Import Provenance (Section 11, Table 28)
    # ------------------------------------------------------------------

    def write_import_provenance(self, prov: ImportProvenance) -> bytes:
        """Write an ImportProvenance block. Returns block UUID.

        Payload layout:
        SourceFormat(2) + Reserved(2) + ToolNameLen(4) + ImportTime(8)
        + OrigFileSize(8) + NoteLen(4) + Reserved2(4)
        + ToolName(var, pad8) + Note(var, pad8)
        """
        tool_raw = prov.tool_name.encode("utf-8") + b"\x00" if prov.tool_name else b""
        note_raw = prov.note.encode("utf-8") + b"\x00" if prov.note else b""

        payload = struct.pack(
            "<HH I Q Q I 4s",
            prov.source_format,                             # 2B SourceFormat
            0,                                              # 2B Reserved
            len(tool_raw),                                  # 4B ToolNameLen
            prov.import_time,                               # 8B ImportTime
            prov.orig_file_size,                            # 8B OrigFileSize
            len(note_raw),                                  # 4B NoteLen
            b"\x00" * 4,                                    # 4B Reserved2
        )
        if tool_raw:
            payload += pad_bytes(tool_raw)
        if note_raw:
            payload += pad_bytes(note_raw)

        return self._write_block(BlockType.ImportProvenance, payload)

    # ------------------------------------------------------------------
    # Related Dump (Section 5.5, Table 17)
    # ------------------------------------------------------------------

    def write_related_dump(self, related: RelatedDump) -> bytes:
        """Write a RelatedDump block. Returns block UUID.

        Payload layout (24B FIXED):
        RelatedDumpUUID(16) + RelatedPID(4) + Relationship(2) + Reserved(2)
        """
        payload = related.related_dump_uuid                 # 16B RelatedDumpUUID
        payload += struct.pack(
            "<IH2s",
            related.related_pid,                            # 4B RelatedPID
            related.relationship,                           # 2B Relationship
            b"\x00" * 2,                                    # 2B Reserved
        )

        return self._write_block(BlockType.RelatedDump, payload)

    # ------------------------------------------------------------------
    # Kernel symbol bundle (P1.6.1, Block 0x0055)
    # ------------------------------------------------------------------

    def write_kernel_symbol_bundle(self, bundle: KernelSymbolBundle) -> bytes:
        """Write a KernelSymbolBundle block. Returns block UUID.

        Tagged-row TLV payload:
            row_count: u32
            reserved:  u32
            rows:      (tag u16, len u16, value bytes[len]) * row_count

        Only non-zero / non-empty fields are emitted as rows.
        """
        rows: list[bytes] = []

        def emit(tag: int, value: bytes) -> None:
            if not value:
                return
            rows.append(struct.pack("<HH", tag, len(value)) + value)

        def emit_u32(tag: int, v: int) -> None:
            if v:
                emit(tag, struct.pack("<I", v))

        def emit_u64(tag: int, v: int) -> None:
            if v:
                emit(tag, struct.pack("<Q", v))

        def emit_u8(tag: int, v: int) -> None:
            if v:
                emit(tag, struct.pack("<B", v))

        def emit_str(tag: int, s: str) -> None:
            if s:
                emit(tag, s.encode("utf-8"))

        emit_u32(0x0001, bundle.page_size)
        emit(0x0002, bundle.kernel_build_id)
        emit_u64(0x0003, bundle.kaslr_text_va)
        emit_u64(0x0004, bundle.kernel_page_offset)
        emit_u8(0x0005, bundle.la57_enabled)
        emit_u8(0x0006, bundle.pti_active)
        emit(0x0007, bundle.btf_sha256)
        emit_u64(0x0008, bundle.btf_size_bytes)
        emit(0x0009, bundle.vmcoreinfo_sha256)
        emit(0x000A, bundle.kernel_config_sha256)
        emit_u64(0x000B, bundle.clock_realtime_ns)
        emit_u64(0x000C, bundle.clock_monotonic_ns)
        emit_u64(0x000D, bundle.clock_boottime_ns)
        emit_str(0x000E, bundle.clocksource)
        emit_str(0x000F, bundle.thp_mode)
        emit_u8(0x0010, bundle.ksm_active)
        emit_u64(0x0011, bundle.directmap_4k_kib)
        emit_u64(0x0012, bundle.directmap_2m_kib)
        emit_u64(0x0013, bundle.directmap_1g_kib)
        emit_str(0x0014, bundle.zram_devices_json)
        emit_u8(0x0015, bundle.zswap_enabled)

        payload = struct.pack("<II", len(rows), 0) + b"".join(rows)
        return self._write_block(BlockType.KernelSymbolBundle, payload)

    # ------------------------------------------------------------------
    # Physical memory map (P1.6.1, Block 0x0059 — non-spec extension)
    # ------------------------------------------------------------------

    def write_physical_memory_map(self, mmap: PhysicalMemoryMap) -> bytes:
        """Write a PhysicalMemoryMap block. Returns block UUID.

        Payload layout:
            row_count: u32
            reserved:  u32
            rows: for each range:
                start:     u64
                end:       u64
                label_len: u16
                reserved:  u16
                label:     bytes[label_len]  (UTF-8, not NUL-terminated)
        """
        rows: list[bytes] = []
        for start, end, label in mmap.ranges:
            label_bytes = label.encode("utf-8")
            rows.append(
                struct.pack("<QQHH", start, end, len(label_bytes), 0)
                + label_bytes
            )
        payload = struct.pack("<II", len(mmap.ranges), 0) + b"".join(rows)
        return self._write_block(BlockType.PhysicalMemoryMap, payload)

    # ------------------------------------------------------------------
    # ConnectivityTable (P1.6.5, Block 0x0054)
    # ------------------------------------------------------------------

    def write_connectivity_table(self, table: ConnectivityTable) -> bytes:
        """Write a ConnectivityTable block (0x0054, P1.6.5).

        Tagged-row TLV payload:
            row_count: u32
            reserved:  u32
            rows:      (row_type u8, row_len u16, row_body bytes[row_len]) * row_count

        Row bodies pack tight; no internal padding. Unknown row_types
        are skippable via ``row_len``.

        Row 0x07 (SNMP counter) stores ``Value`` as an unsigned 8-byte
        field, but the kernel reports some MIB entries signed --
        ``Tcp.MaxConn`` is ``-1`` ("no fixed limit", RFC 2012) on every
        Linux kernel.  Such values are written two's-complement
        (``-1`` -> ``0xFFFFFFFFFFFFFFFF``) via :func:`_u64_wire`, so the
        evidence survives verbatim and a reader aware of the counter's
        signedness recovers it exactly.

        Any other row whose value the format cannot hold is dropped and
        logged; ``row_count`` is computed from the rows actually packed.
        """
        rows: list[bytes] = []

        def _str_field(s: str) -> bytes:
            encoded = s.encode("utf-8")
            return struct.pack("<H", len(encoded)) + encoded

        def _append_row(row_type: int, label: str, build_body: Callable[[], bytes]) -> None:
            # One bad row must not cost the whole capture (see _packed_or_none).
            body = _packed_or_none("ConnectivityTable", label, build_body)
            if body is None:
                return
            rows.append(struct.pack("<BH", row_type, len(body)) + body)

        for r in table.ipv4_routes:
            _append_row(0x01, f"ipv4_route {r.iface}", lambda: (
                _str_field(r.iface)
                + r.dest + r.gateway + r.mask
                + struct.pack("<HII", r.flags, r.metric, r.mtu)
            ))

        for r in table.ipv6_routes:
            _append_row(0x02, f"ipv6_route {r.iface}", lambda: (
                _str_field(r.iface)
                + r.dest
                + struct.pack("<B", r.dest_prefix)
                + r.next_hop
                + struct.pack("<II", r.metric, r.flags)
            ))

        for r in table.arp_entries:
            _append_row(0x03, f"arp {r.iface}", lambda: (
                struct.pack("<B", r.family)
                + r.ip
                + struct.pack("<HH", r.hw_type, r.flags)
                + r.hw_addr
                + _str_field(r.iface)
            ))

        for r in table.packet_sockets:
            _append_row(0x04, f"packet socket inode {r.inode}", lambda: struct.pack(
                "<IQHIIQ",
                r.pid, r.inode, r.proto, r.iface_index, r.user, r.rmem,
            ))

        for r in table.netdev_stats:
            _append_row(0x05, f"netdev {r.iface}", lambda: (
                _str_field(r.iface)
                + struct.pack(
                    "<QQQQQQQQ",
                    r.rx_bytes, r.rx_packets, r.rx_errs, r.rx_drop,
                    r.tx_bytes, r.tx_packets, r.tx_errs, r.tx_drop,
                )
            ))

        for r in table.sockstat_families:
            _append_row(0x06, f"sockstat family {r.family}", lambda: struct.pack(
                "<BIIQ", r.family, r.in_use, r.alloc, r.mem,
            ))

        for r in table.snmp_counters:
            # Signed MIB values (Tcp.MaxConn = -1) go on the wire as
            # two's complement; see the docstring and _u64_wire.
            _append_row(0x07, f"snmp {r.mib}.{r.counter}", lambda: (
                _str_field(r.mib)
                + _str_field(r.counter)
                + struct.pack("<Q", _u64_wire(r.value))
            ))

        # Count what was actually packed, not what was offered: a dropped
        # row must not be promised by the preamble.
        payload = struct.pack("<II", len(rows), 0) + b"".join(rows)
        return self._write_block(BlockType.ConnectivityTable, payload)

    # ------------------------------------------------------------------
    # KernelModuleList (P1.6.2, Block 0x0057)
    # ------------------------------------------------------------------

    def write_kernel_module_list(self, table: KernelModuleList) -> bytes:
        """Write a KernelModuleList block (0x0057, P1.6.2)."""
        rows_bytes: list[bytes] = []
        for r in table.rows:
            name_bytes = r.name.encode("utf-8")
            row = _packed_or_none("KernelModuleList", f"module {r.name}", lambda: (
                struct.pack("<H", len(name_bytes))
                + name_bytes
                + struct.pack(
                    "<QIBBQBB",
                    r.size, r.refcount, r.state, r.taint,
                    r.base, r.flags, 0,
                )
            ))
            if row is None:
                continue
            rows_bytes.append(row)
        # Count the rows actually packed, so a dropped row is never promised.
        payload = struct.pack("<II", len(rows_bytes), 0) + b"".join(rows_bytes)
        return self._write_block(BlockType.KernelModuleList, payload)

    # ------------------------------------------------------------------
    # TargetIntrospection (P1.6.3, Block 0x0058)
    # ------------------------------------------------------------------

    def write_target_introspection(self, info: TargetIntrospection) -> bytes:
        """Write a TargetIntrospection block (0x0058, P1.6.3).

        Tagged-row TLV payload:

        .. code-block:: text

            target_pid: u32          # for multi-target disambiguation
            reserved:   u32          # must be zero
            rows:       (tag u16, len u16, value bytes[len]) * N

        Unlike :meth:`write_kernel_symbol_bundle`, the 8-byte header is
        ``(target_pid, reserved)`` — NOT ``(row_count, reserved)``. The
        TLV-skip-zero policy makes row_count awkward to pre-compute, so
        readers discover rows by walking TLV to end-of-payload.

        Zero / empty values are not emitted (same skip-zero policy as
        :class:`KernelSymbolBundle`).
        """
        rows: list[bytes] = []

        def emit(tag: int, value: bytes) -> None:
            if not value:
                return
            rows.append(struct.pack("<HH", tag, len(value)) + value)

        def emit_u8(tag: int, v: int) -> None:
            if v:
                emit(tag, struct.pack("<B", v))

        def emit_u32(tag: int, v: int) -> None:
            if v:
                emit(tag, struct.pack("<I", v))

        def emit_u64(tag: int, v: int) -> None:
            if v:
                emit(tag, struct.pack("<Q", v))

        def emit_str(tag: int, s: str) -> None:
            if s:
                emit(tag, s.encode("utf-8"))

        emit_u32(0x0001, info.tracer_pid)
        emit_u32(0x0002, info.login_uid)
        emit_u32(0x0003, info.session_audit_id)
        emit_str(0x0004, info.selinux_context)
        emit_str(0x0005, info.target_ns_fingerprint)
        emit_str(0x0006, info.target_ns_scope_vs_collector)
        emit_u64(0x0007, info.smaps_rollup_pss_kib)
        emit_u64(0x0008, info.smaps_rollup_swap_kib)
        emit_u64(0x0009, info.smaps_anon_hugepages_kib)
        emit_u32(0x000A, info.rwx_region_count)
        emit_str(0x000B, info.target_cgroup)
        emit_str(0x000C, info.target_cwd)
        emit_str(0x000D, info.target_root)
        emit_str(0x000E, info.cap_eff)
        emit_str(0x000F, info.cap_amb)
        emit_u8(0x0010, info.no_new_privs)
        emit_u8(0x0011, info.seccomp_mode)
        emit_u8(0x0012, info.core_dumping)
        emit_u32(0x0013, info.thread_count)
        emit_str(0x0014, info.sig_cgt)
        emit_u64(0x0015, info.io_rchar)
        emit_u64(0x0016, info.io_wchar)
        emit_u64(0x0017, info.io_read_bytes)
        emit_u64(0x0018, info.io_write_bytes)
        emit_str(0x0019, info.limit_core)
        emit_str(0x001A, info.limit_memlock)
        emit_str(0x001B, info.limit_nofile)
        emit_str(0x001C, info.personality_hex)
        emit_str(0x001D, info.ancestry)
        emit_u8(0x001E, info.exe_comm_mismatch)
        if info.environ:
            raw_env = (
                info.environ
                if isinstance(info.environ, bytes)
                else info.environ.encode("utf-8")
            )
            emit(0x001F, raw_env)
        if info.redacted_env_keys:
            emit_str(0x0020, ",".join(info.redacted_env_keys))

        payload = struct.pack("<II", info.target_pid, 0) + b"".join(rows)
        return self._write_block(BlockType.TargetIntrospection, payload)

    # ------------------------------------------------------------------
    # ModuleBuildIdManifest (P1.6.2, Block 0x005A — non-spec extension)
    # ------------------------------------------------------------------

    def write_module_build_id_manifest(
        self, manifest: ModuleBuildIdManifest,
    ) -> bytes:
        """Write a ModuleBuildIdManifest block (0x005A, P1.6.2).

        Fixed-size 64-byte rows — no variable-length fields — so the
        append-only overlay can be parsed without a schema lookup.
        """
        ROW_SIZE = 64
        rows_bytes: list[bytes] = []
        for r in manifest.rows:
            if len(r.build_id) > 20:
                raise ValueError(
                    f"build_id too long: {len(r.build_id)} > 20"
                )
            if len(r.disk_hash) > 32:
                raise ValueError(
                    f"disk_hash too long: {len(r.disk_hash)} > 32"
                )
            build_id_padded = r.build_id + b"\x00" * (20 - len(r.build_id))
            disk_hash_padded = r.disk_hash + b"\x00" * (32 - len(r.disk_hash))
            row = (
                struct.pack(
                    "<QBBBB",
                    r.base_addr, r.build_id_len,
                    r.build_id_source, r.flags, 0,
                )
                + build_id_padded
                + disk_hash_padded
            )
            assert len(row) == ROW_SIZE
            rows_bytes.append(row)
        payload = (
            struct.pack("<II", len(manifest.rows), 0)
            + b"".join(rows_bytes)
        )
        return self._write_block(
            BlockType.ModuleBuildIdManifest, payload,
        )

    # ------------------------------------------------------------------
    # RegionOmissionManifest (Block 0x005B — non-spec extension)
    # ------------------------------------------------------------------

    def write_region_omission_manifest(
        self, manifest: RegionOmissionManifest,
    ) -> bytes:
        """Write a RegionOmissionManifest block (0x005B). Returns block UUID.

        Lists regions the acquirer deliberately skipped so a reader can
        tell a partial dump from an incomplete one. Little-endian; all
        strings UTF-8 without NUL terminator, each padded to 8 bytes.

        .. code-block:: text

            Payload header:
                row_count:    u32
                reserved:     u32
                scope_len:    u16
                patterns_len: u16
                reserved:     u32
                scope:        bytes[scope_len]     pad8
                patterns:     bytes[patterns_len]  pad8  (joined with "\\n")
            Row:
                base_addr:   u64
                size:        u64
                protection:  u8
                region_type: u8
                reason:      u8
                reserved:    u8
                name_len:    u16
                reserved:    u16
                name:        bytes[name_len]  pad8

        Raises:
            ValueError: if a string does not fit its u16 length field.
        """
        scope_bytes = _encode_omission_string(manifest.scope, "scope")
        patterns_bytes = _encode_omission_string(
            "\n".join(manifest.exclude_patterns), "exclude_patterns",
        )
        rows_bytes = [self._pack_omission_row(r) for r in manifest.rows]
        payload = (
            struct.pack("<II", len(rows_bytes), 0)
            + struct.pack("<HHI", len(scope_bytes), len(patterns_bytes), 0)
            + pad_bytes(scope_bytes)
            + pad_bytes(patterns_bytes)
            + b"".join(rows_bytes)
        )
        return self._write_block(BlockType.RegionOmissionManifest, payload)

    @staticmethod
    def _pack_omission_row(row: RegionOmissionRow) -> bytes:
        """Pack one :class:`RegionOmissionRow` (fixed 24-byte head + name)."""
        name_bytes = _encode_omission_string(row.name, "name")
        head = struct.pack(
            "<QQBBBBHH",
            row.base_addr, row.size,
            row.protection, int(row.region_type), int(row.reason), 0,
            len(name_bytes), 0,
        )
        return head + pad_bytes(name_bytes)

    # ------------------------------------------------------------------
    # VAS Map (Block 0x1001)
    # ------------------------------------------------------------------

    def write_vas_map(self, entries: list[VasEntry]) -> bytes:
        """Write a VAS Map block (0x1001): the full address-space layout.

        Uses the writer's normal compression flags. Returns the block UUID.

        .. code-block:: text

            Payload header:
                entry_count: u32
                entry_size:  u32      # 0 = variable-length entries
            Entry:
                base_addr:   u64
                region_size: u64
                protection:  u8
                region_type: u8
                path_len:    u16      # incl. NUL; 0 when no path
                reserved:    4 bytes
                path:        bytes[path_len]  NUL-terminated, pad8

        A name that contains a NUL, is not encodable as UTF-8 or does not
        fit the u16 length (NUL included) is dropped -- the entry is kept
        with an empty path, never failing the capture.
        """
        packed = [_pack_vas_entry(e) for e in entries]
        rows = [p for p in packed if p is not None]
        # Count the entries actually packed, so a dropped one is never promised.
        payload = struct.pack("<II", len(rows), 0) + b"".join(rows)
        return self._write_block(
            BlockType.VASMap, payload, flags=self._comp_flags,
        )

    # ------------------------------------------------------------------
    # PersistenceManifest (P1.6.4, Block 0x0056)
    # ------------------------------------------------------------------

    def write_persistence_manifest(self, manifest: PersistenceManifest) -> bytes:
        """Write a PersistenceManifest block (0x0056, P1.6.4).

        Fixed-row payload — no tag dispatch. Every row has the same
        layout:

        .. code-block:: text

            Payload header:
                row_count: u32
                reserved:  u32
            Row:
                source:   u8       # 1..11 persistence class
                reserved: u8
                path_len: u16
                path:     bytes[path_len]   # utf-8, not NUL-terminated
                mtime_ns: u64
                size:     u64      # bytes
                mode:     u32      # st_mode

        Source type enum:

        * 1 = systemd_system        (/etc/systemd/system, /run/…, /usr/lib/…)
        * 2 = systemd_user          (/etc/systemd/user)
        * 3 = cron_system           (/etc/crontab, /etc/cron.d, /etc/cron.*)
        * 4 = cron_user             (/var/spool/cron, …/crontabs)
        * 5 = rc_local              (/etc/rc.local)
        * 6 = profile_d             (/etc/profile.d)
        * 7 = pam_d                 (/etc/pam.d)
        * 8 = udev_rules            (/etc/udev/rules.d, /run/udev/rules.d)
        * 9 = modprobe_d            (/etc/modprobe.d)
        * 10 = system_generators    (/etc/systemd/system-generators, …)
        * 11 = modules_load         (/etc/modules, /etc/modules-load.d)
        """
        rows_bytes: list[bytes] = []
        for r in manifest.rows:
            path_bytes = r.path.encode("utf-8")
            row = _packed_or_none("PersistenceManifest", f"path {r.path}", lambda: (
                struct.pack("<BBH", r.source, 0, len(path_bytes))
                + path_bytes
                + struct.pack("<QQI", r.mtime_ns, r.size, r.mode)
            ))
            if row is None:
                continue
            rows_bytes.append(row)
        # Count the rows actually packed, so a dropped row is never promised.
        payload = (
            struct.pack("<II", len(rows_bytes), 0)
            + b"".join(rows_bytes)
        )
        return self._write_block(BlockType.PersistenceManifest, payload)

    # ------------------------------------------------------------------
    # End of capture
    # ------------------------------------------------------------------

    def finalize(self) -> None:
        """Write End-of-Capture block and flush.

        When encrypted: flushes all buffered blocks as AEAD ciphertext
        and appends the 16-byte authentication tag.
        """
        if self._block_index == 0:
            # Nothing was written, so the EoC below is about to land in
            # Block 0 -- the slot the spec reserves for ProcessIdentity.
            warnings.warn(
                "Spec violation: finalizing a capture with no blocks; "
                "EndOfCapture will occupy Block 0 instead of ProcessIdentity",
                stacklevel=2,
            )
        file_hash = self._chain.finalize()
        acq_end_ns = now_ns()

        # EoC payload: FileHash(32) + AcqEnd(8) + Reserved(8) = 48 bytes
        payload = file_hash + struct.pack("<Q8s", acq_end_ns, b"\x00" * 8)

        self._write_block(BlockType.EndOfCapture, payload)

        if self._encrypted and self._encryptor is not None:
            # Encrypt the entire block stream and write ciphertext + tag
            ciphertext, tag = self._encryptor.finalize()
            self._output.write(ciphertext)
            self._output.write(tag)

        self._output.flush()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_page_state_map(page_states: list[PageState]) -> bytes:
        """Encode page states as 2 bits per page, MSB-first packing.

        Each byte holds 4 page states:
        bits 7-6 = page 0, bits 5-4 = page 1, bits 3-2 = page 2, bits 1-0 = page 3.
        """
        if not page_states:
            return b""

        num_bytes = (len(page_states) + 3) // 4  # 4 pages per byte
        result = bytearray(num_bytes)

        for i, state in enumerate(page_states):
            byte_idx = i // 4
            bit_pos = 6 - (i % 4) * 2  # 6, 4, 2, 0
            result[byte_idx] |= (state & 0x03) << bit_pos

        return bytes(result)
