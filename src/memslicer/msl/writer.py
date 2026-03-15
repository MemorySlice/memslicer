"""Streaming MSL file writer."""
from __future__ import annotations

import struct
import uuid
from typing import BinaryIO

from memslicer.msl.constants import (
    FILE_MAGIC, BLOCK_MAGIC, HEADER_SIZE, BLOCK_HEADER_SIZE,
    HAS_CHILDREN, BlockType, CompAlgo, PageState,
)
from memslicer.msl.types import FileHeader, MemoryRegion, ModuleEntry
from memslicer.msl.integrity import IntegrityChain
from memslicer.msl.compression import compress
from memslicer.utils.padding import pad_bytes, encode_string
from memslicer.utils.timestamps import now_ns


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
    ) -> None:
        self._output = output
        self._header = header
        self._comp_algo = comp_algo
        self._chain = IntegrityChain()
        # Write file header immediately
        self._write_header()

    # ------------------------------------------------------------------
    # File header
    # ------------------------------------------------------------------

    def _write_header(self) -> None:
        """Serialize and write the 64-byte file header."""
        h = self._header
        header_bytes = struct.pack(
            "<8sBBBBIQ16sQHHI8s",
            FILE_MAGIC,           # 8B magic
            h.endianness,         # 1B
            HEADER_SIZE,          # 1B header size
            h.version[0],         # 1B major
            h.version[1],         # 1B minor
            h.flags,              # 4B
            h.cap_bitmap,         # 8B
            h.dump_uuid,          # 16B
            h.timestamp_ns,       # 8B
            h.os_type,            # 2B
            h.arch_type,          # 2B
            h.pid,                # 4B
            b"\x00" * 8,          # 8B reserved
        )
        assert len(header_bytes) == HEADER_SIZE, (
            f"Header is {len(header_bytes)} bytes, expected {HEADER_SIZE}"
        )
        self._output.write(header_bytes)
        self._chain.feed_header(header_bytes)

    # ------------------------------------------------------------------
    # Generic block writer
    # ------------------------------------------------------------------

    def _write_block(
        self,
        block_type: BlockType,
        payload: bytes,
        flags: int = 0,
        parent_uuid: bytes | None = None,
    ) -> bytes:
        """Write a complete block and update the integrity chain.

        Returns the block's UUID.
        """
        block_uuid = uuid.uuid4().bytes
        if parent_uuid is None:
            parent_uuid = b"\x00" * 16

        padded_payload = pad_bytes(payload)
        block_length = BLOCK_HEADER_SIZE + len(padded_payload)

        block_header = struct.pack(
            "<4sHHII16s16s32s",
            BLOCK_MAGIC,            # 4B
            block_type,             # 2B
            flags,                  # 2B
            block_length,           # 4B
            0,                      # 4B reserved
            block_uuid,             # 16B
            parent_uuid,            # 16B
            self._chain.prev_hash,  # 32B
        )
        assert len(block_header) == BLOCK_HEADER_SIZE

        # Write header and payload separately to avoid large concatenation
        self._output.write(block_header)
        self._output.write(padded_payload)
        self._chain.feed_block_parts(block_header, padded_payload)
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
        + PageSize(2) + MapLength(4) + Timestamp(8)
        + PageStateMap(var, pad8) + PageData(var)
        """
        num_pages = len(region.page_states)

        # Build PageStateMap: 2 bits per page, MSB-first packing, padded to 8B
        page_state_map = self._encode_page_state_map(region.page_states)

        # Concatenate page data for CAPTURED pages only, then optionally compress
        raw_page_data = b"".join(region.page_data_chunks)
        page_data = compress(raw_page_data, self._comp_algo) if raw_page_data else b""

        # Fixed-size region header (32 bytes)
        payload = struct.pack(
            "<QQBBHIQ",
            region.base_addr,       # 8B
            region.region_size,     # 8B
            region.protection,      # 1B
            region.region_type,     # 1B
            region.page_size,       # 2B
            num_pages,              # 4B MapLength (number of pages)
            region.timestamp_ns,    # 8B
        )
        payload += pad_bytes(page_state_map)
        payload += page_data  # padded by _write_block via pad_bytes

        return self._write_block(
            BlockType.MemoryRegion, payload, parent_uuid=parent_uuid,
        )

    # ------------------------------------------------------------------
    # Module list
    # ------------------------------------------------------------------

    def write_module_list(self, modules: list[ModuleEntry]) -> bytes:
        """Write a ModuleListIndex block with HAS_CHILDREN flag,
        then individual ModuleEntry blocks as children.

        Returns the index block's UUID.
        """
        # ModuleListIndex payload: count(4) + reserved(4) = 8 bytes
        index_payload = struct.pack("<II", len(modules), 0)
        index_uuid = self._write_block(
            BlockType.ModuleListIndex, index_payload, flags=HAS_CHILDREN,
        )

        # Write each module as a child block
        for mod in modules:
            self._write_module_entry(mod, parent_uuid=index_uuid)

        return index_uuid

    def _write_module_entry(self, mod: ModuleEntry, parent_uuid: bytes) -> bytes:
        """Write a single ModuleEntry block.

        Payload:
        BaseAddr(8) + ModuleSize(8) + PathLen(2) + VersionLen(2) + Reserved(4)
        + Path(var, pad8) + Version(var, pad8) + DiskHash(32)
        + BlobLen(4) + Reserved2(4) + NativeBlob(var)
        """
        path_encoded = encode_string(mod.path)
        version_encoded = encode_string(mod.version)

        parts = [
            struct.pack(
                "<QQHHI",
                mod.base_addr,
                mod.module_size,
                len(path_encoded),
                len(version_encoded),
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
        )

    # ------------------------------------------------------------------
    # End of capture
    # ------------------------------------------------------------------

    def finalize(self) -> None:
        """Write End-of-Capture block and flush."""
        file_hash = self._chain.finalize()
        acq_end_ns = now_ns()

        # EoC payload: FileHash(32) + AcqEnd(8) + Reserved(8) = 48 bytes
        payload = file_hash + struct.pack("<Q8s", acq_end_ns, b"\x00" * 8)

        self._write_block(BlockType.EndOfCapture, payload)
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
