"""Shared test fixtures for MemSlicer tests."""
import pytest
import uuid
from unittest.mock import MagicMock

from memslicer.msl.constants import OSType, ArchType, CompAlgo, PageState, RegionType
from memslicer.msl.types import FileHeader, MemoryRegion, ModuleEntry
from memslicer.utils.timestamps import now_ns


@pytest.fixture
def sample_header():
    """A minimal FileHeader for testing."""
    return FileHeader(
        endianness=1,
        version=(1, 0),
        flags=0,
        cap_bitmap=0x03,  # MemoryRegions + ModuleList
        dump_uuid=uuid.uuid4().bytes,
        timestamp_ns=now_ns(),
        os_type=OSType.Linux,
        arch_type=ArchType.x86_64,
        pid=1234,
    )


@pytest.fixture
def sample_region():
    """A memory region with mixed page states."""
    return MemoryRegion(
        base_addr=0x10000,
        region_size=4096 * 3,
        protection=0x05,  # R+X
        region_type=RegionType.Image,
        page_size=4096,
        timestamp_ns=now_ns(),
        page_states=[PageState.CAPTURED, PageState.FAILED, PageState.CAPTURED],
        page_data_chunks=[b'\xaa' * 4096, b'\xbb' * 4096],  # Only 2 chunks for 2 CAPTURED
    )


@pytest.fixture
def sample_modules():
    """Two sample module entries."""
    return [
        ModuleEntry(
            base_addr=0x400000,
            module_size=0x10000,
            path="/usr/lib/libc.so.6",
            version="2.31",
            disk_hash=b'\x00' * 32,
            native_blob=b"",
        ),
        ModuleEntry(
            base_addr=0x7f0000,
            module_size=0x5000,
            path="/usr/lib/libpthread.so.0",
            version="2.31",
            disk_hash=b'\xff' * 32,
            native_blob=b"\x01\x02\x03\x04",
        ),
    ]


@pytest.fixture
def mock_frida_script():
    """Mock Frida script with canned RPC exports."""
    script = MagicMock()
    api = MagicMock()

    api.get_arch.return_value = "x64"
    api.get_platform.return_value = "linux"
    api.get_page_size.return_value = 4096

    api.enumerate_ranges.return_value = [
        {
            "base": "0x10000",
            "size": 4096,
            "protection": "r--",
            "file": {"path": "/usr/lib/libc.so.6", "offset": 0, "size": 4096},
        },
        {
            "base": "0x20000",
            "size": 8192,
            "protection": "rw-",
            "file": None,
        },
    ]

    api.enumerate_modules.return_value = [
        {"name": "libc.so.6", "base": "0x10000", "size": 0x10000, "path": "/usr/lib/libc.so.6"},
        {"name": "app", "base": "0x400000", "size": 0x1000, "path": "/home/user/app"},
    ]

    # read_memory returns bytes for all addresses
    api.read_memory.return_value = b'\xcc' * 4096

    script.exports_sync = api
    return script, api
