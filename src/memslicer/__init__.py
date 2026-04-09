"""MemSlicer - Memory slice capture and analysis toolkit."""

__version__ = "0.1.0"

from memslicer.msl.constants import (
    BlockType,
    CompAlgo,
    ClockSource,
    Endianness,
    OSType,
    ArchType,
    PageState,
    RegionType,
    CapBit,
)
from memslicer.acquirer.bridge import (
    DebuggerBridge,
    MemoryRange,
    ModuleInfo,
    PlatformInfo,
)
from memslicer.acquirer.engine import AcquisitionEngine
from memslicer.msl.types import (
    SystemContext,
    KeyHint,
    ImportProvenance,
    RelatedDump,
)

__all__ = [
    "__version__",
    "BlockType",
    "ClockSource",
    "CompAlgo",
    "Endianness",
    "OSType",
    "ArchType",
    "PageState",
    "RegionType",
    "CapBit",
    "DebuggerBridge",
    "MemoryRange",
    "ModuleInfo",
    "PlatformInfo",
    "AcquisitionEngine",
    "SystemContext",
    "KeyHint",
    "ImportProvenance",
    "RelatedDump",
]
