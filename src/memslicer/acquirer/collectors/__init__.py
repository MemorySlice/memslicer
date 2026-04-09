"""Investigation data collectors for different platforms.

Use :func:`create_collector` to obtain the appropriate collector
for the target OS.
"""
from __future__ import annotations

import logging
import os
import sys

from memslicer.acquirer.investigation import InvestigationCollector
from memslicer.msl.constants import OSType


def create_collector(
    os_type: OSType,
    is_remote: bool = False,
    logger: logging.Logger | None = None,
) -> InvestigationCollector:
    """Create the appropriate investigation collector for the target OS.

    Args:
        os_type: Target OS type (from platform detection).
        is_remote: True when target is a remote device (e.g., Frida USB/ADB).
                   For remote targets, a FridaRemoteCollector should be used
                   instead — see CLI wiring for dispatch logic.
        logger: Optional logger instance.

    Returns:
        An InvestigationCollector implementation for the target platform.
        Falls back to NullCollector when no suitable collector is available.
    """
    log = logger or logging.getLogger("memslicer")

    if os_type == OSType.Android:
        if os.path.isdir("/proc"):
            from memslicer.acquirer.collectors.android import AndroidCollector
            log.info("Using AndroidCollector for investigation data")
            return AndroidCollector(is_remote=is_remote, logger=logger)

    elif os_type == OSType.Linux:
        if os.path.isdir("/proc"):
            from memslicer.acquirer.collectors.linux import LinuxCollector
            log.info("Using LinuxCollector for investigation data")
            return LinuxCollector(logger=logger)

    elif os_type == OSType.iOS:
        if sys.platform == "darwin":
            from memslicer.acquirer.collectors.ios import IOSCollector
            log.info("Using IOSCollector for investigation data")
            return IOSCollector(logger=logger)

    elif os_type == OSType.macOS:
        if sys.platform == "darwin":
            from memslicer.acquirer.collectors.darwin import DarwinCollector
            log.info("Using DarwinCollector for investigation data")
            return DarwinCollector(logger=logger)

    elif os_type == OSType.Windows:
        if sys.platform == "win32":
            from memslicer.acquirer.collectors.windows import WindowsCollector
            log.info("Using WindowsCollector for investigation data")
            return WindowsCollector(logger=logger)

    from memslicer.acquirer.collectors.fallback import NullCollector
    return NullCollector(logger=logger)
