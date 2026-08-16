"""Tests for platform detection."""
from unittest.mock import MagicMock, patch

import pytest
from memslicer.msl.constants import OSType, ArchType
from memslicer.acquirer.platform_detect import (
    detect_arch,
    detect_os,
    detect_platform,
    parse_gdb_auxv_page_size,
    parse_gdb_osabi,
    parse_maps_text,
    parse_proc_maps,
    valid_page_size,
)


class TestDetectArch:
    def test_ia32(self):
        assert detect_arch("ia32") == ArchType.x86

    def test_x64(self):
        assert detect_arch("x64") == ArchType.x86_64

    def test_arm(self):
        assert detect_arch("arm") == ArchType.ARM32

    def test_arm64(self):
        assert detect_arch("arm64") == ArchType.ARM64

    def test_unknown(self):
        with pytest.raises(ValueError):
            detect_arch("mips")


class TestDetectOS:
    def test_windows(self):
        assert detect_os("windows") == OSType.Windows

    def test_linux(self):
        assert detect_os("linux") == OSType.Linux

    def test_darwin_macos(self):
        modules = [{"name": "libsystem_kernel.dylib", "path": "/usr/lib/system/libsystem_kernel.dylib"}]
        assert detect_os("darwin", modules) == OSType.macOS

    def test_darwin_ios_uikit(self):
        modules = [{"name": "UIKit", "path": "/System/Library/Frameworks/UIKit.framework/UIKit"}]
        assert detect_os("darwin", modules) == OSType.iOS

    def test_linux_android_linker(self):
        modules = [{"name": "linker64", "path": "/system/bin/linker64"}]
        assert detect_os("linux", modules) == OSType.Android

    def test_linux_android_runtime(self):
        modules = [{"name": "libandroid_runtime.so", "path": "/system/lib64/libandroid_runtime.so"}]
        assert detect_os("linux", modules) == OSType.Android

    def test_linux_android_art(self):
        modules = [{"name": "libart.so", "path": "/system/lib64/libart.so"}]
        assert detect_os("linux", modules) == OSType.Android

    def test_os_override(self):
        assert detect_os("linux", [], os_override=OSType.Android) == OSType.Android

    def test_unknown_platform(self):
        with pytest.raises(ValueError):
            detect_os("freebsd")


class TestDetectPlatform:
    def test_full_detection(self):
        os_type, arch_type = detect_platform("x64", "linux")
        assert os_type == OSType.Linux
        assert arch_type == ArchType.x86_64

    def test_with_override(self):
        os_type, arch_type = detect_platform("arm64", "darwin", os_override=OSType.iOS)
        assert os_type == OSType.iOS
        assert arch_type == ArchType.ARM64


SAMPLE_MAPS = (
    "55a1b2c00000-55a1b2c01000 r-xp 00000000 08:01 131074 /usr/bin/target\n"
    "7f8e4a000000-7f8e4a1f4000 r-xp 00027000 08:01 262145 "
    "/usr/lib/x86_64-linux-gnu/libc.so.6\n"
    "7f8e4b000000-7f8e4b021000 rw-p 00000000 00:00 0 \n"
    "55a1b3400000-55a1b3421000 rw-p 00000000 00:00 0 [heap]\n"
    "7ffd1c000000-7ffd1c021000 rw-p 00000000 00:00 0 [stack]\n"
    "7ffd1c1c2000-7ffd1c1c6000 r--p 00000000 00:00 0 [vvar]\n"
    "7ffd1c1c6000-7ffd1c1c7000 r--p 00000000 00:00 0 [vvar_vclock]\n"
    "7ffd1c1c7000-7ffd1c1c9000 r-xp 00000000 00:00 0 [vdso]\n"
    "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n"
)


class TestParseMapsText:
    """Tests for parse_maps_text() -- pure /proc/<pid>/maps text parsing."""

    def test_range_count(self):
        assert len(parse_maps_text(SAMPLE_MAPS)) == 9

    def test_file_backed_line(self):
        rng = parse_maps_text(SAMPLE_MAPS)[1]
        assert rng.base == 0x7F8E4A000000
        assert rng.size == 0x1F4000
        assert rng.protection == "r-x"
        assert rng.file_path == "/usr/lib/x86_64-linux-gnu/libc.so.6"

    def test_anonymous_line_has_no_path(self):
        rng = parse_maps_text(SAMPLE_MAPS)[2]
        assert rng.base == 0x7F8E4B000000
        assert rng.size == 0x21000
        assert rng.protection == "rw-"
        assert rng.file_path == ""

    def test_heap(self):
        rng = parse_maps_text(SAMPLE_MAPS)[3]
        assert rng.base == 0x55A1B3400000
        assert rng.size == 0x21000
        assert rng.protection == "rw-"
        assert rng.file_path == "[heap]"

    def test_stack(self):
        rng = parse_maps_text(SAMPLE_MAPS)[4]
        assert rng.base == 0x7FFD1C000000
        assert rng.size == 0x21000
        assert rng.protection == "rw-"
        assert rng.file_path == "[stack]"

    def test_vvar(self):
        rng = parse_maps_text(SAMPLE_MAPS)[5]
        assert rng.base == 0x7FFD1C1C2000
        assert rng.size == 0x4000
        assert rng.protection == "r--"
        assert rng.file_path == "[vvar]"

    def test_vvar_vclock(self):
        rng = parse_maps_text(SAMPLE_MAPS)[6]
        assert rng.base == 0x7FFD1C1C6000
        assert rng.size == 0x1000
        assert rng.protection == "r--"
        assert rng.file_path == "[vvar_vclock]"

    def test_vdso(self):
        rng = parse_maps_text(SAMPLE_MAPS)[7]
        assert rng.base == 0x7FFD1C1C7000
        assert rng.size == 0x2000
        assert rng.protection == "r-x"
        assert rng.file_path == "[vdso]"

    def test_vsyscall(self):
        rng = parse_maps_text(SAMPLE_MAPS)[8]
        assert rng.base == 0xFFFFFFFFFF600000
        assert rng.size == 0x1000
        assert rng.protection == "--x"
        assert rng.file_path == "[vsyscall]"

    @pytest.mark.parametrize("perms,expected", [
        ("rw-p", "rw-"),
        ("r--s", "r--"),
        ("r-xp", "r-x"),
        ("---p", "---"),
    ])
    def test_protection_normalisation(self, perms, expected):
        line = f"1000-2000 {perms} 00000000 00:00 0 [heap]"
        assert parse_maps_text(line)[0].protection == expected

    def test_short_lines_are_skipped(self):
        text = (
            "1000-2000 rw-p 00000000 00:00\n"
            "3000-4000 rw-p\n"
            "5000-6000 rw-p 00000000 00:00 0 [heap]\n"
        )
        ranges = parse_maps_text(text)
        assert len(ranges) == 1
        assert ranges[0].base == 0x5000

    def test_exactly_five_fields_yields_empty_path(self):
        ranges = parse_maps_text("1000-2000 rw-p 00000000 00:00 0")
        assert len(ranges) == 1
        assert ranges[0].file_path == ""

    def test_empty_string(self):
        assert parse_maps_text("") == []

    def test_blank_and_garbage_lines_ignored(self):
        text = (
            "\n"
            "   \n"
            "not a maps line\n"
            "1000-2000 rw-p 00000000 00:00 0 [heap]\n"
            "\n"
        )
        ranges = parse_maps_text(text)
        assert len(ranges) == 1
        assert ranges[0].file_path == "[heap]"


class TestParseProcMaps:
    """Tests for parse_proc_maps() -- the I/O wrapper around parse_maps_text()."""

    def test_reads_and_delegates(self):
        handle = MagicMock(
            __enter__=lambda s: s,
            __exit__=MagicMock(return_value=False),
            read=lambda: SAMPLE_MAPS,
        )
        with patch("builtins.open", MagicMock(return_value=handle)):
            ranges = parse_proc_maps(1234, logger=MagicMock())
        assert len(ranges) == 9
        assert ranges[3].file_path == "[heap]"

    def test_file_not_found_logs_warning(self):
        logger = MagicMock()
        with patch("builtins.open", side_effect=FileNotFoundError):
            ranges = parse_proc_maps(1234, logger=logger)
        assert ranges == []
        logger.warning.assert_called_once()
        assert "not found" in logger.warning.call_args[0][0]

    def test_permission_error_logs_warning(self):
        logger = MagicMock()
        with patch("builtins.open", side_effect=PermissionError):
            ranges = parse_proc_maps(1234, logger=logger)
        assert ranges == []
        logger.warning.assert_called_once()
        assert "Permission denied" in logger.warning.call_args[0][0]


class TestParseGdbOsabi:
    """Tests for parse_gdb_osabi() -- the target's OS, as GDB sees it.

    The host's platform.system() names the wrong machine whenever the target
    is remote, so this is the only source that holds for a remote capture.
    """

    @pytest.mark.parametrize(
        "osabi,expected",
        [
            ("GNU/Linux", OSType.Linux),
            ("Linux", OSType.Linux),
            ("Darwin", OSType.macOS),
            ("Windows", OSType.Windows),
            ("Cygwin", OSType.Windows),
            ("FreeBSD", OSType.FreeBSD),
            ("NetBSD ELF", OSType.NetBSD),
            ("OpenBSD ELF", OSType.OpenBSD),
            ("QNX Neutrino", OSType.QNX),
            ("Fuchsia", OSType.Fuchsia),
        ],
    )
    def test_auto_form_names_the_current_abi(self, osabi, expected):
        text = (
            f'The current OS ABI is "auto" (currently "{osabi}").\n'
            f'The default OS ABI is "{osabi}".\n'
        )
        assert parse_gdb_osabi(text) == expected

    def test_direct_form(self):
        """An explicitly set osabi is reported without the "auto" wrapper."""
        assert parse_gdb_osabi('The current OS ABI is "Darwin".') == OSType.macOS

    def test_default_line_does_not_win(self):
        """The default names the fallback, not the ABI actually in force."""
        text = (
            'The current OS ABI is "auto" (currently "Darwin").\n'
            'The default OS ABI is "GNU/Linux".\n'
        )
        assert parse_gdb_osabi(text) == OSType.macOS

    @pytest.mark.parametrize("osabi", ["none", "unknown", "SVR4", "Solaris", "AIX"])
    def test_abi_msl_cannot_represent_returns_none(self, osabi):
        """These are routine GDB answers, so the caller falls back rather than
        aborting or recording a guess."""
        text = f'The current OS ABI is "auto" (currently "{osabi}").'
        assert parse_gdb_osabi(text) is None

    def test_unparseable_returns_none(self):
        assert parse_gdb_osabi("something totally unknown") is None

    def test_empty_returns_none(self):
        assert parse_gdb_osabi("") is None


class TestParseGdbAuxvPageSize:
    """Tests for parse_gdb_auxv_page_size() -- the target's page size.

    A wrong page size is not recoverable from the finished MSL file: only
    PageSizeLog2 is stored and the page-state map is sized to match, so the
    capture is self-consistent and wrong.
    """

    def test_decimal_value(self):
        text = (
            "33   AT_SYSINFO_EHDR      System-supplied DSO   0x7ffff7fc9000\n"
            "6    AT_PAGESZ            System page size      65536\n"
            "17   AT_CLKTCK            Frequency of times()  100\n"
        )
        assert parse_gdb_auxv_page_size(text) == 65536

    def test_hex_value(self):
        text = "6    AT_PAGESZ            System page size      0x1000\n"
        assert parse_gdb_auxv_page_size(text) == 4096

    def test_absent_row_returns_none(self):
        text = "17   AT_CLKTCK            Frequency of times()  100\n"
        assert parse_gdb_auxv_page_size(text) is None

    def test_implausible_value_is_rejected(self):
        """A row that parses but cannot describe a real page must not reach the
        writer, which would commit a geometry no reader can tell is wrong."""
        text = "6    AT_PAGESZ            System page size      3000\n"
        assert parse_gdb_auxv_page_size(text) is None

    def test_empty_returns_none(self):
        assert parse_gdb_auxv_page_size("") is None


class TestValidPageSize:
    """Tests for valid_page_size() -- the guard shared by both bridges."""

    @pytest.mark.parametrize("value", [1024, 4096, 16384, 65536, 1 << 21])
    def test_accepts_real_page_sizes(self, value):
        assert valid_page_size(value) is True

    @pytest.mark.parametrize("value", [0, -4096, 3000, 512, 1 << 41])
    def test_rejects_everything_else(self, value):
        assert valid_page_size(value) is False
