"""Tests for platform detection."""
import pytest
from memslicer.msl.constants import OSType, ArchType
from memslicer.acquirer.platform_detect import detect_arch, detect_os, detect_platform


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
