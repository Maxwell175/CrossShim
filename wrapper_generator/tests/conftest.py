"""Pytest configuration and fixtures for wrapper generator tests."""

import os
import pytest
from pathlib import Path


# Default NDK path - can be overridden with environment variable
DEFAULT_NDK_PATH = "/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64/bin"


@pytest.fixture
def ndk_path() -> str:
    """Get the NDK toolchain path."""
    return os.environ.get("ANDROID_NDK_TOOLCHAIN", DEFAULT_NDK_PATH)


@pytest.fixture
def test_data_dir() -> Path:
    """Get the test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture
def sample_library_path(test_data_dir: Path) -> Path:
    """Get path to a sample ARM64 library for testing."""
    # Look for any .so file in the test data directory
    lib_path = test_data_dir / "libtest.so"
    if lib_path.exists():
        return lib_path

    # Try to find TUTK libraries as fallback
    tutk_path = Path("/mnt/ExtraSSD/src/WyzeBridgeDotNet/AndroidWrapperGenerator")
    if tutk_path.exists():
        lib = tutk_path / "libIOTCAPIs.so"
        if lib.exists():
            return lib

    # Try build directory
    build_path = tutk_path / "build"
    if build_path.exists():
        for lib in build_path.glob("lib*.so"):
            if "tutk_c_api" not in lib.name:  # Skip the generated wrapper
                return lib

    pytest.skip("No sample library available for testing")


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Get a temporary output directory for generated files."""
    output_dir = tmp_path / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

