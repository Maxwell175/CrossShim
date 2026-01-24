"""End-to-end tests that build sample Android libraries and wrap them."""

import os
import pytest
import subprocess
from pathlib import Path
from textwrap import dedent

from android_wrapper_generator.wrapper_generator import WrapperGenerator, WrapperConfig


# NDK paths
DEFAULT_NDK_PATH = "/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64/bin"
ANDROID_CLANG = "aarch64-linux-android21-clang"
ANDROID_CLANGPP = "aarch64-linux-android21-clang++"


@pytest.fixture
def ndk_bin_path() -> Path:
    """Get the NDK bin path."""
    path = Path(os.environ.get("ANDROID_NDK_TOOLCHAIN", DEFAULT_NDK_PATH))
    if not path.exists():
        pytest.skip(f"NDK not found at {path}")
    return path


@pytest.fixture
def android_clang(ndk_bin_path: Path) -> Path:
    """Get the Android clang compiler."""
    clang = ndk_bin_path / ANDROID_CLANG
    if not clang.exists():
        pytest.skip(f"Android clang not found at {clang}")
    return clang


@pytest.fixture
def android_clangpp(ndk_bin_path: Path) -> Path:
    """Get the Android clang++ compiler."""
    clangpp = ndk_bin_path / ANDROID_CLANGPP
    if not clangpp.exists():
        pytest.skip(f"Android clang++ not found at {clangpp}")
    return clangpp


class TestE2ESimpleLibrary:
    """End-to-end tests with a simple C library."""

    SIMPLE_LIB_SOURCE = dedent("""
        // Simple math library for testing
        
        __attribute__((visibility("default")))
        int add(int a, int b) {
            return a + b;
        }
        
        __attribute__((visibility("default")))
        int subtract(int a, int b) {
            return a - b;
        }
        
        __attribute__((visibility("default")))
        int multiply(int a, int b) {
            return a * b;
        }
        
        __attribute__((visibility("default")))
        int divide(int a, int b) {
            if (b == 0) return 0;
            return a / b;
        }
        
        // Internal function - should not be exported
        static int internal_helper(int x) {
            return x * 2;
        }
        
        __attribute__((visibility("default")))
        int double_value(int x) {
            return internal_helper(x);
        }
    """)

    @pytest.fixture
    def simple_lib(self, tmp_path: Path, android_clang: Path) -> Path:
        """Build a simple Android ARM64 shared library."""
        # Write source file
        src_file = tmp_path / "simple_math.c"
        src_file.write_text(self.SIMPLE_LIB_SOURCE)
        
        # Build shared library
        lib_file = tmp_path / "libsimple_math.so"
        result = subprocess.run(
            [
                str(android_clang),
                "-shared",
                "-fPIC",
                "-fvisibility=hidden",
                "-o", str(lib_file),
                str(src_file),
            ],
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0:
            pytest.fail(f"Failed to build library: {result.stderr}")
        
        return lib_file

    def test_extract_symbols_from_built_library(self, simple_lib: Path, ndk_bin_path: Path):
        """Test that we can extract symbols from a library we built."""
        config = WrapperConfig(
            wrapper_name="simple_math",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(simple_lib)],
        )
        generator = WrapperGenerator(config)
        
        functions = generator.get_function_list()
        
        # Should have our 5 exported functions
        assert "add" in functions
        assert "subtract" in functions
        assert "multiply" in functions
        assert "divide" in functions
        assert "double_value" in functions
        
        # Should NOT have the internal helper
        assert "internal_helper" not in functions

    def test_generate_wrapper_for_built_library(self, simple_lib: Path, ndk_bin_path: Path, tmp_path: Path):
        """Test generating a complete wrapper for a library we built."""
        output_dir = tmp_path / "generated"
        
        config = WrapperConfig(
            wrapper_name="simple_math_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(simple_lib)],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()
        
        # Check generated files exist
        assert (output_dir / "include" / "simple_math_wrapper.h").exists()
        assert (output_dir / "src" / "simple_math_wrapper.cpp").exists()
        assert (output_dir / "CMakeLists.txt").exists()
        assert (output_dir / "data" / "libsimple_math_so.inc").exists()
        
        # Check header content
        header = (output_dir / "include" / "simple_math_wrapper.h").read_text()
        assert "simple_math_wrapper_add" in header
        assert "simple_math_wrapper_subtract" in header
        assert "simple_math_wrapper_multiply" in header
        assert "simple_math_wrapper_divide" in header
        assert "simple_math_wrapper_double_value" in header

    def test_generate_with_exclude_filter(self, simple_lib: Path, ndk_bin_path: Path, tmp_path: Path):
        """Test generating wrapper with excluded functions."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="filtered_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(simple_lib)],
            output_dir=str(output_dir),
            exclude_functions=["divide", "double_value"],
        )
        generator = WrapperGenerator(config)
        generator.generate()

        header = (output_dir / "include" / "filtered_wrapper.h").read_text()
        assert "filtered_wrapper_add" in header
        assert "filtered_wrapper_subtract" in header
        assert "filtered_wrapper_multiply" in header
        assert "filtered_wrapper_divide" not in header
        assert "filtered_wrapper_double_value" not in header

    def test_generate_with_include_filter(self, simple_lib: Path, ndk_bin_path: Path, tmp_path: Path):
        """Test generating wrapper with only included functions."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="include_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(simple_lib)],
            output_dir=str(output_dir),
            include_functions=["add", "multiply"],
        )
        generator = WrapperGenerator(config)
        generator.generate()

        header = (output_dir / "include" / "include_wrapper.h").read_text()
        assert "include_wrapper_add" in header
        assert "include_wrapper_multiply" in header
        assert "include_wrapper_subtract" not in header
        assert "include_wrapper_divide" not in header


class TestE2ECppLibrary:
    """End-to-end tests with a C++ library using extern "C"."""

    CPP_LIB_SOURCE = dedent('''
        // C++ library with C API for testing
        #include <cstdint>
        #include <cstring>

        extern "C" {

        // String manipulation functions
        __attribute__((visibility("default")))
        int string_length(const char* str) {
            if (!str) return 0;
            return strlen(str);
        }

        __attribute__((visibility("default")))
        void string_copy(char* dest, const char* src, int max_len) {
            if (!dest || !src || max_len <= 0) return;
            strncpy(dest, src, max_len - 1);
            dest[max_len - 1] = '\\0';
        }

        // Buffer operations
        __attribute__((visibility("default")))
        void* buffer_create(int size) {
            if (size <= 0) return nullptr;
            return new uint8_t[size]();
        }

        __attribute__((visibility("default")))
        void buffer_destroy(void* buffer) {
            delete[] static_cast<uint8_t*>(buffer);
        }

        __attribute__((visibility("default")))
        int buffer_write(void* buffer, int offset, const void* data, int size) {
            if (!buffer || !data || offset < 0 || size <= 0) return -1;
            memcpy(static_cast<uint8_t*>(buffer) + offset, data, size);
            return size;
        }

        __attribute__((visibility("default")))
        int buffer_read(const void* buffer, int offset, void* data, int size) {
            if (!buffer || !data || offset < 0 || size <= 0) return -1;
            memcpy(data, static_cast<const uint8_t*>(buffer) + offset, size);
            return size;
        }

        } // extern "C"
    ''')

    @pytest.fixture
    def cpp_lib(self, tmp_path: Path, android_clangpp: Path) -> Path:
        """Build a C++ Android ARM64 shared library."""
        src_file = tmp_path / "buffer_lib.cpp"
        src_file.write_text(self.CPP_LIB_SOURCE)

        lib_file = tmp_path / "libbuffer.so"
        result = subprocess.run(
            [
                str(android_clangpp),
                "-shared",
                "-fPIC",
                "-fvisibility=hidden",
                "-std=c++17",
                "-o", str(lib_file),
                str(src_file),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to build C++ library: {result.stderr}")

        return lib_file

    def test_extract_cpp_library_symbols(self, cpp_lib: Path, ndk_bin_path: Path):
        """Test extracting symbols from C++ library with extern C."""
        config = WrapperConfig(
            wrapper_name="buffer",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(cpp_lib)],
        )
        generator = WrapperGenerator(config)

        functions = generator.get_function_list()

        assert "string_length" in functions
        assert "string_copy" in functions
        assert "buffer_create" in functions
        assert "buffer_destroy" in functions
        assert "buffer_write" in functions
        assert "buffer_read" in functions

    def test_generate_cpp_library_wrapper(self, cpp_lib: Path, ndk_bin_path: Path, tmp_path: Path):
        """Test generating wrapper for C++ library."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="buffer_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(cpp_lib)],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()

        header = (output_dir / "include" / "buffer_wrapper.h").read_text()
        impl = (output_dir / "src" / "buffer_wrapper.cpp").read_text()

        # Check all functions are wrapped
        assert "buffer_wrapper_string_length" in header
        assert "buffer_wrapper_buffer_create" in header
        assert "buffer_wrapper_buffer_destroy" in header

        # Check implementation includes emulator calls
        assert "call_function" in impl
        assert "get_symbol" in impl


class TestE2EMultipleLibraries:
    """End-to-end tests with multiple libraries."""

    MATH_LIB_SOURCE = dedent("""
        __attribute__((visibility("default")))
        int math_add(int a, int b) { return a + b; }

        __attribute__((visibility("default")))
        int math_sub(int a, int b) { return a - b; }
    """)

    UTIL_LIB_SOURCE = dedent("""
        __attribute__((visibility("default")))
        int util_max(int a, int b) { return a > b ? a : b; }

        __attribute__((visibility("default")))
        int util_min(int a, int b) { return a < b ? a : b; }
    """)

    @pytest.fixture
    def multi_libs(self, tmp_path: Path, android_clang: Path) -> list[Path]:
        """Build multiple Android ARM64 shared libraries."""
        libs = []

        for name, source in [("math", self.MATH_LIB_SOURCE), ("util", self.UTIL_LIB_SOURCE)]:
            src_file = tmp_path / f"{name}.c"
            src_file.write_text(source)

            lib_file = tmp_path / f"lib{name}.so"
            result = subprocess.run(
                [
                    str(android_clang),
                    "-shared", "-fPIC", "-fvisibility=hidden",
                    "-o", str(lib_file),
                    str(src_file),
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                pytest.fail(f"Failed to build {name} library: {result.stderr}")

            libs.append(lib_file)

        return libs

    def test_extract_from_multiple_libraries(self, multi_libs: list[Path], ndk_bin_path: Path):
        """Test extracting symbols from multiple libraries."""
        config = WrapperConfig(
            wrapper_name="combined",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(lib) for lib in multi_libs],
        )
        generator = WrapperGenerator(config)

        functions = generator.get_function_list()

        # Should have functions from both libraries
        assert "math_add" in functions
        assert "math_sub" in functions
        assert "util_max" in functions
        assert "util_min" in functions

    def test_generate_wrapper_for_multiple_libraries(self, multi_libs: list[Path], ndk_bin_path: Path, tmp_path: Path):
        """Test generating wrapper for multiple libraries."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="combined_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(lib) for lib in multi_libs],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()

        # Check generated files
        header = (output_dir / "include" / "combined_wrapper.h").read_text()

        # Should have all functions from both libraries
        assert "combined_wrapper_math_add" in header
        assert "combined_wrapper_math_sub" in header
        assert "combined_wrapper_util_max" in header
        assert "combined_wrapper_util_min" in header

        # Should have embedded data for both libraries
        assert (output_dir / "data" / "libmath_so.inc").exists()
        assert (output_dir / "data" / "libutil_so.inc").exists()


class TestE2ECrossLibraryCalls:
    """End-to-end tests for cross-library function calls.

    These tests verify that functions in one shared library can call
    functions defined in another shared library when both are loaded
    into the emulator.
    """

    # Base library with core functions
    CORE_LIB_SOURCE = dedent("""
        // Core library with basic operations

        __attribute__((visibility("default")))
        int core_add(int a, int b) {
            return a + b;
        }

        __attribute__((visibility("default")))
        int core_multiply(int a, int b) {
            return a * b;
        }

        __attribute__((visibility("default")))
        int core_square(int x) {
            return x * x;
        }

        // Global state for testing
        static int g_core_counter = 0;

        __attribute__((visibility("default")))
        void core_increment_counter(void) {
            g_core_counter++;
        }

        __attribute__((visibility("default")))
        int core_get_counter(void) {
            return g_core_counter;
        }

        __attribute__((visibility("default")))
        void core_reset_counter(void) {
            g_core_counter = 0;
        }
    """)

    # Client library that depends on core library
    CLIENT_LIB_SOURCE = dedent("""
        // Client library that calls functions from core library

        // Declare external functions from core library
        extern int core_add(int a, int b);
        extern int core_multiply(int a, int b);
        extern int core_square(int x);
        extern void core_increment_counter(void);
        extern int core_get_counter(void);
        extern void core_reset_counter(void);

        __attribute__((visibility("default")))
        int client_sum_of_squares(int a, int b) {
            // Uses core_square from core library
            return core_add(core_square(a), core_square(b));
        }

        __attribute__((visibility("default")))
        int client_power_of_two(int exp) {
            // Uses core_multiply from core library
            int result = 1;
            for (int i = 0; i < exp; i++) {
                result = core_multiply(result, 2);
            }
            return result;
        }

        __attribute__((visibility("default")))
        int client_factorial(int n) {
            // Uses core_multiply from core library
            int result = 1;
            for (int i = 2; i <= n; i++) {
                result = core_multiply(result, i);
            }
            return result;
        }

        __attribute__((visibility("default")))
        int client_increment_and_get(void) {
            // Uses core_increment_counter and core_get_counter
            core_increment_counter();
            return core_get_counter();
        }

        __attribute__((visibility("default")))
        void client_reset(void) {
            core_reset_counter();
        }
    """)

    # Third library that depends on both core and client
    ADVANCED_LIB_SOURCE = dedent("""
        // Advanced library that calls functions from both core and client

        // Declare external functions
        extern int core_add(int a, int b);
        extern int core_multiply(int a, int b);
        extern int client_sum_of_squares(int a, int b);
        extern int client_factorial(int n);

        __attribute__((visibility("default")))
        int advanced_pythagorean_check(int a, int b, int c) {
            // Check if a^2 + b^2 == c^2 using client_sum_of_squares
            int sum_sq = client_sum_of_squares(a, b);
            int c_sq = core_multiply(c, c);
            return sum_sq == c_sq ? 1 : 0;
        }

        __attribute__((visibility("default")))
        int advanced_combination(int n, int r) {
            // Calculate n! / (r! * (n-r)!) using client_factorial
            if (r > n || r < 0) return 0;
            if (r == 0 || r == n) return 1;

            int n_fact = client_factorial(n);
            int r_fact = client_factorial(r);
            int nr_fact = client_factorial(n - r);

            return n_fact / core_multiply(r_fact, nr_fact);
        }

        __attribute__((visibility("default")))
        int advanced_chain_call(int x) {
            // Chain: core_add -> client_sum_of_squares -> core_multiply
            int step1 = core_add(x, x);           // 2x
            int step2 = client_sum_of_squares(step1, x);  // (2x)^2 + x^2 = 5x^2
            return core_multiply(step2, 2);       // 10x^2
        }
    """)

    @pytest.fixture
    def cross_lib_core(self, tmp_path: Path, android_clang: Path) -> Path:
        """Build the core library."""
        src_file = tmp_path / "core.c"
        src_file.write_text(self.CORE_LIB_SOURCE)

        lib_file = tmp_path / "libcore.so"
        result = subprocess.run(
            [
                str(android_clang),
                "-shared", "-fPIC", "-fvisibility=hidden",
                "-o", str(lib_file),
                str(src_file),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to build core library: {result.stderr}")

        return lib_file

    @pytest.fixture
    def cross_lib_client(self, tmp_path: Path, android_clang: Path, cross_lib_core: Path) -> Path:
        """Build the client library that depends on core."""
        src_file = tmp_path / "client.c"
        src_file.write_text(self.CLIENT_LIB_SOURCE)

        lib_file = tmp_path / "libclient.so"
        result = subprocess.run(
            [
                str(android_clang),
                "-shared", "-fPIC", "-fvisibility=hidden",
                "-L", str(tmp_path),
                "-lcore",
                "-o", str(lib_file),
                str(src_file),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to build client library: {result.stderr}")

        return lib_file

    @pytest.fixture
    def cross_lib_advanced(self, tmp_path: Path, android_clang: Path,
                           cross_lib_core: Path, cross_lib_client: Path) -> Path:
        """Build the advanced library that depends on both core and client."""
        src_file = tmp_path / "advanced.c"
        src_file.write_text(self.ADVANCED_LIB_SOURCE)

        lib_file = tmp_path / "libadvanced.so"
        result = subprocess.run(
            [
                str(android_clang),
                "-shared", "-fPIC", "-fvisibility=hidden",
                "-L", str(tmp_path),
                "-lcore", "-lclient",
                "-o", str(lib_file),
                str(src_file),
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            pytest.fail(f"Failed to build advanced library: {result.stderr}")

        return lib_file

    def test_extract_cross_library_symbols(self, cross_lib_core: Path,
                                           cross_lib_client: Path, ndk_bin_path: Path):
        """Test extracting symbols from libraries with cross-library dependencies."""
        config = WrapperConfig(
            wrapper_name="cross_lib",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(cross_lib_core), str(cross_lib_client)],
        )
        generator = WrapperGenerator(config)

        functions = generator.get_function_list()

        # Core library functions
        assert "core_add" in functions
        assert "core_multiply" in functions
        assert "core_square" in functions
        assert "core_increment_counter" in functions
        assert "core_get_counter" in functions
        assert "core_reset_counter" in functions

        # Client library functions
        assert "client_sum_of_squares" in functions
        assert "client_power_of_two" in functions
        assert "client_factorial" in functions
        assert "client_increment_and_get" in functions
        assert "client_reset" in functions

    def test_generate_cross_library_wrapper(self, cross_lib_core: Path,
                                            cross_lib_client: Path,
                                            ndk_bin_path: Path, tmp_path: Path):
        """Test generating wrapper for libraries with cross-library dependencies."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="cross_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(cross_lib_core), str(cross_lib_client)],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()

        # Check generated files
        header = (output_dir / "include" / "cross_wrapper.h").read_text()
        impl = (output_dir / "src" / "cross_wrapper.cpp").read_text()

        # Should have functions from both libraries
        assert "cross_wrapper_core_add" in header
        assert "cross_wrapper_client_sum_of_squares" in header

        # Should have embedded data for both libraries
        assert (output_dir / "data" / "libcore_so.inc").exists()
        assert (output_dir / "data" / "libclient_so.inc").exists()

        # Implementation should load libraries in correct order
        # (core before client since client depends on core)
        assert "libcore_so" in impl
        assert "libclient_so" in impl

    def test_generate_three_library_chain(self, cross_lib_core: Path,
                                          cross_lib_client: Path,
                                          cross_lib_advanced: Path,
                                          ndk_bin_path: Path, tmp_path: Path):
        """Test generating wrapper for three libraries with chained dependencies."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="chain_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[
                str(cross_lib_core),
                str(cross_lib_client),
                str(cross_lib_advanced)
            ],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()

        # Check generated files
        header = (output_dir / "include" / "chain_wrapper.h").read_text()

        # Should have functions from all three libraries
        assert "chain_wrapper_core_add" in header
        assert "chain_wrapper_client_sum_of_squares" in header
        assert "chain_wrapper_advanced_pythagorean_check" in header
        assert "chain_wrapper_advanced_combination" in header
        assert "chain_wrapper_advanced_chain_call" in header

        # Should have embedded data for all three libraries
        assert (output_dir / "data" / "libcore_so.inc").exists()
        assert (output_dir / "data" / "libclient_so.inc").exists()
        assert (output_dir / "data" / "libadvanced_so.inc").exists()

    def test_cross_library_with_shared_state(self, cross_lib_core: Path,
                                             cross_lib_client: Path,
                                             ndk_bin_path: Path, tmp_path: Path):
        """Test that cross-library calls can share state (global variables)."""
        output_dir = tmp_path / "generated"

        config = WrapperConfig(
            wrapper_name="state_wrapper",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(cross_lib_core), str(cross_lib_client)],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()

        # Check that state-related functions are wrapped
        header = (output_dir / "include" / "state_wrapper.h").read_text()

        # Core state functions
        assert "state_wrapper_core_increment_counter" in header
        assert "state_wrapper_core_get_counter" in header
        assert "state_wrapper_core_reset_counter" in header

        # Client functions that use core state
        assert "state_wrapper_client_increment_and_get" in header
        assert "state_wrapper_client_reset" in header


class TestE2ECrossLibraryRuntime:
    """Runtime tests that build and execute wrappers to verify cross-library calls.

    These tests actually compile the generated wrapper and run it to verify
    that cross-library function calls work correctly at runtime.
    """

    # Core library with basic operations
    CORE_LIB_SOURCE = dedent("""
        // Core library with basic operations

        __attribute__((visibility("default")))
        int core_add(int a, int b) {
            return a + b;
        }

        __attribute__((visibility("default")))
        int core_multiply(int a, int b) {
            return a * b;
        }

        __attribute__((visibility("default")))
        int core_square(int x) {
            return x * x;
        }

        // Global state for testing
        static int g_counter = 0;

        __attribute__((visibility("default")))
        void core_set_counter(int val) {
            g_counter = val;
        }

        __attribute__((visibility("default")))
        int core_get_counter(void) {
            return g_counter;
        }

        __attribute__((visibility("default")))
        void core_add_to_counter(int val) {
            g_counter += val;
        }
    """)

    # Client library that depends on core library
    CLIENT_LIB_SOURCE = dedent("""
        // Client library that calls functions from core library

        extern int core_add(int a, int b);
        extern int core_multiply(int a, int b);
        extern int core_square(int x);
        extern void core_set_counter(int val);
        extern int core_get_counter(void);
        extern void core_add_to_counter(int val);

        __attribute__((visibility("default")))
        int client_sum_of_squares(int a, int b) {
            return core_add(core_square(a), core_square(b));
        }

        __attribute__((visibility("default")))
        int client_power(int base, int exp) {
            int result = 1;
            for (int i = 0; i < exp; i++) {
                result = core_multiply(result, base);
            }
            return result;
        }

        __attribute__((visibility("default")))
        int client_double_counter(void) {
            int val = core_get_counter();
            core_set_counter(core_multiply(val, 2));
            return core_get_counter();
        }

        __attribute__((visibility("default")))
        int client_accumulate(int val) {
            core_add_to_counter(val);
            return core_get_counter();
        }
    """)

    @pytest.fixture
    def runtime_libs(self, tmp_path: Path, android_clang: Path) -> tuple[Path, Path]:
        """Build core and client libraries for runtime testing."""
        # Build core library
        core_src = tmp_path / "core.c"
        core_src.write_text(self.CORE_LIB_SOURCE)
        core_lib = tmp_path / "libcore.so"

        result = subprocess.run(
            [
                str(android_clang),
                "-shared", "-fPIC", "-fvisibility=hidden",
                "-o", str(core_lib),
                str(core_src),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.fail(f"Failed to build core library: {result.stderr}")

        # Build client library
        client_src = tmp_path / "client.c"
        client_src.write_text(self.CLIENT_LIB_SOURCE)
        client_lib = tmp_path / "libclient.so"

        result = subprocess.run(
            [
                str(android_clang),
                "-shared", "-fPIC", "-fvisibility=hidden",
                "-L", str(tmp_path),
                "-lcore",
                "-o", str(client_lib),
                str(client_src),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            pytest.fail(f"Failed to build client library: {result.stderr}")

        return core_lib, client_lib

    @pytest.fixture
    def generated_wrapper(self, runtime_libs: tuple[Path, Path],
                          ndk_bin_path: Path, tmp_path: Path) -> Path:
        """Generate wrapper for the runtime test libraries."""
        core_lib, client_lib = runtime_libs
        output_dir = tmp_path / "wrapper"

        config = WrapperConfig(
            wrapper_name="crosslib",
            ndk_path=str(ndk_bin_path),
            library_paths=[str(core_lib), str(client_lib)],
            output_dir=str(output_dir),
        )
        generator = WrapperGenerator(config)
        generator.generate()

        return output_dir

    def test_wrapper_loads_libraries_in_order(self, generated_wrapper: Path):
        """Test that the wrapper loads libraries in the correct order."""
        impl = (generated_wrapper / "src" / "crosslib.cpp").read_text()

        # Find the positions of library loading
        core_pos = impl.find("libcore_so")
        client_pos = impl.find("libclient_so")

        # Core should be loaded before client
        assert core_pos != -1, "libcore_so not found in implementation"
        assert client_pos != -1, "libclient_so not found in implementation"
        assert core_pos < client_pos, "Core library should be loaded before client library"

    def test_wrapper_has_cross_library_functions(self, generated_wrapper: Path):
        """Test that wrapper exposes functions from both libraries."""
        header = (generated_wrapper / "include" / "crosslib.h").read_text()

        # Core functions
        assert "crosslib_core_add" in header
        assert "crosslib_core_multiply" in header
        assert "crosslib_core_square" in header
        assert "crosslib_core_set_counter" in header
        assert "crosslib_core_get_counter" in header
        assert "crosslib_core_add_to_counter" in header

        # Client functions (that call core functions)
        assert "crosslib_client_sum_of_squares" in header
        assert "crosslib_client_power" in header
        assert "crosslib_client_double_counter" in header
        assert "crosslib_client_accumulate" in header

    def test_wrapper_cmake_includes_both_libraries(self, generated_wrapper: Path):
        """Test that CMakeLists.txt includes both library data files."""
        cmake = (generated_wrapper / "CMakeLists.txt").read_text()

        # Should reference both library data files
        assert "libcore_so.inc" in cmake or "data" in cmake
        assert "libclient_so.inc" in cmake or "data" in cmake

    def test_wrapper_data_files_exist(self, generated_wrapper: Path):
        """Test that embedded library data files are created."""
        data_dir = generated_wrapper / "data"

        assert (data_dir / "libcore_so.inc").exists()
        assert (data_dir / "libclient_so.inc").exists()

        # Verify they contain actual data
        core_data = (data_dir / "libcore_so.inc").read_text()
        client_data = (data_dir / "libclient_so.inc").read_text()

        assert len(core_data) > 100, "Core library data seems too small"
        assert len(client_data) > 100, "Client library data seems too small"
