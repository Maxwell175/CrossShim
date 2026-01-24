"""Tests for the WrapperGenerator class."""

import pytest
from pathlib import Path

from android_wrapper_generator.wrapper_generator import WrapperGenerator, WrapperConfig
from android_wrapper_generator.symbol_extractor import Symbol, SymbolType, LibraryInfo


class TestWrapperConfig:
    """Tests for WrapperConfig dataclass."""
    
    def test_default_values(self):
        """Test default configuration values."""
        config = WrapperConfig(
            wrapper_name="test",
            ndk_path="/path/to/ndk",
        )
        
        assert config.wrapper_name == "test"
        assert config.ndk_path == "/path/to/ndk"
        assert config.library_paths == []
        assert config.output_dir == "./generated"
        assert config.type_hints == {}
        assert config.exclude_functions == []
        assert config.include_functions is None
        assert config.embed_libraries is True
    
    def test_custom_values(self):
        """Test custom configuration values."""
        config = WrapperConfig(
            wrapper_name="my_wrapper",
            ndk_path="/custom/ndk",
            library_paths=["lib1.so", "lib2.so"],
            output_dir="/custom/output",
            type_hints={"func": {"return_type": "int"}},
            exclude_functions=["excluded_func"],
            include_functions=["included_func"],
            embed_libraries=False,
        )
        
        assert config.wrapper_name == "my_wrapper"
        assert len(config.library_paths) == 2
        assert config.output_dir == "/custom/output"
        assert "func" in config.type_hints
        assert "excluded_func" in config.exclude_functions
        assert "included_func" in config.include_functions
        assert config.embed_libraries is False


class TestWrapperGenerator:
    """Tests for WrapperGenerator class."""
    
    def test_init(self, ndk_path: str):
        """Test WrapperGenerator initialization."""
        config = WrapperConfig(
            wrapper_name="test",
            ndk_path=ndk_path,
        )
        generator = WrapperGenerator(config)
        
        assert generator.config == config
        assert generator.libraries == []
    
    def test_extract_symbols(self, ndk_path: str, sample_library_path: Path):
        """Test symbol extraction."""
        config = WrapperConfig(
            wrapper_name="test",
            ndk_path=ndk_path,
            library_paths=[str(sample_library_path)],
        )
        generator = WrapperGenerator(config)
        
        libs = generator.extract_symbols()
        
        assert len(libs) == 1
        assert libs[0].name == sample_library_path.name
    
    def test_filter_functions_exclude(self, ndk_path: str):
        """Test function filtering with exclude list."""
        config = WrapperConfig(
            wrapper_name="test",
            ndk_path=ndk_path,
            exclude_functions=["excluded_func"],
        )
        generator = WrapperGenerator(config)
        
        lib = LibraryInfo(
            path=Path("/test/lib.so"),
            name="lib.so",
            arch="aarch64",
            symbols=[
                Symbol("keep_func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so"),
                Symbol("excluded_func", 0x2000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so"),
            ],
            dependencies=[],
        )
        
        filtered = generator.filter_functions(lib)
        func_names = [s.name for s in filtered.symbols if s.is_function()]
        
        assert "keep_func" in func_names
        assert "excluded_func" not in func_names
    
    def test_filter_functions_include(self, ndk_path: str):
        """Test function filtering with include list."""
        config = WrapperConfig(
            wrapper_name="test",
            ndk_path=ndk_path,
            include_functions=["included_func"],
        )
        generator = WrapperGenerator(config)
        
        lib = LibraryInfo(
            path=Path("/test/lib.so"),
            name="lib.so",
            arch="aarch64",
            symbols=[
                Symbol("included_func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so"),
                Symbol("other_func", 0x2000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so"),
            ],
            dependencies=[],
        )
        
        filtered = generator.filter_functions(lib)
        func_names = [s.name for s in filtered.symbols if s.is_function()]
        
        assert "included_func" in func_names
        assert "other_func" not in func_names
    
    def test_get_function_list(self, ndk_path: str, sample_library_path: Path):
        """Test getting function list."""
        config = WrapperConfig(
            wrapper_name="test",
            ndk_path=ndk_path,
            library_paths=[str(sample_library_path)],
        )
        generator = WrapperGenerator(config)
        
        functions = generator.get_function_list()
        
        assert isinstance(functions, list)
        # Functions should be sorted and unique
        assert functions == sorted(set(functions))
    
    def test_generate(self, ndk_path: str, sample_library_path: Path, temp_output_dir: Path):
        """Test full wrapper generation."""
        config = WrapperConfig(
            wrapper_name="test_wrapper",
            ndk_path=ndk_path,
            library_paths=[str(sample_library_path)],
            output_dir=str(temp_output_dir),
        )
        generator = WrapperGenerator(config)
        
        generator.generate()
        
        # Check that files were created
        assert (temp_output_dir / "include" / "test_wrapper.h").exists()
        assert (temp_output_dir / "src" / "test_wrapper.cpp").exists()
        assert (temp_output_dir / "CMakeLists.txt").exists()

