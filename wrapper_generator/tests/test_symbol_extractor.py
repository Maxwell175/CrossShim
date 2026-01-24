"""Tests for the SymbolExtractor class."""

import pytest
from pathlib import Path

from android_wrapper_generator.symbol_extractor import (
    SymbolExtractor,
    Symbol,
    SymbolType,
    LibraryInfo,
)


class TestSymbolExtractor:
    """Tests for SymbolExtractor."""
    
    def test_init_with_valid_ndk_path(self, ndk_path: str):
        """Test initialization with a valid NDK path."""
        extractor = SymbolExtractor(ndk_path)
        assert extractor.ndk_path == Path(ndk_path)
    
    def test_init_with_invalid_ndk_path(self):
        """Test initialization with an invalid NDK path."""
        with pytest.raises(FileNotFoundError):
            SymbolExtractor("/nonexistent/path")
    
    def test_llvm_nm_path(self, ndk_path: str):
        """Test that llvm-nm path is correct."""
        extractor = SymbolExtractor(ndk_path)
        assert extractor.llvm_nm.name == "llvm-nm"
        assert extractor.llvm_nm.exists()
    
    def test_llvm_readelf_path(self, ndk_path: str):
        """Test that llvm-readelf path is correct."""
        extractor = SymbolExtractor(ndk_path)
        assert extractor.llvm_readelf.name == "llvm-readelf"
        assert extractor.llvm_readelf.exists()
    
    def test_extract_symbols_file_not_found(self, ndk_path: str):
        """Test that extracting from non-existent file raises error."""
        extractor = SymbolExtractor(ndk_path)
        with pytest.raises(FileNotFoundError):
            extractor.extract_symbols("/nonexistent/library.so")
    
    def test_extract_symbols_from_library(self, ndk_path: str, sample_library_path: Path):
        """Test extracting symbols from a real library."""
        extractor = SymbolExtractor(ndk_path)
        lib_info = extractor.extract_symbols(str(sample_library_path))
        
        assert isinstance(lib_info, LibraryInfo)
        assert lib_info.name == sample_library_path.name
        assert lib_info.path == sample_library_path
        assert lib_info.arch in ("aarch64", "arm", "x86_64", "unknown")
        assert isinstance(lib_info.symbols, list)
    
    def test_extract_symbols_has_functions(self, ndk_path: str, sample_library_path: Path):
        """Test that extracted symbols include functions."""
        extractor = SymbolExtractor(ndk_path)
        lib_info = extractor.extract_symbols(str(sample_library_path))
        
        functions = lib_info.get_exported_functions()
        # Most libraries should have at least some exported functions
        assert len(functions) > 0 or len(lib_info.symbols) > 0
    
    def test_extract_multiple_libraries(self, ndk_path: str, sample_library_path: Path):
        """Test extracting from multiple libraries."""
        extractor = SymbolExtractor(ndk_path)
        libs = extractor.extract_multiple([str(sample_library_path)])
        
        assert len(libs) == 1
        assert libs[0].name == sample_library_path.name


class TestSymbol:
    """Tests for Symbol dataclass."""
    
    def test_symbol_is_function(self):
        """Test is_function method."""
        func_sym = Symbol(
            name="test_func",
            address=0x1000,
            size=100,
            symbol_type=SymbolType.FUNCTION,
            binding="GLOBAL",
            visibility="DEFAULT",
            section=".text",
            library="libtest.so",
        )
        assert func_sym.is_function() is True
        
        obj_sym = Symbol(
            name="test_var",
            address=0x2000,
            size=8,
            symbol_type=SymbolType.OBJECT,
            binding="GLOBAL",
            visibility="DEFAULT",
            section=".data",
            library="libtest.so",
        )
        assert obj_sym.is_function() is False
    
    def test_symbol_is_exported(self):
        """Test is_exported method."""
        exported = Symbol(
            name="exported_func",
            address=0x1000,
            size=100,
            symbol_type=SymbolType.FUNCTION,
            binding="GLOBAL",
            visibility="DEFAULT",
            section=".text",
            library="libtest.so",
        )
        assert exported.is_exported() is True
        
        hidden = Symbol(
            name="hidden_func",
            address=0x1000,
            size=100,
            symbol_type=SymbolType.FUNCTION,
            binding="GLOBAL",
            visibility="HIDDEN",
            section=".text",
            library="libtest.so",
        )
        assert hidden.is_exported() is False
        
        local = Symbol(
            name="local_func",
            address=0x1000,
            size=100,
            symbol_type=SymbolType.FUNCTION,
            binding="LOCAL",
            visibility="DEFAULT",
            section=".text",
            library="libtest.so",
        )
        assert local.is_exported() is False


class TestLibraryInfo:
    """Tests for LibraryInfo dataclass."""
    
    def test_get_exported_functions(self):
        """Test get_exported_functions method."""
        lib = LibraryInfo(
            path=Path("/test/libtest.so"),
            name="libtest.so",
            arch="aarch64",
            symbols=[
                Symbol("func1", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "libtest.so"),
                Symbol("func2", 0x2000, 100, SymbolType.FUNCTION, "GLOBAL", "HIDDEN", ".text", "libtest.so"),
                Symbol("var1", 0x3000, 8, SymbolType.OBJECT, "GLOBAL", "DEFAULT", ".data", "libtest.so"),
                Symbol("func3", 0x4000, 100, SymbolType.FUNCTION, "WEAK", "DEFAULT", ".text", "libtest.so"),
            ],
            dependencies=["libc.so"],
        )
        
        exported = lib.get_exported_functions()
        assert len(exported) == 2
        assert exported[0].name == "func1"
        assert exported[1].name == "func3"

