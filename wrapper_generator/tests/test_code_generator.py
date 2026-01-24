"""Tests for the CodeGenerator class."""

import pytest
from pathlib import Path

from android_wrapper_generator.code_generator import CodeGenerator, FunctionInfo
from android_wrapper_generator.symbol_extractor import Symbol, SymbolType, LibraryInfo


class TestFunctionInfo:
    """Tests for FunctionInfo class."""
    
    def test_basic_function_info(self):
        """Test basic FunctionInfo creation."""
        sym = Symbol(
            name="test_func",
            address=0x1000,
            size=100,
            symbol_type=SymbolType.FUNCTION,
            binding="GLOBAL",
            visibility="DEFAULT",
            section=".text",
            library="libtest.so",
        )
        func = FunctionInfo(sym, param_count=2)
        
        assert func.name == "test_func"
        assert func.library == "libtest.so"
        assert func.param_count == 2
        assert func.return_type == "uint64_t"
    
    def test_param_list_with_types_empty(self):
        """Test param_list_with_types with no parameters."""
        sym = Symbol("func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so")
        func = FunctionInfo(sym, param_count=0)
        
        assert func.param_list_with_types == ""
    
    def test_param_list_with_types(self):
        """Test param_list_with_types with parameters."""
        sym = Symbol("func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so")
        func = FunctionInfo(sym, param_count=2)
        
        assert func.param_list_with_types == ", uint64_t arg0, uint64_t arg1"
    
    def test_arg_list(self):
        """Test arg_list generation."""
        sym = Symbol("func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so")
        func = FunctionInfo(sym, param_count=2)
        
        assert func.arg_list == "(uint64_t)arg0, (uint64_t)arg1"
    
    def test_default_return_values(self):
        """Test default return values for different types."""
        sym = Symbol("func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so")
        
        func = FunctionInfo(sym)
        func.return_type = "int"
        assert func.default_return == "-1"
        
        func.return_type = "uint64_t"
        assert func.default_return == "0"
        
        func.return_type = "void*"
        assert func.default_return == "nullptr"
        
        func.return_type = "void"
        assert func.default_return == ""
    
    def test_return_cast(self):
        """Test return cast generation."""
        sym = Symbol("func", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "lib.so")
        
        func = FunctionInfo(sym)
        func.return_type = "uint64_t"
        assert func.return_cast == ""
        
        func.return_type = "int"
        assert func.return_cast == "(int)"


class TestCodeGenerator:
    """Tests for CodeGenerator class."""
    
    def test_init(self):
        """Test CodeGenerator initialization."""
        gen = CodeGenerator("test_wrapper")
        assert gen.wrapper_name == "test_wrapper"
        assert gen.libraries == []
        assert gen.functions == []
    
    def test_add_library(self):
        """Test adding a library."""
        gen = CodeGenerator("test_wrapper")
        
        lib = LibraryInfo(
            path=Path("/test/libtest.so"),
            name="libtest.so",
            arch="aarch64",
            symbols=[
                Symbol("func1", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "libtest.so"),
                Symbol("func2", 0x2000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "libtest.so"),
            ],
            dependencies=[],
        )
        
        gen.add_library(lib)
        
        assert len(gen.libraries) == 1
        assert len(gen.functions) == 2
    
    def test_set_type_hints(self):
        """Test setting type hints."""
        gen = CodeGenerator("test_wrapper")
        
        hints = {
            "func1": {"return_type": "int", "param_types": ["int", "char*"]},
        }
        gen.set_type_hints(hints)
        
        assert gen.type_hints == hints
    
    def test_generate_creates_files(self, temp_output_dir: Path):
        """Test that generate creates expected files."""
        gen = CodeGenerator("test_wrapper")
        
        # Create a mock library (we'll skip the data generation for this test)
        lib = LibraryInfo(
            path=Path(__file__),  # Use this test file as a dummy
            name="libtest.so",
            arch="aarch64",
            symbols=[
                Symbol("func1", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "libtest.so"),
            ],
            dependencies=[],
        )
        gen.add_library(lib)
        
        gen.generate(str(temp_output_dir))
        
        # Check that expected files were created
        assert (temp_output_dir / "include" / "test_wrapper.h").exists()
        assert (temp_output_dir / "src" / "test_wrapper.cpp").exists()
        assert (temp_output_dir / "CMakeLists.txt").exists()
        assert (temp_output_dir / "data").exists()
    
    def test_generated_header_content(self, temp_output_dir: Path):
        """Test that generated header has expected content."""
        gen = CodeGenerator("my_wrapper")
        
        lib = LibraryInfo(
            path=Path(__file__),
            name="libtest.so",
            arch="aarch64",
            symbols=[
                Symbol("test_function", 0x1000, 100, SymbolType.FUNCTION, "GLOBAL", "DEFAULT", ".text", "libtest.so"),
            ],
            dependencies=[],
        )
        gen.add_library(lib)
        gen.generate(str(temp_output_dir))
        
        header_content = (temp_output_dir / "include" / "my_wrapper.h").read_text()
        
        assert "my_wrapperHandle" in header_content
        assert "my_wrapper_Create" in header_content
        assert "my_wrapper_Destroy" in header_content
        assert "my_wrapper_Load" in header_content
        assert "my_wrapper_test_function" in header_content

