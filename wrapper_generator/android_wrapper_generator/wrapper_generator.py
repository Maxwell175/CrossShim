"""
Wrapper Generator - Main class for generating Android library wrappers.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict

from .symbol_extractor import SymbolExtractor, LibraryInfo
from .code_generator import CodeGenerator


@dataclass
class WrapperConfig:
    """Configuration for wrapper generation."""
    
    # Name of the generated wrapper
    wrapper_name: str
    
    # Path to Android NDK toolchain bin directory
    ndk_path: str
    
    # List of library paths to wrap
    library_paths: List[str] = field(default_factory=list)
    
    # Output directory for generated files
    output_dir: str = "./generated"
    
    # Type hints for functions: {"func_name": {"return_type": "int", "param_types": ["int", "char*"]}}
    type_hints: Dict[str, Dict[str, str]] = field(default_factory=dict)
    
    # Functions to exclude from wrapping
    exclude_functions: List[str] = field(default_factory=list)
    
    # Functions to include (if set, only these are wrapped)
    include_functions: Optional[List[str]] = None
    
    # Whether to generate embedded library data
    embed_libraries: bool = True


class WrapperGenerator:
    """
    Main class for generating Android library wrappers.
    
    This class orchestrates the entire wrapper generation process:
    1. Extract symbols from input libraries using NDK tools
    2. Filter and process symbols based on configuration
    3. Generate C++ wrapper code
    4. Generate CMakeLists.txt for building
    
    Usage:
        config = WrapperConfig(
            wrapper_name="my_wrapper",
            ndk_path="/path/to/ndk/toolchain/bin",
            library_paths=["libfoo.so", "libbar.so"],
            output_dir="./output",
        )
        generator = WrapperGenerator(config)
        generator.generate()
    """
    
    def __init__(self, config: WrapperConfig):
        """
        Initialize the wrapper generator.
        
        Args:
            config: Configuration for wrapper generation
        """
        self.config = config
        self.extractor = SymbolExtractor(config.ndk_path)
        self.code_gen = CodeGenerator(config.wrapper_name)
        self.libraries: List[LibraryInfo] = []
    
    def extract_symbols(self) -> List[LibraryInfo]:
        """
        Extract symbols from all configured libraries.
        
        Returns:
            List of LibraryInfo for each library
        """
        self.libraries = self.extractor.extract_multiple(self.config.library_paths)
        return self.libraries
    
    def filter_functions(self, lib_info: LibraryInfo) -> LibraryInfo:
        """
        Filter functions based on include/exclude configuration.
        
        Args:
            lib_info: Library information to filter
            
        Returns:
            Filtered LibraryInfo
        """
        filtered_symbols = []
        
        for sym in lib_info.symbols:
            # Skip non-functions
            if not sym.is_function():
                filtered_symbols.append(sym)
                continue
            
            # Check exclude list
            if sym.name in self.config.exclude_functions:
                continue
            
            # Check include list (if specified)
            if self.config.include_functions is not None:
                if sym.name not in self.config.include_functions:
                    continue
            
            filtered_symbols.append(sym)
        
        lib_info.symbols = filtered_symbols
        return lib_info
    
    def generate(self) -> None:
        """
        Generate the complete wrapper.
        
        This is the main entry point that:
        1. Extracts symbols from libraries
        2. Filters functions
        3. Generates wrapper code
        """
        # Extract symbols
        if not self.libraries:
            self.extract_symbols()
        
        # Set type hints
        self.code_gen.set_type_hints(self.config.type_hints)
        
        # Add libraries (with filtering)
        for lib in self.libraries:
            filtered_lib = self.filter_functions(lib)
            self.code_gen.add_library(filtered_lib)
        
        # Generate code
        self.code_gen.generate(self.config.output_dir)
    
    def get_function_list(self) -> List[str]:
        """
        Get list of all exported function names.
        
        Returns:
            List of function names
        """
        if not self.libraries:
            self.extract_symbols()
        
        functions = []
        for lib in self.libraries:
            for sym in lib.get_exported_functions():
                functions.append(sym.name)
        
        return sorted(set(functions))
    
    def print_summary(self) -> None:
        """Print a summary of extracted libraries and symbols."""
        if not self.libraries:
            self.extract_symbols()
        
        print(f"Wrapper: {self.config.wrapper_name}")
        print(f"Output: {self.config.output_dir}")
        print()
        
        total_functions = 0
        for lib in self.libraries:
            funcs = lib.get_exported_functions()
            total_functions += len(funcs)
            print(f"Library: {lib.name}")
            print(f"  Architecture: {lib.arch}")
            print(f"  Dependencies: {', '.join(lib.dependencies) or 'none'}")
            print(f"  Exported functions: {len(funcs)}")
            print()
        
        print(f"Total functions to wrap: {total_functions}")

