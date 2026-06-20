"""
Symbol Extractor - Uses Android NDK tools to extract symbols from shared libraries.
"""

import subprocess
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any


class SymbolType(Enum):
    """Type of symbol extracted from the library."""
    FUNCTION = "function"
    OBJECT = "object"
    UNKNOWN = "unknown"


@dataclass
class Symbol:
    """Represents an exported symbol from a shared library."""
    name: str
    address: int
    size: int
    symbol_type: SymbolType
    binding: str  # GLOBAL, WEAK, LOCAL
    visibility: str  # DEFAULT, HIDDEN, PROTECTED
    section: str  # .text, .data, .bss, etc.
    library: str  # Source library name
    
    def is_function(self) -> bool:
        """Check if this symbol is a function."""
        return self.symbol_type == SymbolType.FUNCTION
    
    def is_exported(self) -> bool:
        """Check if this symbol is exported (visible externally)."""
        return self.binding in ("GLOBAL", "WEAK") and self.visibility == "DEFAULT"


@dataclass
class LibraryInfo:
    """Information about a shared library."""
    path: Path
    name: str
    arch: str
    symbols: List[Symbol] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    def get_exported_functions(self) -> List[Symbol]:
        """Get all exported function symbols."""
        return [s for s in self.symbols if s.is_function() and s.is_exported()]


class SymbolExtractor:
    """
    Extracts symbols from Android ARM64 shared libraries using NDK tools.
    
    Uses llvm-nm and llvm-readelf from the Android NDK to parse ELF files
    and extract symbol information.
    """
    
    def __init__(self, ndk_path: Optional[str] = None):
        """
        Initialize the symbol extractor.
        
        Args:
            ndk_path: Path to the Android NDK toolchain bin directory.
                      If None, will try to find it from environment.
        """
        self._explicit_ndk_path = ndk_path is not None
        self.ndk_path = Path(ndk_path) if ndk_path else self._find_ndk_path()
        self._validate_ndk_tools()
    
    def _find_ndk_path(self) -> Path:
        """Try to find the NDK toolchain path from environment."""
        import os
        
        # Check common environment variables
        for var in ["ANDROID_NDK_HOME", "ANDROID_NDK", "NDK_HOME"]:
            if var in os.environ:
                ndk_root = Path(os.environ[var])
                toolchain = ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
                if toolchain.exists():
                    return toolchain
        
        raise ValueError(
            "Could not find Android NDK. Please set ANDROID_NDK_HOME or "
            "provide ndk_path parameter."
        )
    
    def _validate_ndk_tools(self) -> None:
        """Validate that required NDK tools exist."""
        import shutil

        required_tools = ["llvm-nm", "llvm-readelf"]
        self._tool_paths = {}

        for tool in required_tools:
            tool_path = self.ndk_path / tool
            if tool_path.exists():
                self._tool_paths[tool] = tool_path
            else:
                if self._explicit_ndk_path:
                    raise FileNotFoundError(
                        f"Required tool not found: {tool_path}"
                    )
                # Try to find system tool
                system_tool = shutil.which(tool)
                if system_tool:
                    self._tool_paths[tool] = Path(system_tool)
                else:
                    raise FileNotFoundError(
                        f"Required tool not found: {tool} (not in NDK path {tool_path} or system PATH)"
                    )

    @property
    def llvm_nm(self) -> Path:
        """Path to llvm-nm tool."""
        return self._tool_paths.get("llvm-nm", self.ndk_path / "llvm-nm")

    @property
    def llvm_readelf(self) -> Path:
        """Path to llvm-readelf tool."""
        return self._tool_paths.get("llvm-readelf", self.ndk_path / "llvm-readelf")
    
    def extract_symbols(self, library_path: str) -> LibraryInfo:
        """
        Extract all symbols from a shared library.
        
        Args:
            library_path: Path to the .so file
            
        Returns:
            LibraryInfo containing all extracted symbols
        """
        lib_path = Path(library_path)
        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {library_path}")
        
        # Get library architecture
        arch = self._get_architecture(lib_path)
        
        # Get dependencies
        deps = self._get_dependencies(lib_path)
        
        # Extract symbols using llvm-nm
        symbols = self._extract_symbols_nm(lib_path)
        
        # Enhance with readelf info
        self._enhance_symbols_readelf(lib_path, symbols)
        
        return LibraryInfo(
            path=lib_path,
            name=lib_path.name,
            arch=arch,
            symbols=symbols,
            dependencies=deps,
        )
    
    def _get_architecture(self, lib_path: Path) -> str:
        """Get the architecture of the library."""
        result = subprocess.run(
            [str(self.llvm_readelf), "-h", str(lib_path)],
            capture_output=True,
            text=True,
        )
        
        if "AArch64" in result.stdout or "aarch64" in result.stdout.lower():
            return "aarch64"
        elif "ARM" in result.stdout:
            return "arm"
        elif "X86-64" in result.stdout or "x86_64" in result.stdout.lower():
            return "x86_64"
        else:
            return "unknown"
    
    def _get_dependencies(self, lib_path: Path) -> List[str]:
        """Get the list of library dependencies."""
        result = subprocess.run(
            [str(self.llvm_readelf), "-d", str(lib_path)],
            capture_output=True,
            text=True,
        )
        
        deps = []
        for line in result.stdout.splitlines():
            if "NEEDED" in line:
                # Extract library name from line like: 0x0000000000000001 (NEEDED) Shared library: [libc.so]
                match = re.search(r'\[([^\]]+)\]', line)
                if match:
                    deps.append(match.group(1))
        
        return deps

    def _extract_symbols_nm(self, lib_path: Path) -> List[Symbol]:
        """Extract symbols using llvm-nm."""
        # Use --defined-only to get only defined symbols, --dynamic for dynamic symbols
        result = subprocess.run(
            [str(self.llvm_nm), "--defined-only", "--dynamic", "-S", str(lib_path)],
            capture_output=True,
            text=True,
        )

        symbols = []
        lib_name = lib_path.name

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue

            # Format: address [size] type name
            # Example: 0000000000001234 0000000000000010 T my_function
            try:
                if len(parts) == 4:
                    addr_str, size_str, sym_type, name = parts
                    address = int(addr_str, 16)
                    size = int(size_str, 16)
                elif len(parts) == 3:
                    addr_str, sym_type, name = parts
                    address = int(addr_str, 16)
                    size = 0
                else:
                    continue

                # Determine symbol type from nm output
                symbol_type = self._nm_type_to_symbol_type(sym_type)
                binding = "GLOBAL" if sym_type.isupper() else "LOCAL"

                symbols.append(Symbol(
                    name=name,
                    address=address,
                    size=size,
                    symbol_type=symbol_type,
                    binding=binding,
                    visibility="DEFAULT",
                    section=self._nm_type_to_section(sym_type),
                    library=lib_name,
                ))
            except (ValueError, IndexError):
                continue

        return symbols

    def _nm_type_to_symbol_type(self, nm_type: str) -> SymbolType:
        """Convert nm symbol type to SymbolType enum."""
        nm_type = nm_type.upper()
        if nm_type in ("T", "W"):  # Text (code) section
            return SymbolType.FUNCTION
        elif nm_type in ("D", "B", "R", "G"):  # Data, BSS, Read-only, Small data
            return SymbolType.OBJECT
        else:
            return SymbolType.UNKNOWN

    def _nm_type_to_section(self, nm_type: str) -> str:
        """Convert nm symbol type to section name."""
        nm_type = nm_type.upper()
        section_map = {
            "T": ".text",
            "D": ".data",
            "B": ".bss",
            "R": ".rodata",
            "W": ".text",  # Weak symbol in text
            "G": ".sdata",  # Small data
        }
        return section_map.get(nm_type, "unknown")

    def _enhance_symbols_readelf(self, lib_path: Path, symbols: List[Symbol]) -> None:
        """Enhance symbol information using llvm-readelf."""
        result = subprocess.run(
            [str(self.llvm_readelf), "--dyn-syms", "--wide", str(lib_path)],
            capture_output=True,
            text=True,
        )

        # Build a map of symbol names to their readelf info
        readelf_info: Dict[str, Dict[str, Any]] = {}

        for line in result.stdout.splitlines():
            # Format: Num: Value Size Type Bind Vis Ndx Name
            # Example: 1: 0000000000001234 16 FUNC GLOBAL DEFAULT 12 my_function
            parts = line.split()
            if len(parts) >= 8:
                try:
                    name = parts[7] if len(parts) > 7 else parts[-1]
                    # Remove version info like @LIBC
                    if "@" in name:
                        name = name.split("@")[0]

                    readelf_info[name] = {
                        "type": parts[3],
                        "binding": parts[4],
                        "visibility": parts[5],
                    }
                except (IndexError, ValueError):
                    continue

        # Update symbols with readelf info
        for sym in symbols:
            if sym.name in readelf_info:
                info = readelf_info[sym.name]
                if info["type"] == "FUNC":
                    sym.symbol_type = SymbolType.FUNCTION
                elif info["type"] == "OBJECT":
                    sym.symbol_type = SymbolType.OBJECT
                sym.binding = info["binding"]
                sym.visibility = info["visibility"]

    def extract_multiple(self, library_paths: List[str]) -> List[LibraryInfo]:
        """
        Extract symbols from multiple libraries.

        Args:
            library_paths: List of paths to .so files

        Returns:
            List of LibraryInfo for each library
        """
        return [self.extract_symbols(path) for path in library_paths]
