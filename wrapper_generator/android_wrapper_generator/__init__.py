"""
Android Wrapper Generator

A Python library that uses Android NDK utilities to examine exported symbols
of Android ARM64 shared libraries and generate host shared library wrappers
that embed the libraries and use an emulator to call the wrapped functions.
"""

from .symbol_extractor import SymbolExtractor, Symbol, SymbolType
from .wrapper_generator import WrapperGenerator, WrapperConfig
from .code_generator import CodeGenerator

__version__ = "1.0.0"
__all__ = [
    "SymbolExtractor",
    "Symbol",
    "SymbolType",
    "WrapperGenerator",
    "WrapperConfig",
    "CodeGenerator",
]

