"""
Command-line interface for the Android Wrapper Generator.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .wrapper_generator import WrapperGenerator, WrapperConfig


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="android-wrapper-gen",
        description="Generate host shared library wrappers for Android ARM64 shared libraries.",
    )
    
    parser.add_argument(
        "libraries",
        nargs="+",
        help="Path(s) to Android ARM64 shared library (.so) files to wrap",
    )
    
    parser.add_argument(
        "-n", "--name",
        required=True,
        help="Name for the generated wrapper (e.g., 'my_wrapper')",
    )
    
    parser.add_argument(
        "-o", "--output",
        default="./generated",
        help="Output directory for generated files (default: ./generated)",
    )
    
    parser.add_argument(
        "--ndk-path",
        required=True,
        help="Path to Android NDK toolchain bin directory",
    )
    
    parser.add_argument(
        "--type-hints",
        help="Path to JSON file with type hints for functions",
    )
    
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Function names to exclude from wrapping",
    )
    
    parser.add_argument(
        "--include",
        nargs="*",
        help="Only wrap these function names (if specified)",
    )
    
    parser.add_argument(
        "--list-functions",
        action="store_true",
        help="List all exported functions and exit",
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary of libraries and exit",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    return parser.parse_args(args)


def load_type_hints(path: str) -> dict:
    """Load type hints from a JSON file."""
    with open(path) as f:
        return json.load(f)


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    parsed = parse_args(args)
    
    # Validate library paths
    for lib_path in parsed.libraries:
        if not Path(lib_path).exists():
            print(f"Error: Library not found: {lib_path}", file=sys.stderr)
            return 1
    
    # Load type hints if provided
    type_hints = {}
    if parsed.type_hints:
        try:
            type_hints = load_type_hints(parsed.type_hints)
        except Exception as e:
            print(f"Error loading type hints: {e}", file=sys.stderr)
            return 1
    
    # Create configuration
    config = WrapperConfig(
        wrapper_name=parsed.name,
        ndk_path=parsed.ndk_path,
        library_paths=parsed.libraries,
        output_dir=parsed.output,
        type_hints=type_hints,
        exclude_functions=parsed.exclude or [],
        include_functions=parsed.include,
    )
    
    # Create generator
    try:
        generator = WrapperGenerator(config)
    except Exception as e:
        print(f"Error initializing generator: {e}", file=sys.stderr)
        return 1
    
    # Handle list-functions mode
    if parsed.list_functions:
        functions = generator.get_function_list()
        for func in functions:
            print(func)
        return 0
    
    # Handle summary mode
    if parsed.summary:
        generator.print_summary()
        return 0
    
    # Generate wrapper
    try:
        if parsed.verbose:
            print(f"Generating wrapper '{parsed.name}'...")
            print(f"Libraries: {', '.join(parsed.libraries)}")
            print(f"Output: {parsed.output}")
        
        generator.generate()
        
        if parsed.verbose:
            print("Generation complete!")
        
        return 0
        
    except Exception as e:
        print(f"Error generating wrapper: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

