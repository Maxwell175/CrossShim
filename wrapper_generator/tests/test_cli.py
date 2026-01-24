"""Tests for the CLI module."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from android_wrapper_generator.cli import parse_args, main


class TestParseArgs:
    """Tests for argument parsing."""
    
    def test_required_arguments(self):
        """Test that required arguments are enforced."""
        # Missing --name
        with pytest.raises(SystemExit):
            parse_args(["lib.so", "--ndk-path", "/path/to/ndk"])
        
        # Missing --ndk-path
        with pytest.raises(SystemExit):
            parse_args(["lib.so", "--name", "test"])
        
        # Missing library
        with pytest.raises(SystemExit):
            parse_args(["--name", "test", "--ndk-path", "/path/to/ndk"])
    
    def test_basic_arguments(self):
        """Test basic argument parsing."""
        args = parse_args([
            "lib1.so", "lib2.so",
            "--name", "my_wrapper",
            "--ndk-path", "/path/to/ndk",
        ])
        
        assert args.libraries == ["lib1.so", "lib2.so"]
        assert args.name == "my_wrapper"
        assert args.ndk_path == "/path/to/ndk"
        assert args.output == "./generated"  # default
    
    def test_optional_arguments(self):
        """Test optional argument parsing."""
        args = parse_args([
            "lib.so",
            "--name", "test",
            "--ndk-path", "/ndk",
            "--output", "/custom/output",
            "--exclude", "func1", "func2",
            "--include", "func3",
            "--verbose",
        ])
        
        assert args.output == "/custom/output"
        assert args.exclude == ["func1", "func2"]
        assert args.include == ["func3"]
        assert args.verbose is True
    
    def test_list_functions_flag(self):
        """Test --list-functions flag."""
        args = parse_args([
            "lib.so",
            "--name", "test",
            "--ndk-path", "/ndk",
            "--list-functions",
        ])
        
        assert args.list_functions is True
    
    def test_summary_flag(self):
        """Test --summary flag."""
        args = parse_args([
            "lib.so",
            "--name", "test",
            "--ndk-path", "/ndk",
            "--summary",
        ])
        
        assert args.summary is True


class TestMain:
    """Tests for main function."""
    
    def test_library_not_found(self, ndk_path: str):
        """Test error when library doesn't exist."""
        result = main([
            "/nonexistent/lib.so",
            "--name", "test",
            "--ndk-path", ndk_path,
        ])
        
        assert result == 1
    
    def test_list_functions(self, ndk_path: str, sample_library_path: Path, capsys):
        """Test --list-functions mode."""
        result = main([
            str(sample_library_path),
            "--name", "test",
            "--ndk-path", ndk_path,
            "--list-functions",
        ])
        
        assert result == 0
        captured = capsys.readouterr()
        # Should have printed some function names
        assert len(captured.out) > 0
    
    def test_summary(self, ndk_path: str, sample_library_path: Path, capsys):
        """Test --summary mode."""
        result = main([
            str(sample_library_path),
            "--name", "test",
            "--ndk-path", ndk_path,
            "--summary",
        ])
        
        assert result == 0
        captured = capsys.readouterr()
        assert "Wrapper: test" in captured.out
        assert "Library:" in captured.out
    
    def test_generate(self, ndk_path: str, sample_library_path: Path, temp_output_dir: Path):
        """Test full generation."""
        result = main([
            str(sample_library_path),
            "--name", "test_wrapper",
            "--ndk-path", ndk_path,
            "--output", str(temp_output_dir),
        ])
        
        assert result == 0
        assert (temp_output_dir / "include" / "test_wrapper.h").exists()
    
    def test_verbose_output(self, ndk_path: str, sample_library_path: Path, temp_output_dir: Path, capsys):
        """Test verbose output."""
        result = main([
            str(sample_library_path),
            "--name", "test",
            "--ndk-path", ndk_path,
            "--output", str(temp_output_dir),
            "--verbose",
        ])
        
        assert result == 0
        captured = capsys.readouterr()
        assert "Generating wrapper" in captured.out
        assert "Generation complete" in captured.out

