#!/bin/bash
# Run all wrapper generator tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create venv if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python -m venv .venv
fi

# Activate venv
source .venv/bin/activate

# Install package in dev mode if needed
if ! pip show android-wrapper-generator &>/dev/null; then
    echo "Installing package in development mode..."
    pip install -e ".[dev]"
fi

# Run tests
echo "Running tests..."
python -m pytest tests/ -v "$@"

