#!/bin/bash
#
# Download bionic test sources and googletest
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Bionic Test Suite Setup ==="
echo ""

# Download googletest if not present
if [ ! -d "googletest" ]; then
    echo "Downloading googletest..."
    git clone --depth 1 --branch v1.14.0 https://github.com/google/googletest.git googletest
    echo "  Done."
else
    echo "googletest already present."
fi

# Download bionic tests if not present
if [ ! -d "tests" ]; then
    echo "Downloading bionic tests..."
    mkdir -p tests

    # Use sparse checkout to get only the tests directory
    # Locked to ndk-r29-release branch to match NDK version
    git clone --depth 1 --branch ndk-r29-release --filter=blob:none --sparse \
        https://github.com/aosp-mirror/platform_bionic.git bionic_repo

    cd bionic_repo
    git sparse-checkout set tests
    cd ..

    # Copy test files
    cp -r bionic_repo/tests/* tests/
    rm -rf bionic_repo

    # Rename bionic utils.h so our shim is used instead
    if [ -f "tests/utils.h" ]; then
        mv tests/utils.h tests/utils_bionic_original.h
        echo "  Renamed tests/utils.h -> tests/utils_bionic_original.h"
    fi

    # Same for SignalUtils.h
    if [ -f "tests/SignalUtils.h" ]; then
        mv tests/SignalUtils.h tests/SignalUtils_bionic_original.h
        echo "  Renamed tests/SignalUtils.h -> tests/SignalUtils_bionic_original.h"
    fi

    echo "  Done."
else
    echo "bionic tests already present."
fi

# Create shim directory
mkdir -p shim

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Run ./build.sh to build tests"
echo "  2. Run ./run.sh to execute tests through CrossShim"
