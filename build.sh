#!/bin/bash
# Build script for hookscantool
# Usage: ./build.sh [msvc|mingw] [build-dir]
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLCHAIN="${1:-mingw}"
BUILD_DIR="${2:-$SCRIPT_DIR/build-$TOOLCHAIN}"

# Detect compiler
if [ "$TOOLCHAIN" = "msvc" ]; then
    echo "Using MSVC..."
    # Generator name: "Visual Studio 17 2022" or "Visual Studio 18 2026" (Insiders)
    VS_GEN="${VS_GEN:-Visual Studio 17 2022}"
    cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" -G "$VS_GEN" -A x64
    cmake --build "$BUILD_DIR" --config Release
else
    # MinGW GCC build
    GCC="${GCC:-gcc}"
    GXX="${GXX:-g++}"
    MAKE="${MAKE:-mingw32-make}"

    echo "Using GCC: $GCC"
    echo "Using G++: $GXX"

    # Configure only if needed, so rebuilds are incremental
    if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
        cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" \
            -G "MinGW Makefiles" \
            -DCMAKE_C_COMPILER="$GCC" \
            -DCMAKE_CXX_COMPILER="$GXX" \
            -DCMAKE_MAKE_PROGRAM="$MAKE" \
            -DCMAKE_BUILD_TYPE=Release
    fi

    cmake --build "$BUILD_DIR" -- -j$(nproc 2>/dev/null || echo 4)
fi

echo ""
echo "Build complete!"
echo "  CLI: $BUILD_DIR/hookscan_cli.exe"
echo "  GUI: $BUILD_DIR/hookscantool.exe"
