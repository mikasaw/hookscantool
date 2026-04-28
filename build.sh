#!/bin/bash
# Build script for hookscantool
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Detect compiler
if [ -n "$1" ] && [ "$1" = "msvc" ]; then
    echo "Using MSVC..."
    # MSVC build via cmake
    cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" -G "Visual Studio 17 2022" -A x64
    cmake --build "$BUILD_DIR" --config Release
else
    # MinGW GCC build
    GCC="${GCC:-gcc}"
    GXX="${GXX:-g++}"
    MAKE="${MAKE:-mingw32-make}"

    echo "Using GCC: $GCC"
    echo "Using G++: $GXX"

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    cmake -B "$BUILD_DIR" -S "$SCRIPT_DIR" \
        -G "MinGW Makefiles" \
        -DCMAKE_C_COMPILER="$GCC" \
        -DCMAKE_CXX_COMPILER="$GXX" \
        -DCMAKE_MAKE_PROGRAM="$MAKE" \
        -DCMAKE_BUILD_TYPE=Release

    cmake --build "$BUILD_DIR" -- -j$(nproc 2>/dev/null || echo 4)
fi

echo ""
echo "Build complete!"
echo "  CLI: $BUILD_DIR/hookscan_cli.exe"
echo "  GUI: $BUILD_DIR/hookscantool.exe"