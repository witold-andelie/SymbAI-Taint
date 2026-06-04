#!/bin/bash
# Compile test programs for OPM evaluation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$PROJECT_DIR/tests"
OUTPUT_DIR="$TEST_DIR/test_binaries"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Compiling test programs..."

# Compile each test program
for source in "$TEST_DIR/test_programs"/*.c; do
    if [ -f "$source" ]; then
        filename=$(basename "$source" .c)
        echo "Compiling: $filename"

        # Compile with debug info
        gcc -g -O0 -o "$OUTPUT_DIR/$filename" "$source"

        # Create stripped version
        cp "$OUTPUT_DIR/$filename" "$OUTPUT_DIR/${filename}.stripped"
        strip --strip-debug "$OUTPUT_DIR/${filename}.stripped"

        echo "  -> $OUTPUT_DIR/$filename"
        echo "  -> $OUTPUT_DIR/${filename}.stripped"
    fi
done

echo ""
echo "Compilation complete!"
echo "Debug binaries: $OUTPUT_DIR/*.c"
echo "Stripped binaries: $OUTPUT_DIR/*.stripped"
