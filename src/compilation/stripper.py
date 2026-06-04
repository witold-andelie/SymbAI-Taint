"""
Binary Stripper Module

Handles stripping debug symbols from ELF binaries.
Creates both stripped (for analysis) and unstripped (for ground truth) versions.
"""

import os
import shutil
import subprocess
import logging
from typing import Optional, Tuple
from pathlib import Path

logger = logging.getLogger('OPM.compilation')


class StripError(Exception):
    """Exception raised for stripping errors."""
    pass


def strip_binary(
    binary_path: str,
    output_path: Optional[str] = None,
    keep_original: bool = True
) -> str:
    """
    Strip debug symbols from a binary.

    Args:
        binary_path: Path to the binary to strip
        output_path: Output path for stripped binary (default: binary_path.stripped)
        keep_original: If True, keep original binary and create stripped copy

    Returns:
        Path to the stripped binary

    Raises:
        StripError: If stripping fails
        FileNotFoundError: If binary not found
    """
    binary_path = os.path.abspath(binary_path)
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    # Determine output path
    if output_path is None:
        if keep_original:
            output_path = binary_path + ".stripped"
        else:
            output_path = binary_path

    # If keeping original, copy first
    if keep_original:
        shutil.copy2(binary_path, output_path)
        logger.info(f"Copied binary to: {output_path}")

    # Strip the binary
    cmd = ['strip', '--strip-debug', output_path]

    logger.info(f"Stripping: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            error_msg = f"Stripping failed:\n{result.stderr}"
            logger.error(error_msg)
            raise StripError(error_msg)

        logger.info(f"Successfully stripped: {output_path}")
        return output_path

    except subprocess.TimeoutExpired:
        raise StripError("Stripping timed out after 30 seconds")
    except FileNotFoundError:
        raise StripError("strip command not found. Install binutils.")


def create_stripped_copy(
    binary_path: str,
    output_dir: Optional[str] = None
) -> Tuple[str, str]:
    """
    Create both stripped and unstripped versions of a binary.

    Args:
        binary_path: Path to the original binary
        output_dir: Output directory (default: same as binary)

    Returns:
        Tuple of (original_path, stripped_path)
    """
    binary_path = os.path.abspath(binary_path)
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    # Determine output directory
    if output_dir is None:
        output_dir = os.path.dirname(binary_path)
    os.makedirs(output_dir, exist_ok=True)

    # Get binary name
    binary_name = Path(binary_path).name

    # Create paths
    original_path = os.path.join(output_dir, f"{binary_name}.debug")
    stripped_path = os.path.join(output_dir, f"{binary_name}.stripped")

    # Copy original (with debug info)
    shutil.copy2(binary_path, original_path)
    logger.info(f"Copied original (with debug): {original_path}")

    # Create stripped copy
    shutil.copy2(binary_path, stripped_path)
    strip_binary(stripped_path, keep_original=False)
    logger.info(f"Created stripped copy: {stripped_path}")

    return original_path, stripped_path


def is_stripped(binary_path: str) -> bool:
    """
    Check if a binary is stripped.

    Args:
        binary_path: Path to the binary

    Returns:
        True if binary is stripped
    """
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    try:
        result = subprocess.run(
            ['readelf', '-S', binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            # Check for absence of debug sections
            has_debug = '.debug_info' in result.stdout
            return not has_debug
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: check file size (stripped binaries are usually smaller)
    return False


def extract_debug_info(
    binary_path: str,
    debug_path: Optional[str] = None
) -> str:
    """
    Extract debug information to a separate file.

    Args:
        binary_path: Path to the binary with debug info
        debug_path: Output path for debug info

    Returns:
        Path to the debug info file
    """
    binary_path = os.path.abspath(binary_path)
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    if debug_path is None:
        debug_path = binary_path + ".debug"

    cmd = ['objcopy', '--only-keep-debug', binary_path, debug_path]

    logger.info(f"Extracting debug info: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            error_msg = f"Debug extraction failed:\n{result.stderr}"
            logger.error(error_msg)
            raise StripError(error_msg)

        logger.info(f"Debug info extracted to: {debug_path}")
        return debug_path

    except subprocess.TimeoutExpired:
        raise StripError("Debug extraction timed out")
    except FileNotFoundError:
        raise StripError("objcopy command not found. Install binutils.")


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python stripper.py <binary_path> [output_dir]")
        sys.exit(1)

    binary = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        original, stripped = create_stripped_copy(binary, output)
        print(f"Original (with debug): {original}")
        print(f"Stripped: {stripped}")
        print(f"Is stripped (original): {is_stripped(original)}")
        print(f"Is stripped (stripped): {is_stripped(stripped)}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
