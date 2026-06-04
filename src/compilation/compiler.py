"""
Compiler Module

Handles compilation of C source code to ELF binaries.
Supports GCC and Clang compilers with configurable flags.
"""

import os
import subprocess
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger('OPM.compilation')


class CompilationError(Exception):
    """Exception raised for compilation errors."""
    pass


def compile_source(
    source_path: str,
    compiler: str = "gcc",
    flags: Optional[List[str]] = None,
    output_dir: Optional[str] = None,
    output_name: Optional[str] = None
) -> str:
    """
    Compile a C source file to an ELF binary.

    Args:
        source_path: Path to the C source file
        compiler: Compiler to use ('gcc' or 'clang')
        flags: Additional compilation flags
        output_dir: Output directory (default: same as source)
        output_name: Output binary name (default: source name without extension)

    Returns:
        Path to the compiled binary

    Raises:
        CompilationError: If compilation fails
        FileNotFoundError: If source file not found
    """
    source_path = os.path.abspath(source_path)
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file not found: {source_path}")

    # Default flags: debug info + no optimization (preserve variables)
    if flags is None:
        flags = ["-g", "-O0"]

    # Determine output path
    source_name = Path(source_path).stem
    if output_name is None:
        output_name = source_name

    if output_dir is None:
        output_dir = os.path.dirname(source_path)
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, output_name)

    # Build compilation command
    cmd = [compiler] + flags + ["-o", output_path, source_path]

    logger.info(f"Compiling: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            error_msg = f"Compilation failed:\n{result.stderr}"
            logger.error(error_msg)
            raise CompilationError(error_msg)

        if result.stderr:
            logger.warning(f"Compilation warnings:\n{result.stderr}")

        logger.info(f"Successfully compiled to: {output_path}")

        # On Windows, check for .exe extension
        if os.name == 'nt' and not output_path.endswith('.exe'):
            exe_path = output_path + '.exe'
            if os.path.exists(exe_path):
                output_path = exe_path

        return output_path

    except subprocess.TimeoutExpired:
        raise CompilationError("Compilation timed out after 60 seconds")
    except FileNotFoundError:
        raise CompilationError(f"Compiler not found: {compiler}")


def compile_test_programs(
    source_dir: str,
    output_dir: str,
    compiler: str = "gcc",
    flags: Optional[List[str]] = None
) -> Dict[str, str]:
    """
    Compile all C source files in a directory.

    Args:
        source_dir: Directory containing C source files
        output_dir: Output directory for binaries
        compiler: Compiler to use
        flags: Compilation flags

    Returns:
        Dictionary mapping source paths to binary paths
    """
    source_dir = os.path.abspath(source_dir)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    results = {}
    source_files = list(Path(source_dir).glob("*.c")) + list(Path(source_dir).glob("*.cpp"))

    for source_file in source_files:
        try:
            binary_path = compile_source(
                source_path=str(source_file),
                compiler=compiler,
                flags=flags,
                output_dir=output_dir
            )
            results[str(source_file)] = binary_path
        except (CompilationError, FileNotFoundError) as e:
            logger.error(f"Failed to compile {source_file}: {e}")
            results[str(source_file)] = None

    logger.info(f"Compiled {len([v for v in results.values() if v])}/{len(results)} files")
    return results


def get_binary_info(binary_path: str) -> Dict[str, Any]:
    """
    Get information about a compiled binary.

    Args:
        binary_path: Path to the binary

    Returns:
        Dictionary with binary information
    """
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    info = {
        'path': binary_path,
        'size': os.path.getsize(binary_path),
        'has_debug_info': False,
        'is_stripped': False,
        'architecture': None,
    }

    # Check for debug info using readelf
    try:
        result = subprocess.run(
            ['readelf', '-S', binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            info['has_debug_info'] = '.debug_info' in result.stdout
            info['is_stripped'] = 'SYMTAB' not in result.stdout or '[strip]' in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Get architecture
    try:
        result = subprocess.run(
            ['file', binary_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            if 'x86-64' in result.stdout or 'x86_64' in result.stdout:
                info['architecture'] = 'x86_64'
            elif 'aarch64' in result.stdout:
                info['architecture'] = 'aarch64'
            elif 'ARM' in result.stdout:
                info['architecture'] = 'arm'
            elif 'MIPS' in result.stdout:
                info['architecture'] = 'mips'
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return info


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python compiler.py <source_file> [output_dir]")
        sys.exit(1)

    source = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        binary = compile_source(source, output_dir=output)
        info = get_binary_info(binary)
        print(f"Compiled: {binary}")
        print(f"Info: {info}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
