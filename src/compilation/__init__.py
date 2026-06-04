"""
Compilation Module

Implements: SourceCode → Compilation → Binary
From infra.txt: "Compilation and Stripping"

This module handles:
1. Compiling C source code to ELF binaries
2. Stripping debug symbols (for ground truth separation)
3. Preserving original binaries with debug info (for evaluation)
"""

from .compiler import compile_source, compile_test_programs
from .stripper import strip_binary, create_stripped_copy
