"""
Typed IR Module

Implements: VEX IR + CFG + DFG + TypeRecoveryOutput → TypeMetadataInjection → TypedIR
From infra.txt: "Type Metadata Injection"

This module handles:
1. Injecting type metadata into IR
2. Creating type-augmented intermediate representation
3. Linking type information to variables
"""

from .type_injector import inject_type_metadata, TypedIR
from .ir_types import IRType, IRVariable, IRFunction
