"""
IR Type Definitions

Defines types used in the typed intermediate representation.
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class TypeKind(Enum):
    """Kind of IR type."""
    VOID = "void"
    INTEGER = "integer"
    FLOAT = "float"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    FUNCTION = "function"


@dataclass
class IRType:
    """Base IR type."""
    kind: TypeKind
    name: str
    size: int = 0  # Size in bits
    is_signed: bool = True

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, IRType):
            return self.name == other.name
        return False


@dataclass
class VoidType(IRType):
    """Void type."""
    kind: TypeKind = TypeKind.VOID
    name: str = "void"
    size: int = 0


@dataclass
class IntegerType(IRType):
    """Integer type."""
    kind: TypeKind = TypeKind.INTEGER
    name: str = "i32"
    size: int = 32
    is_signed: bool = True


@dataclass
class FloatType(IRType):
    """Floating point type."""
    kind: TypeKind = TypeKind.FLOAT
    name: str = "f32"
    size: int = 32


@dataclass
class PointerType(IRType):
    """Pointer type."""
    kind: TypeKind = TypeKind.POINTER
    name: str = "ptr"
    size: int = 64  # Default 64-bit
    points_to: Optional[IRType] = None

    def __str__(self):
        if self.points_to:
            return f"{self.points_to}*"
        return "void*"


@dataclass
class ArrayType(IRType):
    """Array type."""
    kind: TypeKind = TypeKind.ARRAY
    name: str = "array"
    size: int = 0
    element_type: Optional[IRType] = None
    length: int = 0

    def __str__(self):
        if self.element_type:
            return f"{self.element_type}[{self.length}]"
        return f"unknown[{self.length}]"


@dataclass
class StructType(IRType):
    """Struct type."""
    kind: TypeKind = TypeKind.STRUCT
    name: str = "struct"
    size: int = 0
    fields: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class FunctionType(IRType):
    """Function type."""
    kind: TypeKind = TypeKind.FUNCTION
    name: str = "func"
    size: int = 0
    return_type: Optional[IRType] = None
    parameter_types: List[IRType] = field(default_factory=list)


@dataclass
class IRVariable:
    """Variable in the IR."""
    name: str
    type: IRType
    address: Optional[int] = None
    stack_offset: Optional[int] = None
    register: Optional[str] = None
    is_parameter: bool = False
    is_global: bool = False

    def __str__(self):
        return f"{self.name}: {self.type}"


@dataclass
class IRFunction:
    """Function in the IR."""
    name: str
    address: int
    return_type: Optional[IRType] = None
    parameters: List[IRVariable] = field(default_factory=list)
    local_variables: List[IRVariable] = field(default_factory=list)
    entry_block: Optional[int] = None


# Common type instances
VOID = VoidType()
I1 = IntegerType(name="i1", size=1)
I8 = IntegerType(name="i8", size=8)
I16 = IntegerType(name="i16", size=16)
I32 = IntegerType(name="i32", size=32)
I64 = IntegerType(name="i64", size=64)
U8 = IntegerType(name="u8", size=8, is_signed=False)
U16 = IntegerType(name="u16", size=16, is_signed=False)
U32 = IntegerType(name="u32", size=32, is_signed=False)
U64 = IntegerType(name="u64", size=64, is_signed=False)
F32 = FloatType(name="f32", size=32)
F64 = FloatType(name="f64", size=64)


def parse_type_string(type_str: str) -> IRType:
    """
    Parse a type string into an IRType.

    Args:
        type_str: Type string (e.g., "i32", "void*", "char[10]")

    Returns:
        IRType instance
    """
    type_str = type_str.strip().lower()

    # Void
    if type_str == 'void':
        return VOID

    # Integer types
    if type_str in ('i1', 'bool'):
        return I1
    if type_str in ('i8', 'char', 'byte'):
        return I8
    if type_str in ('i16', 'short'):
        return I16
    if type_str in ('i32', 'int', 'long'):
        return I32
    if type_str in ('i64', 'long long'):
        return I64

    # Unsigned types
    if type_str in ('u8', 'unsigned char'):
        return U8
    if type_str in ('u16', 'unsigned short'):
        return U16
    if type_str in ('u32', 'unsigned int', 'unsigned long'):
        return U32
    if type_str in ('u64', 'unsigned long long'):
        return U64

    # Float types
    if type_str in ('f32', 'float'):
        return F32
    if type_str in ('f64', 'double'):
        return F64

    # Pointer types
    if type_str.endswith('*'):
        base_type_str = type_str[:-1].strip()
        base_type = parse_type_string(base_type_str) if base_type_str else VOID
        return PointerType(points_to=base_type)

    # Array types
    if '[' in type_str and ']' in type_str:
        bracket_start = type_str.index('[')
        bracket_end = type_str.index(']')
        element_type_str = type_str[:bracket_start].strip()
        length_str = type_str[bracket_start+1:bracket_end].strip()

        element_type = parse_type_string(element_type_str) if element_type_str else VOID
        length = int(length_str) if length_str.isdigit() else 0

        return ArrayType(element_type=element_type, length=length)

    # Default: treat as void
    return VOID


def get_type_size(ir_type: IRType) -> int:
    """Get size of a type in bytes."""
    if ir_type.size > 0:
        return ir_type.size // 8
    return 0


def is_integer_type(ir_type: IRType) -> bool:
    """Check if type is an integer type."""
    return ir_type.kind == TypeKind.INTEGER


def is_float_type(ir_type: IRType) -> bool:
    """Check if type is a float type."""
    return ir_type.kind == TypeKind.FLOAT


def is_pointer_type(ir_type: IRType) -> bool:
    """Check if type is a pointer type."""
    return ir_type.kind == TypeKind.POINTER


def is_numeric_type(ir_type: IRType) -> bool:
    """Check if type is numeric (integer or float)."""
    return ir_type.kind in (TypeKind.INTEGER, TypeKind.FLOAT)
