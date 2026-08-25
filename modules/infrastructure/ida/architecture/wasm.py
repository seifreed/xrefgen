"""Small, dependency-free WebAssembly module parser for static resolution."""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


def _uleb(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            break
    raise ValueError("invalid WebAssembly unsigned LEB128")


def _sleb(data: bytes, offset: int, bits: int = 32) -> Tuple[int, int]:
    value, offset = _uleb(data, offset)
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value, offset


def _name(data: bytes, offset: int) -> Tuple[str, int]:
    length, offset = _uleb(data, offset)
    end = offset + length
    return data[offset:end].decode("utf-8", "replace"), end


def _skip_limits(data: bytes, offset: int) -> int:
    flags, offset = _uleb(data, offset)
    _, offset = _uleb(data, offset)
    if flags & 1:
        _, offset = _uleb(data, offset)
    return offset


def _skip_const_expr(data: bytes, offset: int) -> Tuple[Optional[int], int]:
    value = None
    while offset < len(data):
        opcode = data[offset]
        offset += 1
        if opcode == 0x41:
            value, offset = _sleb(data, offset)
        elif opcode == 0x42:
            value, offset = _sleb(data, offset, 64)
        elif opcode == 0x23:
            _, offset = _uleb(data, offset)
        elif opcode == 0xD2:
            value, offset = _uleb(data, offset)
        elif opcode == 0x0B:
            return value, offset
        else:
            # The parser only needs the expression boundary for offsets.
            offset = _skip_instruction(data, offset - 1)
    raise ValueError("unterminated WebAssembly constant expression")


def _blocktype(data: bytes, offset: int) -> int:
    byte = data[offset]
    if byte == 0x40 or byte >= 0x7B:
        return offset + 1
    _, offset = _sleb(data, offset, 33)
    return offset


def _skip_instruction(data: bytes, offset: int) -> int:
    opcode = data[offset]
    offset += 1
    if opcode in {0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B}:
        return offset
    if opcode in {0x02, 0x03, 0x04}:
        return _blocktype(data, offset)
    if opcode in {0x0C, 0x0D, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24}:
        _, offset = _uleb(data, offset)
        return offset
    if opcode == 0x0E:
        count, offset = _uleb(data, offset)
        for _ in range(count + 1):
            _, offset = _uleb(data, offset)
        return offset
    if opcode == 0x11:
        _, offset = _uleb(data, offset)
        _, offset = _uleb(data, offset)
        return offset
    if opcode == 0x41:
        return _sleb(data, offset)[1]
    if opcode == 0x42:
        return _sleb(data, offset, 64)[1]
    if opcode == 0x43:
        return offset + 4
    if opcode == 0x44:
        return offset + 8
    if opcode == 0xD0:
        return offset + 1
    if opcode in {0xD2}:
        return _uleb(data, offset)[1]
    if 0x28 <= opcode <= 0x3E:
        _, offset = _uleb(data, offset)
        _, offset = _uleb(data, offset)
        return offset
    if opcode == 0xFC:
        sub, offset = _uleb(data, offset)
        if sub in {8, 9, 10, 11, 12, 13, 14, 15, 16, 17}:
            _, offset = _uleb(data, offset)
            if sub in {8, 10, 12, 14, 16}:
                _, offset = _uleb(data, offset)
        return offset
    if opcode == 0xFD:
        _, offset = _uleb(data, offset)
        return min(len(data), offset + 16)
    return offset


@dataclass(frozen=True)
class WasmFunctionBody:
    index: int
    body_offset: int
    code_offset: int
    code_end: int


@dataclass(frozen=True)
class WasmInstruction:
    offset: int
    end: int
    opcode: int
    immediate: Optional[int] = None
    table_index: Optional[int] = None


class WasmModule:
    """Parse the sections needed for statically known indirect calls."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x00asm" or data[4:8] != b"\x01\x00\x00\x00":
            raise ValueError("unsupported WebAssembly module header")
        self.data = data
        self.imported_functions = 0
        self.function_bodies: Dict[int, WasmFunctionBody] = {}
        self.table_entries: Dict[int, Dict[int, int]] = {}
        self.exports: Dict[str, int] = {}
        self._parse_sections()

    @classmethod
    def from_file(cls, path: str):
        with open(path, "rb") as stream:
            return cls(stream.read())

    @property
    def defined_function_indices(self) -> List[int]:
        return sorted(self.function_bodies)

    def _parse_sections(self):
        offset = 8
        function_count = 0
        while offset < len(self.data):
            section_id = self.data[offset]
            offset += 1
            size, payload = _uleb(self.data, offset)
            end = payload + size
            if end > len(self.data):
                raise ValueError("truncated WebAssembly section")
            if section_id == 2:
                self._parse_imports(payload, end)
            elif section_id == 3:
                function_count, _ = _uleb(self.data, payload)
            elif section_id == 7:
                self._parse_exports(payload, end)
            elif section_id == 9:
                self._parse_elements(payload, end)
            elif section_id == 10:
                self._parse_code(payload, end)
            offset = end
        if function_count and len(self.function_bodies) != function_count:
            raise ValueError("WebAssembly function/code section mismatch")

    def _parse_imports(self, offset: int, end: int):
        count, offset = _uleb(self.data, offset)
        for _ in range(count):
            _, offset = _name(self.data, offset)
            _, offset = _name(self.data, offset)
            kind = self.data[offset]
            offset += 1
            if kind == 0:
                self.imported_functions += 1
                _, offset = _uleb(self.data, offset)
            elif kind == 1:
                offset = self._skip_table_type(offset)
            elif kind == 2:
                offset = _skip_limits(self.data, offset)
            elif kind == 3:
                offset += 2
            else:
                raise ValueError("unknown WebAssembly import kind")
        if offset > end:
            raise ValueError("truncated WebAssembly import section")

    def _skip_table_type(self, offset: int) -> int:
        return _skip_limits(self.data, offset + 1)

    def _parse_exports(self, offset: int, end: int):
        count, offset = _uleb(self.data, offset)
        for _ in range(count):
            name, offset = _name(self.data, offset)
            kind = self.data[offset]
            offset += 1
            index, offset = _uleb(self.data, offset)
            if kind == 0:
                self.exports[name] = index
        if offset > end:
            raise ValueError("truncated WebAssembly export section")

    def _parse_code(self, offset: int, end: int):
        count, offset = _uleb(self.data, offset)
        for ordinal in range(count):
            body_size, body_start = _uleb(self.data, offset)
            body_end = body_start + body_size
            if body_end > end:
                raise ValueError("truncated WebAssembly code body")
            locals_count, code_offset = _uleb(self.data, body_start)
            for _ in range(locals_count):
                _, code_offset = _uleb(self.data, code_offset)
                code_offset += 1
            self.function_bodies[self.imported_functions + ordinal] = WasmFunctionBody(
                self.imported_functions + ordinal,
                body_start,
                code_offset,
                body_end,
            )
            offset = body_end

    def _parse_elements(self, offset: int, end: int):
        count, offset = _uleb(self.data, offset)
        for _ in range(count):
            flags, offset = _uleb(self.data, offset)
            table = 0
            active = flags in {0, 2, 4, 6}
            values: List[int] = []
            if flags in {0, 4}:
                base, offset = _skip_const_expr(self.data, offset)
            elif flags in {2, 6}:
                table, offset = _uleb(self.data, offset)
                base, offset = _skip_const_expr(self.data, offset)
            else:
                base = 0
            if flags in {0, 1, 2, 3}:
                if flags in {1, 2, 3}:
                    offset += 1
                count_values, offset = _uleb(self.data, offset)
                for _ in range(count_values):
                    value, offset = _uleb(self.data, offset)
                    values.append(value)
            else:
                if flags in {5, 6, 7}:
                    offset += 1
                count_values, offset = _uleb(self.data, offset)
                for _ in range(count_values):
                    value, offset = _skip_const_expr(self.data, offset)
                    if value is not None:
                        values.append(value)
            if active and base is not None:
                self.table_entries.setdefault(table, {}).update(
                    {base + index: value for index, value in enumerate(values)}
                )
        if offset > end:
            raise ValueError("truncated WebAssembly element section")

    def instructions(self, function_index: int) -> List[WasmInstruction]:
        body = self.function_bodies.get(function_index)
        if not body:
            return []
        result = []
        offset = body.code_offset
        previous_const = None
        while offset < body.code_end:
            start = offset
            opcode = self.data[offset]
            end = _skip_instruction(self.data, offset)
            if end <= start or end > body.code_end:
                break
            immediate = None
            table_index = None
            if opcode == 0x41:
                immediate, _ = _sleb(self.data, start + 1)
            elif opcode == 0x11:
                cursor = start + 1
                _, cursor = _uleb(self.data, cursor)
                table_index, _ = _uleb(self.data, cursor)
                immediate = previous_const
            result.append(WasmInstruction(start, end, opcode, immediate, table_index))
            previous_const = immediate if opcode == 0x41 else None
            offset = end
        return result

    def table_target(self, table: int, element: Optional[int]) -> Optional[int]:
        if element is None:
            return None
        return self.table_entries.get(table, {}).get(element)

    def branch_targets(self, function_index: int) -> Dict[int, List[int]]:
        """Return br_table instruction offsets mapped to relative code targets."""
        instructions = self.instructions(function_index)
        stack = []
        matching = {}
        for instruction in instructions:
            if instruction.opcode in {0x02, 0x03, 0x04}:
                stack.append((instruction.opcode, instruction.end, None))
            elif instruction.opcode == 0x0B and stack:
                kind, start, _ = stack.pop()
                matching[start] = instruction.end
        targets = {}
        stack = []
        for instruction in instructions:
            if instruction.opcode in {0x02, 0x03, 0x04}:
                stack.append((instruction.opcode, instruction.end, None))
                continue
            if instruction.opcode == 0x0B:
                if stack:
                    stack.pop()
                continue
            if instruction.opcode != 0x0E:
                continue
            cursor = instruction.offset + 1
            count, cursor = _uleb(self.data, cursor)
            depths = []
            for _ in range(count + 1):
                depth, cursor = _uleb(self.data, cursor)
                depths.append(depth)
            values = []
            for depth in depths:
                if depth >= len(stack):
                    continue
                kind, start, _ = stack[-1 - depth]
                values.append(start if kind == 0x03 else matching.get(start, start))
            targets[instruction.offset] = values
        return targets
