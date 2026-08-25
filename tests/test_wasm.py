from modules.infrastructure.ida.architecture.wasm import WasmModule


def _section(section_id, payload):
    return bytes([section_id, len(payload)]) + payload


def test_wasm_parser_resolves_static_table_and_branch_targets():
    body = bytes([
        0x00,
        0x41, 0x01,
        0x11, 0x00, 0x00,
        0x02, 0x40,
        0x41, 0x00,
        0x0E, 0x01, 0x00, 0x00,
        0x0B, 0x0B,
    ])
    module = (
        b"\x00asm\x01\x00\x00\x00"
        + _section(1, bytes([1, 0x60, 0, 0]))
        + _section(3, bytes([1, 0]))
        + _section(4, bytes([1, 0x70, 0, 2]))
        + _section(9, bytes([1, 0, 0x41, 0, 0x0B, 2, 0, 0]))
        + _section(10, bytes([1, len(body)]) + body)
    )

    parsed = WasmModule(module)
    assert parsed.table_target(0, 1) == 0
    instructions = parsed.instructions(0)
    indirect = next(item for item in instructions if item.opcode == 0x11)
    assert indirect.immediate == 1
    assert parsed.branch_targets(0)
