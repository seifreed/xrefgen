# IDA Pro Cross-Reference Generator for Mandiant XRefer

Professional IDAPython script that generates additional cross-references for IDA Pro that aren't automatically detected, specifically designed for use with the **Mandiant XRefer** plugin.

## Author
**Marc Rivero** | [@seifreed](https://twitter.com/seifreed)

## Version
**1.2** - Enhanced with advanced analysis capabilities

## Overview

This script detects various types of indirect references and control flow patterns that IDA Pro's automatic analysis might miss, particularly in:
- **Modern compiled languages** (Rust, Go, C++)
- **Obfuscated malware** 
- **Packed binaries**
- **Complex control flow patterns**

The generated references are saved in `_user_xrefs.txt` format compatible with Mandiant XRefer plugin.

## Features

### Core Detection Methods

#### 1. **Indirect Call/Jump Analysis**
- Resolves register-based indirect calls (`call rax`, `jmp rcx`)
- Memory-based indirect calls (`call [rax+0x10]`, `jmp [rbp+var_8]`)
- Function pointer resolution through constant loading
- Complex vtable dispatch patterns

#### 2. **Advanced Switch-Case Detection**
- Uses `idaapi.get_switch_info_ex()` for accurate jump table analysis
- Multiple fallback methods for different switch patterns
- Supports various entry sizes (8, 4, 2, 1 bytes)
- Handles complex switch constructs in modern compilers

#### 3. **Trampoline Function Detection**
- Small wrapper functions (≤16 bytes, ≤2 instructions)
- Simple jump/call forwarding patterns
- Common in optimized binaries and dynamic linking

#### 4. **Advanced Pattern Recognition**
- Complex vtable-like dispatches (`call [rax+offset]`)
- Register-based indirect calls with register tracking
- Small trampoline functions analysis
- Multi-level pointer dereferences

#### 5. **Hex-Rays Pseudocode Analysis** ⭐ *NEW*
- Analyzes decompiled pseudocode for hidden references
- Detects function pointer calls: `sub_401000()`
- Identifies indirect calls: `(*func_ptr)()`
- Finds vtable accesses: `object->method()`
- Reveals references obfuscated in assembly

#### 6. **Stack Variable Tracking** ⭐ *NEW*
- Tracks function pointers stored on stack
- Correlates stack variable assignments with usage
- Detects `lea` + indirect call patterns
- Common in malware obfuscation techniques

#### 7. **Dynamic Import Detection** ⭐ *NEW*
- Detects `GetProcAddress`/`dlsym` usage patterns
- Correlates string loading with API resolution
- Identifies `LoadLibrary` → `GetProcAddress` → call sequences
- Tracks dynamic API function loading

#### 8. **String Reference Analysis** ⭐ *NEW*
- Categorizes strings by behavior patterns:
  - **Malware indicators**: `CreateProcess`, `VirtualAlloc`, etc.
  - **Crypto indicators**: `encrypt`, `AES`, `SHA`, etc.
  - **Network indicators**: `HTTP`, `TCP`, `socket`, etc.
  - **File operations**: `CreateFile`, `ReadFile`, etc.
  - **Registry operations**: `RegOpenKey`, etc.
  - **Persistence**: `CreateService`, `schtasks`, etc.
- Detects file paths, URLs, and registry keys
- Tracks indirect string references through registers

#### 9. **Variable Reference Analysis** ⭐ *NEW*
- Global variable function pointer analysis
- Vtable and function pointer table detection
- Structure member function pointer access
- Local variable tracking for function pointers

### Performance Optimizations

- **Aggressive Filtering**: Removes trivial, duplicate, and already-known references
- **Modern Language Support**: Optimized for Rust, Go, and C++ binaries
- **Memory Efficient**: Processes large binaries without excessive memory usage
- **Duplicate Prevention**: Automatic deduplication of references

## Installation

1. Copy `xref_generator.py` to your IDA Pro scripts directory
2. Open your target binary in IDA Pro 9.0+
3. Run the script: `File > Script file...` or `Alt+F7`

## Usage

### Basic Usage
```python
# Run from IDA Pro console
exec(open("path/to/xref_generator.py").read())
```

### Advanced Usage
```python
# Create generator instance for custom analysis
generator = XrefGenerator()

# Run specific analysis modules
indirect_refs = generator.get_indirect_calls()
switch_refs = generator.detect_switch_cases() 
stack_refs = generator.detect_stack_variable_refs()
pseudocode_refs = generator.analyze_hexrays_pseudocode()

# Generate complete analysis
generator.generate_xrefs()
```

## Output Format

The script generates `_user_xrefs.txt` with the format:
```
0x401234,0x402000 # indirect_call
0x401240,0x403000 # switch_case_0
0x401250,0x404000 # vtable_dispatch
0x401260,0x405000 # pseudocode_func_ptr
0x401270,0x406000 # string_malware_indicator_createprocess
0x401280,0x407000 # stack_var_call
0x401290,0x408000 # dynamic_import_GetProcAddress
```

### Reference Types

| Type | Description |
|------|-------------|
| `indirect_call` | Register/memory-based calls |
| `indirect_jmp` | Register/memory-based jumps |
| `switch_case_N` | Switch case N target |
| `jumptable_entry` | Jump table entry |
| `vtable_dispatch` | Virtual table method call |
| `vtable_func_ptr` | Vtable function pointer |
| `trampoline` | Small trampoline function |
| `small_trampoline` | Advanced trampoline pattern |
| `reg_indirect_call` | Register indirect call |
| `pseudocode_func_call` | Function call from pseudocode |
| `pseudocode_func_ptr` | Function pointer from pseudocode |
| `pseudocode_vtable_access` | Vtable access from pseudocode |
| `stack_var_call` | Stack variable call |
| `stack_var_jmp` | Stack variable jump |
| `stack_var_lea_call` | LEA + indirect call pattern |
| `dynamic_import_*` | Dynamic import resolution |
| `api_string_*` | API name string reference |
| `resolved_dynamic_import` | Resolved dynamic function |
| `string_*` | Categorized string references |
| `string_path` | File path string |
| `string_url` | URL string |
| `string_registry` | Registry path string |
| `string_api_name` | API name string |
| `string_indirect_ref` | Indirect string reference |
| `global_var_*` | Global variable reference |
| `vtable_entry_N` | Vtable entry N |
| `struct_member_ptr` | Structure member pointer |

## Requirements

- **IDA Pro 9.0+** (tested on 9.0 and 9.1)
- **Python 3.x** within IDA environment
- **Hex-Rays Decompiler** (optional, for pseudocode analysis)

## Compatibility Notes

- **IDA Pro 8.x**: Some features may not work due to API changes
- **32-bit binaries**: Automatically adjusts pointer sizes
- **Large binaries**: May take several minutes on complex Rust/Go binaries
- **Hex-Rays**: Pseudocode analysis requires decompiler license

## Performance Tips

- For very large binaries (>100MB), consider running analysis on specific segments
- The script includes built-in progress logging
- Modern language binaries (Rust/Go) may generate 1000+ references

## Troubleshooting

### Common Issues

1. **"Hex-Rays decompiler not available"**
   - Pseudocode analysis skipped (normal without decompiler)
   - Other analysis methods continue working

2. **Large number of references (>10,000)**
   - Normal for Rust/Go binaries
   - Consider filtering by reference type if needed

3. **Performance on large binaries**
   - Script includes progress logging
   - Consider analyzing specific functions if needed

## Use Cases

### Malware Analysis
- Dynamic API resolution patterns
- Stack-based obfuscation
- String-based IoC detection
- Persistence mechanism identification

### Reverse Engineering
- Complex control flow analysis
- Virtual function resolution
- Modern language binary analysis
- Obfuscated code patterns

### Vulnerability Research
- Hidden code paths
- Indirect function calls
- Complex switch statements
- Dynamic import analysis

## Mandiant XRefer Integration

1. Run this script to generate `_user_xrefs.txt`
2. Load Mandiant XRefer plugin in IDA
3. XRefer will automatically detect and load the additional references
4. Use XRefer's visualization and analysis features

## Version History

- **v1.2**: Added pseudocode analysis, stack variables, dynamic imports, string analysis, variable references
- **v1.1**: Enhanced switch-case detection, performance optimizations
- **v1.0**: Initial release with basic indirect call detection

## Contributing

Feel free to contribute improvements or report issues. This script is designed to be modular and extensible.

## License

This script is provided for educational and research purposes. Use responsibly and in compliance with applicable laws and regulations. 