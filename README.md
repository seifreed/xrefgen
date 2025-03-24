# XrefGen - Advanced Cross-Reference Generator for IDA Pro

## Overview

XrefGen is an IDAPython script that enhances IDA Pro's static analysis capabilities by generating additional cross-references not automatically detected by IDA Pro. These supplementary references are saved in a format compatible with Mandiant's XRefer plugin, allowing for improved navigation and understanding of complex code.

## Features

- **Indirect Call/Jump Detection**: Identifies targets of indirect calls (`call [reg]`, `call [mem]`, etc.) and jumps
- **Switch-Case Tables**: Multiple methods to detect and map switch-case jump tables:
  - Pattern-based detection for complex control flow
  - Using `idaapi.get_switch_info_ex` for native detection
  - Jump table analysis with multiple entry size support
- **Vtable Constructors**: Detects C++ vtable references in constructors
- **Trampoline Functions**: Identifies small functions that only contain jumps to other locations
- **Advanced Dispatch Pattern Detection**: Identifies complex dispatch patterns in modern languages:
  - Vtable-like dispatches (especially useful for C++, Rust)
  - Register-based indirect calls with register tracking
  - Complex switch patterns
- **Conservative Validation**: Only includes references that point to valid code locations
- **Filter for Already Known References**: Avoids duplicating references already detected by IDA

## Requirements

- IDA Pro (tested on version 9.0/9.1)
- Python 3.x

## Installation

1. Download `xref_generator.py` to your local machine
2. Load your binary in IDA Pro
3. Run the script via IDA's Script Command (Alt+F7) or File > Script Command...

## Usage

The script automatically:

1. Analyzes the current loaded binary
2. Detects various types of cross-references
3. Generates a file named `_user_xrefs.txt` in the same directory as your binary
4. Logs progress and reference counts to the console

The output file uses the format required by Mandiant XRefer:
```
0x<source_address>,0x<target_address> # <reference_type>
```

## How It Works

XrefGen performs a thorough scan of all functions in the binary, using several techniques:

1. **Indirect Call Analysis**: 
   - Examines patterns before call instructions to find loaded values
   - Tracks registers across multiple instructions
   - Filters out trivial jumps and already known references

2. **Switch-Case Detection**:
   - Multiple detection methods for maximum coverage
   - Native IDA API (`get_switch_info_ex` and `calc_switch_cases`)
   - Direct jump table analysis with size detection
   - Pattern recognition for typical switch-case constructs

3. **Memory Reference Tracking**: 
   - Follows memory references to find actual targets
   - Supports various memory access patterns

4. **Size-Based Detection**: 
   - Finds small functions that likely serve as trampolines
   - Filters trivial trampolines

5. **Modern Language Support**:
   - Specialized heuristics for C++, Rust, Go, and other modern languages
   - Detection of vtable dispatch patterns
   - Enhanced tracking of function pointer loads

## Example Output

```
[XrefGen] Starting cross-reference generation...
[XrefGen] Found 127 significant indirect calls/jumps
[XrefGen] Found 43 significant switch case references
[XrefGen] Found 32 switch-case references using get_switch_info_ex
[XrefGen] Found 18 significant vtable constructor references
[XrefGen] Found 32 significant trampoline functions
[XrefGen] Found 95 advanced dispatch patterns
[XrefGen] Generated 347 significant cross-references
[XrefGen] Results written to: C:\path\to\_user_xrefs.txt
```

## Integration with Mandiant XRefer

The output file is directly compatible with Mandiant's XRefer plugin, which allows you to:

1. Import additional cross-references into IDA Pro
2. Navigate the binary using these supplementary references
3. Get a more complete picture of the program's control flow

## Performance Notes

- For very large binaries or those with complex control flow (like those compiled from Rust), the script might generate a large number of references
- The script includes filtering mechanisms to focus on the most significant references
- It avoids adding references already detected by IDA

## Author

Marc Rivero | @seifreed

## License

This project is available under the MIT License.

## Acknowledgments

- Developed to extend the functionality of IDA Pro's cross-reference capabilities
- Designed to work with the Mandiant XRefer plugin 