"""IDA Pro plugin entry for XrefGen (IDA 9.2+)."""

import os
import sys

import idaapi
import ida_kernwin


# The installer keeps the core under IDAUSR/scripts/xrefgen.
_CORE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "xrefgen")
if os.path.isdir(_CORE_DIR) and _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)


class XrefGenPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "XrefGen - Advanced Cross-Reference Generator"
    help = "Generate additional xrefs for Mandiant XRefer"
    wanted_name = "XrefGen"
    wanted_hotkey = "Alt-Shift-X"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        try:
            import xrefgen

            # Default to interactive mode when launched as plugin
            xrefgen.XrefGen().interactive_mode()
        except (ImportError, AttributeError, TypeError, RuntimeError) as exc:
            ida_kernwin.warning("XrefGen failed: %s" % exc)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return XrefGenPlugin()
