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
            try:
                from modules.observability import exception
                exception("Plugin launch failed", event_name="plugin.launch_failed", status="failed")
            except ImportError:
                pass
            ida_kernwin.warning("XrefGen could not start; see the IDA console log")

    def term(self):
        try:
            from modules.observability import info, shutdown
            info("XrefGen plugin shutting down", event_name="plugin.shutdown")
            shutdown()
        except ImportError:
            pass


def PLUGIN_ENTRY():
    return XrefGenPlugin()
