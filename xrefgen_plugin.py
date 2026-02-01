"""IDA Pro plugin entry for XrefGen (IDA 9.2+)."""

import idaapi
import ida_kernwin


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
        except Exception as exc:
            ida_kernwin.warning("XrefGen failed: %s" % exc)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return XrefGenPlugin()
