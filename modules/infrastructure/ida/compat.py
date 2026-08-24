"""Small compatibility helpers for supported IDA 9.x APIs."""

try:
    import ida_ida
except ImportError:
    ida_ida = None


def is_64bit() -> bool:
    return bool(ida_ida and hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit())


def procname() -> str:
    if ida_ida is None or not hasattr(ida_ida, "inf_get_procname"):
        return ""
    try:
        return (ida_ida.inf_get_procname() or "").lower()
    except (TypeError, ValueError, AttributeError, RuntimeError):
        return ""
