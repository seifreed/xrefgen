"""Interprocedural summaries and propagation."""


class InterproceduralSummaries:
    def __init__(self, analyzer):
        self.a = analyzer

    def record_arg_to_arg(self, func_ea: int, src_reg: str, dst_reg: str):
        self.a.taint_summaries_arg.setdefault(func_ea, {}).setdefault(src_reg, set()).add(dst_reg)

    def record_arg_to_mem(self, func_ea: int, src_reg: str):
        self.a.taint_summaries_mem.setdefault(func_ea, set()).add(src_reg)

    def apply(self, call_ea: int, callee_ea: int, caller_func_ea: int):
        # Arg->arg propagation summary
        summary_arg = self.a.taint_summaries_arg.get(callee_ea, {})
        if summary_arg and caller_func_ea in self.a.tainted_regs:
            for src_arg, dst_args in summary_arg.items():
                if src_arg in self.a.tainted_regs[caller_func_ea]:
                    for dst in dst_args:
                        self.a.tainted_regs.setdefault(caller_func_ea, {})[dst] = self.a.tainted_regs[caller_func_ea][src_arg]
        # Arg->mem propagation summary
        summary_mem = self.a.taint_summaries_mem.get(callee_ea, set())
        if summary_mem and caller_func_ea in self.a.tainted_regs:
            aliases = self.a._heap_aliases.get(caller_func_ea, {})
            for src_arg in summary_mem:
                if src_arg in self.a.tainted_regs[caller_func_ea] and src_arg in aliases:
                    key = f"heap:{aliases[src_arg]}"
                    self.a.tainted_mem.setdefault(caller_func_ea, {})[key] = self.a.tainted_regs[caller_func_ea][src_arg]
                    self.a.taint_kinds_mem.setdefault(caller_func_ea, {})[key] = \
                        self.a.taint_kinds_regs.get(caller_func_ea, {}).get(src_arg, "ptr")
