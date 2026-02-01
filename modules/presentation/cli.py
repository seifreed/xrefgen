"""Presentation helpers for XrefGen (IDA UI/IO wrappers)."""

from typing import Dict, List, Tuple
import os
import time
import json
import csv
import ida_kernwin
import ida_nalt
import idc
from modules.presentation.logger import info


class XrefGenPresenter:
    def __init__(self, config, optimizer, module_manager):
        self.config = config
        self.optimizer = optimizer
        self.manager = module_manager

    def show_main_menu(self):
        choices = [
            "Run full analysis",
            "Run incremental analysis",
            "Select specific modules",
            "Configure settings",
            "Clear cache",
            "View statistics",
            "Exit",
        ]
        try:
            return ida_kernwin.choose_from_list(
                choices,
                "XrefGen - Select Action",
                0,
            )
        except Exception:
            return 0

    def select_modules_dialog(self):
        module_names = [m.get_name() for m in self.manager.modules]
        try:
            selected_names = []
            remaining = list(module_names)
            while remaining:
                idx = ida_kernwin.choose_from_list(
                    [f"[ ] {n}" for n in remaining] + ["<Run>"],
                    "Select modules to add (choose <Run> to proceed)",
                    0,
                )
                if idx is None or idx < 0 or idx >= len(remaining):
                    break
                selected_names.append(remaining.pop(idx))
            return selected_names
        except Exception:
            return []

    def configure_dialog(self):
        info("Configuration dialog not yet implemented")
        info("Edit xrefgen_config.json manually")

    def show_statistics(self):
        stats = self.optimizer.get_statistics()
        msg = (
            "XrefGen Statistics\n\n"
            f"Binary Hash: {stats['binary_hash']}\n"
            f"Cached Functions: {stats['cached_functions']}\n"
            f"Cached Analyses: {stats['cached_analyses']}\n"
            f"Cache Size: {stats['cache_size_mb']:.2f} MB\n\n"
            f"Modules Registered: {len(self.manager.modules)}\n"
        )
        try:
            ida_kernwin.info("%s", str(msg))
        except Exception:
            print(msg)

    def save_results(self, results: List[Tuple[int, int, str, float]], evidence_counts: dict = None, evidence_types: dict = None, profile: dict = None, taint_kinds: dict = None):
        output_file = self.config.get('general.output_file', '_user_xrefs.txt')
        json_file = self.config.get('general.json_output_file', '_user_xrefs.json')
        csv_file = self.config.get('general.csv_output_file', '_user_xrefs.csv')
        profile_file = self.config.get('general.profile_output_file', '_xrefgen_profile.json')
        taint_txt = self.config.get('general.taint_kind_output_file', '_user_xrefs_taint.txt')
        binary_path = ida_nalt.get_input_file_path()
        base_dir = os.path.dirname(binary_path)
        idb_path = self._get_idb_path(binary_path)
        output_name_mode = self.config.get("general.output_name_mode", "idb")
        output_path = self._resolve_output_path(output_file, idb_path, base_dir, output_name_mode)
        json_path = self._resolve_output_path(json_file, idb_path, base_dir, output_name_mode)
        csv_path = self._resolve_output_path(csv_file, idb_path, base_dir, output_name_mode)
        profile_path = self._resolve_output_path(profile_file, idb_path, base_dir, output_name_mode)
        taint_path = self._resolve_output_path(taint_txt, idb_path, base_dir, output_name_mode)

        details_name = self.config.get('general.details_output_file')
        if not details_name:
            if output_file.lower().endswith('.txt'):
                details_name = output_file[:-4] + '_details.txt'
            else:
                details_name = output_file + '_details.txt'
        details_path = self._resolve_output_path(details_name, idb_path, base_dir, output_name_mode)

        print(f"\n[XrefGen] Saving {len(results)} cross-references to {output_path}")
        include_taint = bool(self.config.get("general.include_taint_kind_in_txt", False))
        txt_format = self.config.get("general.txt_format", "xrefer")
        include_evidence = bool(self.config.get("general.txt_include_evidence", False))
        with open(output_path, 'w') as f_min:
            for source, target, _typ, _conf in results:
                if txt_format == "xrefer":
                    f_min.write(f"0x{source:x},0x{target:x}\n")
                    continue
                line_parts = [f"0x{source:x}", f"0x{target:x}"]
                if include_taint and taint_kinds:
                    kind = taint_kinds.get((source, target), "")
                    line_parts.append(kind)
                if include_evidence and evidence_types:
                    et = sorted(list(evidence_types.get((source, target), [])))
                    if et:
                        line_parts.append(f"evid=[{','.join(f'{e}:1' for e in et)}]")
                f_min.write(",".join(line_parts) + "\n")
        info(f"Results written to: {output_path}")

        with open(details_path, 'w') as f_det:
            self._write_details_header(f_det, binary_path, len(results))

            results_by_type: Dict[str, List[Tuple[int, int, float]]] = {}
            for source, target, xref_type, confidence in sorted(results):
                results_by_type.setdefault(xref_type, []).append((source, target, confidence))

            for xref_type in sorted(results_by_type.keys()):
                f_det.write(f"\n# {xref_type} ({len(results_by_type[xref_type])} refs)\n")
                for source, target, confidence in results_by_type[xref_type]:
                    evid = ""
                    if evidence_types:
                        et = sorted(list(evidence_types.get((source, target), [])))
                        if et:
                            evid = f" evid={','.join(et)}"
                    f_det.write(f"0x{source:x},0x{target:x} # {xref_type} ({confidence:.2f}){evid}\n")

        info(f"Detailed report written to: {details_path}")

        if taint_kinds:
            with open(taint_path, 'w') as f_tk:
                for source, target, _typ, _conf in results:
                    kind = taint_kinds.get((source, target), "")
                    f_tk.write(f"0x{source:x},0x{target:x},{kind}\n")
            info(f"Taint-kind TXT written to: {taint_path}")

        self._write_json(results, json_path, evidence_counts, evidence_types, taint_kinds)
        self._write_csv(results, csv_path, evidence_counts, evidence_types, taint_kinds)
        if profile:
            self._write_profile(profile, profile_path)

    def _get_idb_path(self, fallback_binary_path: str) -> str:
        try:
            path = idc.get_idb_path()
            if path:
                return path
        except Exception:
            pass
        return fallback_binary_path

    def _resolve_output_path(self, name: str, idb_path: str, base_dir: str, mode: str) -> str:
        if not name:
            return ""
        if os.path.isabs(name) or os.path.dirname(name):
            return name
        if mode == "idb":
            return f"{idb_path}{name}"
        return os.path.join(base_dir, name)

    def _write_json(self, results, path: str, evidence_counts: dict = None, evidence_types: dict = None, taint_kinds: dict = None):
        payload = [
            {
                "source": f"0x{source:x}",
                "target": f"0x{target:x}",
                "type": xref_type,
                "confidence": confidence,
                "evidence": (evidence_counts.get((source, target), 0) if evidence_counts else 0),
                "evidence_types": sorted(list(evidence_types.get((source, target), []))) if evidence_types else [],
                "taint_kind": taint_kinds.get((source, target)) if taint_kinds else None,
            }
            for source, target, xref_type, confidence in results
        ]
        with open(path, "w", encoding="utf-8") as f_json:
            json.dump(payload, f_json, indent=2)
        info(f"JSON written to: {path}")

    def _write_csv(self, results, path: str, evidence_counts: dict = None, evidence_types: dict = None, taint_kinds: dict = None):
        with open(path, "w", newline="", encoding="utf-8") as f_csv:
            writer = csv.writer(f_csv)
            writer.writerow(["source", "target", "type", "confidence", "evidence", "evidence_types", "taint_kind"])
            for source, target, xref_type, confidence in results:
                evidence = evidence_counts.get((source, target), 0) if evidence_counts else 0
                etypes = sorted(list(evidence_types.get((source, target), []))) if evidence_types else []
                tkind = taint_kinds.get((source, target)) if taint_kinds else ""
                writer.writerow([f"0x{source:x}", f"0x{target:x}", xref_type, f"{confidence:.2f}", evidence, "|".join(etypes), tkind])
        info(f"CSV written to: {path}")

    def _write_profile(self, profile: dict, path: str):
        with open(path, "w", encoding="utf-8") as f_prof:
            json.dump(profile, f_prof, indent=2)
        info(f"Profile written to: {path}")

    def _write_details_header(self, f_det, binary_path: str, total: int):
        f_det.write("# XrefGen v2.0 - Cross-Reference Analysis Results\n")
        f_det.write(f"# Binary: {os.path.basename(binary_path)}\n")
        f_det.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f_det.write(f"# Total xrefs: {total}\n")
        f_det.write("#\n")
        f_det.write("# Format: source,target # type (confidence)\n")
        f_det.write("#\n\n")
