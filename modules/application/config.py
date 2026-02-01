"""Configuration management for XrefGen."""

import json
import os
from typing import Dict, Any, List


class Config:
    """Configuration manager for XrefGen."""

    DEFAULT_CONFIG = {
        "general": {
            "output_file": "_user_xrefs.txt",
            "min_confidence": 0.5,
            "verbose": True,
            "details_output_file": "_user_xrefs_details.txt",
            "json_output_file": "_user_xrefs.json",
            "csv_output_file": "_user_xrefs.csv",
            "profile_output_file": "_xrefgen_profile.json",
            "include_taint_kind": True,
            "taint_kind_output_file": "_user_xrefs_taint.txt",
            "include_taint_kind_in_txt": True,
            "txt_format": "xrefer",
            "txt_include_evidence": False,
            "output_name_mode": "idb",
            "slow_functions_report": "_xrefgen_slow.json",
            "log_file": None,
            "log_level": "info",
        },
        "modules": {
            "data_flow": {
                "enabled": True,
                "tuning_table": {
                    "sink_min_confidence": 0.5,
                    "function_timeout_ms": 0,
                    "large_function_threshold": 2000,
                    "large_function_taint_depth": 6,
                    "cfg_complexity_threshold": 200,
                    "cfg_depth_scale": 0.5,
                    "cfg_fanout_threshold": 4,
                    "cfg_loop_penalty": 0.85,
                    "cfg_edge_density_threshold": 2.5,
                    "cfg_loop_nesting_penalty": 0.8,
                    "max_taint_depth": 10,
                    "sanitizer_scoped": True,
                    "jump_table_taint": True,
                    "cf_sensitive_sinks": True,
                    "stack_arg_scan_max_back": 16,
                    "return_value_back_depth": 20,
                    "return_value_forward_depth": 10,
                    "register_resolve_back_depth": 10,
                    "pointer_chain_max_depth": 5,
                },
                "taint_sources": ["recv", "read", "fread", "scanf", "gets"],
                "string_sources": ["gets", "fgets", "getline", "scanf", "fscanf", "recv", "read"],
                "numeric_parsers": ["atoi", "atol", "strtol", "strtoul", "strtoll", "strtoull", "sscanf", "scanf", "fscanf"],
                "taint_sinks": ["system", "exec", "strcpy", "sprintf", "memcpy"],
                "taint_carrying_apis": ["memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf"],
                "heap_alloc_apis": ["malloc", "calloc", "realloc", "new", "operator new", "HeapAlloc", "VirtualAlloc"],
                "use_hexrays_taint": True,
                "taint_sanitizers": ["memset", "bzero", "strncpy", "strncat"],
                "taint_interprocedural_depth": 1,
                "taint_interprocedural_fanout": 5,
                "stack_arg_win_slots": [0, 8, 16, 24],
            },
            "obfuscation": {
                "enabled": True,
                "detect_cff": True,
                "detect_opaque_predicates": True,
                "detect_string_encryption": True,
                "detect_anti_analysis": True,
                "tuning_table": {
                    "max_dispatcher_size": 1000,
                    "cff_min_block_refs": 5,
                    "cff_min_comparisons": 3,
                    "cff_min_jumps": 3,
                    "cff_dispatcher_scan_limit": 20,
                    "cff_dispatcher_scan_window": 256,
                    "cff_resolved_confidence": 0.7,
                },
            },
            "architecture": {
                "enabled": True,
                "architectures": ["x86", "x64", "arm", "arm64", "mips", "wasm"],
            },
            "graph": {
                "enabled": True,
                "tuning_table": {
                    "complexity_threshold": 10,
                    "cluster_threshold": 0.7,
                    "hub_threshold": 20,
                    "cycle_max_len": 2,
                    "skip_trivial_size": 16,
                    "max_chain_depth": 20,
                    "max_indirect_targets": 3,
                    "min_indirect_confidence": 0.4,
                    "vtable_min_len": 3,
                },
                "compiler_profile": "auto",
                "callback_targets": {
                    "qsort": 3,
                    "bsearch": 3,
                    "createthread": 2,
                    "enumwindows": 0,
                    "enumchildwindows": 1
                },
                "confidence_table": {
                    "hub_call": 0.6,
                    "call_cycle": 0.55,
                    "trampoline": 0.7,
                    "wrapper_call": 0.6,
                    "callback_arg": 0.75,
                    "seh_handler": 0.7,
                    "vtable_named": 0.65,
                    "vtable_scan": 0.55,
                    "call_chain_base": 1.0,
                    "call_chain_min": 0.6,
                    "call_chain_depth_decay": 0.1,
                },
                "indirect_backtrack_depth": 10,
                "indirect_score_decay": 0.1,
                "indirect_direct_confidence": 0.95,
                "indirect_base_confidence": 0.9,
                "merge_multi_source_bonus": 0.12,
                "merge_heuristic_penalty": 0.9,
                "call_chain_decay": 0.98,
                "call_chain_min_length": 2,
            },
            "ml": {
                "enabled": True,
                "model_path": None,
                "similarity_threshold": 0.85,
                "use_embeddings": False,
                "max_functions": 1000,
            },
            "performance": {
                "enabled": True,
                "use_cache": True,
                "cache_dir": ".xrefgen_cache",
                "incremental": True,
                "cache_ttl_seconds": 3600,
                "max_function_ms": 0,
                "skip_slow_functions": False,
                "skip_slow_graph": True,
            },
            "ida_features": {
                "enabled": True,
                "use_lumina": False,
                "use_microcode": True,
                "use_type_libraries": True,
            },
            "interactive": {
                "enabled": True,
                "preview_mode": True,
                "custom_filters": [],
            },
        },
        "filters": {
            "exclude_segments": [],
            "exclude_functions": [],
            "include_only_segments": [],
            "include_only_functions": [],
        },
    }

    def __init__(self, config_file: str = None):
        if config_file is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            root_dir = os.path.dirname(os.path.dirname(script_dir))
            self.config_file = os.path.join(root_dir, "xrefgen_config.json")
        else:
            self.config_file = config_file
        self.config = self.load_config()
        self.validation_errors = self.validate_config(self.config)
        if self.validation_errors:
            for err in self.validation_errors:
                print(f"[XrefGen] Config warning: {err}")

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    return self._merge_configs(self.DEFAULT_CONFIG, user_config)
            except Exception as e:
                print(f"[XrefGen] Error loading config: {e}, using defaults")
                return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate configuration keys and report unknown/invalid entries."""
        errors: List[str] = []
        schema = self._schema()

        def walk(node, spec, path):
            if not isinstance(node, dict):
                errors.append(f"Expected object at '{path}'")
                return
            for key, val in node.items():
                if key not in spec:
                    errors.append(f"Unknown config key: {path + key}")
                    continue
                expected = spec[key]
                if isinstance(expected, dict):
                    if isinstance(val, dict):
                        walk(val, expected, path + key + ".")
                    else:
                        errors.append(f"Expected object at '{path + key}'")
            # Check for required keys (present in schema but missing in config)
            for key in spec.keys():
                if key not in node:
                    errors.append(f"Missing config key: {path + key}")

        walk(config, schema, "")
        return errors

    def _schema(self) -> Dict[str, Any]:
        """Return a minimal schema for config validation."""
        return {
            "general": {
                "output_file": None,
                "min_confidence": None,
                "verbose": None,
                "details_output_file": None,
                "json_output_file": None,
                "csv_output_file": None,
                "log_file": None,
                "log_level": None,
                "profile_output_file": None,
                "include_taint_kind": None,
                "taint_kind_output_file": None,
                "include_taint_kind_in_txt": None,
                "txt_format": None,
                "txt_include_evidence": None,
                "output_name_mode": None,
                "slow_functions_report": None,
            },
            "modules": {
                "data_flow": {
                    "enabled": None,
                    "tuning_table": None,
                    "taint_sources": None,
                    "string_sources": None,
                    "numeric_parsers": None,
                    "taint_sinks": None,
                    "taint_carrying_apis": None,
                    "heap_alloc_apis": None,
                    "use_hexrays_taint": None,
                    "taint_sanitizers": None,
                    "taint_interprocedural_depth": None,
                    "taint_interprocedural_fanout": None,
                    "stack_arg_win_slots": None,
                    "sink_exec_keywords": None,
                    "sink_string_keywords": None,
                },
                "obfuscation": {
                    "enabled": None,
                    "detect_cff": None,
                    "detect_opaque_predicates": None,
                    "detect_string_encryption": None,
                    "detect_anti_analysis": None,
                    "tuning_table": None,
                },
                "architecture": {
                    "enabled": None,
                    "architectures": None,
                },
                "graph": {
                    "enabled": None,
                    "compiler_profile": None,
                    "callback_targets": None,
                    "confidence_table": None,
                    "tuning_table": None,
                    "indirect_backtrack_depth": None,
                    "indirect_score_decay": None,
                    "indirect_direct_confidence": None,
                    "indirect_base_confidence": None,
                    "merge_multi_source_bonus": None,
                    "merge_heuristic_penalty": None,
                    "call_chain_decay": None,
                    "call_chain_min_length": None,
                },
                "ml": {
                    "enabled": None,
                    "model_path": None,
                    "similarity_threshold": None,
                    "use_embeddings": None,
                    "max_functions": None,
                },
                "performance": {
                    "enabled": None,
                    "use_cache": None,
                    "cache_dir": None,
                    "incremental": None,
                    "cache_ttl_seconds": None,
                    "max_function_ms": None,
                    "skip_slow_functions": None,
                    "skip_slow_graph": None,
                },
                "ida_features": {
                    "enabled": None,
                    "use_lumina": None,
                    "use_microcode": None,
                    "use_type_libraries": None,
                },
                "interactive": {
                    "enabled": None,
                    "preview_mode": None,
                    "custom_filters": None,
                },
            },
            "filters": {
                "exclude_segments": None,
                "exclude_functions": None,
                "include_only_segments": None,
                "include_only_functions": None,
            },
        }

    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"[XrefGen] Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"[XrefGen] Error saving config: {e}")

    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Recursively merge user config with defaults."""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, path: str, default: Any = None) -> Any:
        """Get config value by dot-notation path (e.g., 'modules.data_flow.enabled')."""
        keys = path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, path: str, value: Any):
        """Set config value by dot-notation path."""
        keys = path.split('.')
        target = self.config
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        target[keys[-1]] = value

    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """Get configuration for a specific module."""
        return self.config.get("modules", {}).get(module_name, {})
