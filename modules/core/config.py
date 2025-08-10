"""
Configuration management for XrefGen
"""

import json
import os
from typing import Dict, Any

class Config:
    """Configuration manager for XrefGen"""
    
    DEFAULT_CONFIG = {
        "general": {
            "output_file": "_user_xrefs.txt",
            "min_confidence": 0.5,
            "verbose": True,
            "parallel_processing": True,
            "max_workers": 4
        },
        "modules": {
            "data_flow": {
                "enabled": True,
                "taint_sources": ["recv", "read", "fread", "scanf", "gets"],
                "taint_sinks": ["system", "exec", "strcpy", "sprintf", "memcpy"],
                "max_taint_depth": 10
            },
            "obfuscation": {
                "enabled": True,
                "detect_cff": True,
                "detect_opaque_predicates": True,
                "detect_string_encryption": True,
                "max_dispatcher_size": 1000
            },
            "architecture": {
                "enabled": True,
                "architectures": ["x86", "x64", "arm", "arm64", "mips", "wasm"]
            },
            "graph": {
                "enabled": True,
                "max_chain_depth": 20,
                "cluster_threshold": 0.7,
                "complexity_threshold": 10
            },
            "ml": {
                "enabled": False,
                "model_path": None,
                "similarity_threshold": 0.85,
                "use_embeddings": True
            },
            "performance": {
                "enabled": True,
                "use_cache": True,
                "cache_dir": ".xrefgen_cache",
                "incremental": True
            },
            "ida_features": {
                "enabled": True,
                "use_lumina": False,
                "use_microcode": True,
                "use_type_libraries": True
            },
            "interactive": {
                "enabled": True,
                "preview_mode": True,
                "custom_filters": []
            }
        },
        "filters": {
            "exclude_segments": [],
            "exclude_functions": [],
            "include_only_segments": [],
            "include_only_functions": []
        }
    }
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or "xrefgen_config.json"
        self.config = self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    return self._merge_configs(self.DEFAULT_CONFIG, user_config)
            except Exception as e:
                print(f"[XrefGen] Error loading config: {e}, using defaults")
                return self.DEFAULT_CONFIG.copy()
        else:
            return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"[XrefGen] Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"[XrefGen] Error saving config: {e}")
    
    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Recursively merge user config with defaults"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, path: str, default: Any = None) -> Any:
        """Get config value by dot-notation path (e.g., 'modules.data_flow.enabled')"""
        keys = path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def set(self, path: str, value: Any):
        """Set config value by dot-notation path"""
        keys = path.split('.')
        target = self.config
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        target[keys[-1]] = value
    
    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """Get configuration for a specific module"""
        return self.config.get("modules", {}).get(module_name, {})