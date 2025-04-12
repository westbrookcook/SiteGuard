"""
Configuration management for SiteGuard
"""

import json
import os
from pathlib import Path


class Config:
    def __init__(self):
        self.default_config = {
            "timeout": 10,
            "max_redirects": 5,
            "user_agent": "SiteGuard/0.1",
            "tests": {
                "xss": True,
                "sqli": True,
                "path_traversal": True,
                "sensitive_files": True
            },
            "payloads": {
                "xss_custom": [],
                "sqli_custom": []
            },
            "output": {
                "verbose": True,
                "show_progress": True
            }
        }
        self.config = self.default_config.copy()

    def load_from_file(self, config_path):
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
                self._merge_config(file_config)
            return True
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load config file: {e}")
            return False

    def save_to_file(self, config_path):
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def _merge_config(self, file_config):
        for key, value in file_config.items():
            if key in self.config:
                if isinstance(value, dict) and isinstance(self.config[key], dict):
                    self.config[key].update(value)
                else:
                    self.config[key] = value

    def get(self, key, default=None):
        return self.config.get(key, default)

    def create_sample_config(self, config_path):
        sample_config = {
            "timeout": 15,
            "tests": {
                "xss": True,
                "sqli": True,
                "path_traversal": False
            },
            "output": {
                "verbose": False
            }
        }

        try:
            with open(config_path, 'w') as f:
                json.dump(sample_config, f, indent=2)
            print(f"Sample config created at: {config_path}")
            return True
        except Exception as e:
            print(f"Error creating sample config: {e}")
            return False