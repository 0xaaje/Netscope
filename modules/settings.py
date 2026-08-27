"""Local, non-secret application settings."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict


DEFAULT_SETTINGS: Dict[str, Any] = {
    "theme": "dark",
    "default_profile": "standard",
    "timeout": 1.5,
    "workers": 200,
    "rate_limit": None,
    "output_directory": "output",
    "reverse_dns": True,
    "banner_inspection": True,
}


def settings_path() -> Path:
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_root / "netscope" / "settings.json"


def load_settings() -> Dict[str, Any]:
    path = settings_path()
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        data = {}
    settings = dict(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        for key in DEFAULT_SETTINGS:
            if key in data and not isinstance(data[key], (dict, list)):
                settings[key] = data[key]
    return settings


def save_settings(values: Dict[str, Any]) -> Path:
    settings = dict(DEFAULT_SETTINGS)
    for key in DEFAULT_SETTINGS:
        if key in values and not isinstance(values[key], (dict, list)):
            settings[key] = values[key]
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path
