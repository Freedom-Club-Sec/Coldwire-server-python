import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = json.load(f)
