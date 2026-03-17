import os
from pathlib import Path
from ruamel.yaml import YAML
from typing import Dict, Any, List

class YamlManager:
    def __init__(self, cheatsheet_dir: str, methodology_dir: str):
        self.cheatsheet_dir = Path(cheatsheet_dir)
        self.methodology_dir = Path(methodology_dir)
        self.yaml = YAML()
        self.yaml.preserve_quotes = True

    def _get_files(self, directory: Path) -> List[str]:
        return [f.name for f in directory.glob("*.yaml")]

    def list_cheatsheets(self) -> List[str]:
        return self._get_files(self.cheatsheet_dir)

    def list_methodologies(self) -> List[str]:
        return self._get_files(self.methodology_dir)

    def read_yaml(self, directory: Path, filename: str) -> Dict[str, Any]:
        filepath = directory / filename
        if not filepath.exists():
            raise FileNotFoundError(f"{filename} not found in {directory}")
        with open(filepath, "r") as f:
            return self.yaml.load(f)

    def write_yaml(self, directory: Path, filename: str, data: Dict[str, Any]):
        filepath = directory / filename
        with open(filepath, "w") as f:
            self.yaml.dump(data, f)
            
    def get_cheatsheet(self, filename: str) -> Dict[str, Any]:
        return self.read_yaml(self.cheatsheet_dir, filename)

    def save_cheatsheet(self, filename: str, data: Dict[str, Any]):
        self.write_yaml(self.cheatsheet_dir, filename, data)

    def get_methodology(self, filename: str) -> Dict[str, Any]:
        return self.read_yaml(self.methodology_dir, filename)

    def save_methodology(self, filename: str, data: Dict[str, Any]):
        self.write_yaml(self.methodology_dir, filename, data)
