from abc import ABC, abstractmethod
from typing import Optional
from classes.dataclass import ScanResult

class BaseParser(ABC):
    
    def __init__(self, filepath: str):
        self.filepath = filepath
    
    @classmethod
    def detect(cls, data: dict) -> bool:
        """Return True if this parser can handle the given data"""
        pass
    
    @classmethod
    def detect_file(cls, filepath: str) -> bool:
        """Detect based on file-level sniffing (XML, CSV, JSON header)."""

    @abstractmethod
    def parse(self) -> ScanResult:
        """Parse the data and return normalized VulnParse-Pin format"""
        pass
    
    @staticmethod
    def _safe_float(value: str):
        try: 
            return float(value)
        except (TypeError, ValueError):
            return None
    
    @staticmethod    
    def _safe_int(value:str):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
        
    @staticmethod
    def _safe_text(elem_text: Optional[str]) -> Optional[str]:
        """Normalize text from xml by stripping leading/trailing whitespace and collapsing newlines"""
        if not elem_text:
            return None
        return " ".join(elem_text.split())