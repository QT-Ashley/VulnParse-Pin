from abc import ABC, abstractmethod

class BaseParser(ABC):
    @abstractmethod
    def detect(self, data: dict) -> bool:
        """Return True if this parser can handle the given data"""
        pass

    @abstractmethod
    def parse(self, data: dict) -> dict:
        """Parse the data and return normalized VulnParse-Pin format"""
        pass
