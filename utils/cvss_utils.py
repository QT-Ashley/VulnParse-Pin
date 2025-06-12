import re
from typing import Optional
from .logger import *
from . import logger_instance as log

try:
    from cvss import CVSS3
except ImportError:
    CVSS3 = None #Fallback if module isn't installed
    
    
CVSS3_REGEX = r'^CVSS:3\.[0-1]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$/'

def is_valid_cvss_vector(vector: Optional[str]) -> bool:
    '''
    Validate if a given string is well-formed CVSS V3.x vector.
    
    Args:
        vector (str): CVSS vector string.
        
    Returns:
        bool: True if valid, False otherwise.
    '''
    
    if vector is None:
        return False
    pattern = re.compile(CVSS3_REGEX)
    return bool(pattern.match(vector))


def parse_cvss_vector(vector: str) -> Optional[dict]:
    '''
    Parse a CVSS v3.X vector string into its base score components.
    
    Args:
        vector (str): CVSS vector string.
        
    Returns:
        dict or None: Dictionary of CVSS score or None if invalid or supported.
    '''
    if not is_valid_cvss_vector(vector):
        return None
    
    if CVSS3 is None:
        raise ImportError("cvss package is not installed. Install it with 'pip install cvss'.")
    
    try:
        cvss_obj = CVSS3(vector)
        return cvss_obj.scores()
    except Exception as e:
        log.log.print_error(f"Error parsing CVSS vector: {e}")
        log.log.logger.exception(f"Exception: {e}")
        return None
