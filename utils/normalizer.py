import ipaddress
from typing import get_type_hints, List, Union, Any, Optional
from dataclasses import fields, is_dataclass
from datetime import datetime

def normalize_dict_to_dataclass(raw_dict: dict, dataclass_type):
    '''
    Normalize the raw_dict to match the types expected by the dataclass_type, converting types as needed for common cases.
    '''
    hints = get_type_hints(dataclass_type)
    normalized = {}
    
    for f in fields(dataclass_type):
        field_name = f.name
        field_type = hints.get(field_name)
        raw_value = raw_dict.get(field_name)
        
        # Handle missing keys
        if raw_value is None:
            # For Optional fields, keep None
            normalized[field_name] = None
            continue
        
        
        # Normalize based on expected type
        try:
            # Handle Optional[X]
            origin = getattr(field_type, '__origin__', None)
            if origin is Union and type(None) in field_type.__args__:
                inner_type = next(t for t in field_type.__args__ if t is not type(None))
                normalized[field_name] = coerce_type(raw_value, inner_type)
            else:
                normalized[field_name] = coerce_type(raw_value, field_type)
        except Exception:
            normalized[field_name] = raw_value
            
    return normalized

def coerce_type(value, target_type, default: Optional[Any] = None):
    '''
    Try to convert value to target_type in common cases.
    '''
    # Handle strings that should be lists
    if target_type == List[str]:
        if isinstance(value, str):
            # Assume comma separated
            return [v.strip() for v in value.split(",") if v.strip()]
        elif isinstance(value, list):
            return [str(v) for v in value]
        else:
            return []
        
    # Handle bool fields
    if target_type == bool:
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1")
        return bool(value)
    
    # Handle float fields
    if target_type == float:
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
        
    # Handle int fields
    if target_type == int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
        
    # Handle str fields
    if target_type == str:
        if value is None:
            return ""
        return str(value)
    
    # Handle Nested Dataclasses
    if is_dataclass(target_type):
        if isinstance(value, dict):
            return normalize_dict_to_dataclass(value, target_type)
    
    # For nested dataclasses or unknown types just return the value, Or extend as needed.
    
    return value

def coerce_list_of_strs(value: Any) -> list[str]:
    """
    Coerce a value into a list of strings.

    This function ensures that the input value is returned as a list of strings.
    - If the value is a string, it splits it by commas.
    - If it's already a list, it converts each item to a string.
    - For any other type, it returns an empty list.

    Args:
        value (Any): The value to convert.

    Returns:
        List[str]: A list of strings.
    """
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    elif isinstance(value, list):
        return [coerce_type(v, str, default="").strip() for v in value if v]
    else:
        return []
    
def coerce_str(value: Union[str, int, float, None], default: Optional[str] = "Unknown") -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    elif isinstance(value, (int, float)):
        return str(value)
    return default

def coerce_ip(value: Union[str, List, None]) -> Optional[str]:
    if isinstance(value, str):
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            return None
    return "0.0.0.0"

def coerce_int(value: Union[str, int, None], default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
    
def coerce_date(value: str, default: Optional[str] = None) -> Optional[str]:
    try:
        #Check ISO format for date
        datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value
    except (ValueError, TypeError, AttributeError):
        return default
    
def coerce_severity(value: str, default: Optional[str] = "Low") -> Optional[str]:
    try:
        valid = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Informational",
            "none": "None",
            "unknown": "Unknown"
        }
        return valid.get(str(value).strip().lower(), default)
    except Exception:
        return default

def coerce_protocol(value: str, default: Optional[str] = "Unavailable") -> Optional[str]:
    valid_protocols = {'tcp', 'udp', 'icmp', 'bgp'}
    try:
        str_value = str(value).lower()
        if str_value in valid_protocols:
            return str_value
        else:
            return default
    except (ValueError, TypeError):
        return default
        

def coerce_list(value, default=[]):
    if isinstance(value, list):
        return value
    elif value is None:
        return []
    return default if default is not None else []

def coerce_float(value, default: Optional[float] = 0.0) -> Optional[float]:
    try:
        if isinstance(value, float):
            return float(value)
    except (ValueError, TypeError):
        return default
        

# Fail Hard Helper
def  require_str(value, field_name) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Invalid or missing value for required field: {field_name}")
    return value