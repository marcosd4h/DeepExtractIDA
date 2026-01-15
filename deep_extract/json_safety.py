"""
JSON serialization safety utilities for database storage.

This module handles JSON serialization with size bounds, type safety,
and guaranteed serializability to prevent database corruption and handle edge cases.
"""

import json
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
from decimal import Decimal

from .logging_utils import debug_print


# Default size limits (configurable per-field if needed)
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10MB per JSON field
DEFAULT_MAX_LIST_ITEMS = 10000        # Max items in a list before truncation
DEFAULT_MAX_DICT_KEYS = 5000          # Max keys in a dict before truncation
DEFAULT_MAX_STRING_LENGTH = 100000    # Max string length before truncation


class JSONSerializationError(Exception):
    """Raised when JSON serialization cannot be safely performed."""
    pass


def to_json_safe(obj: Any, 
                 max_bytes: Optional[int] = None,
                 max_list_items: Optional[int] = None,
                 max_dict_keys: Optional[int] = None,
                 max_string_length: Optional[int] = None,
                 drop_keys: Optional[Set[str]] = None,
                 truncate_lists: bool = True,
                 field_name: str = "unknown") -> str:
    """
    Converts an object to JSON with guaranteed serializability and size bounds.
    
    This function ensures:
    1. All data types are JSON-serializable
    2. Output size is bounded
    3. Metadata about truncation is recorded
    4. No exceptions escape (returns error JSON on failure)
    
    Args:
        obj: The object to serialize
        max_bytes: Maximum size of output JSON in bytes (default: 10MB)
        max_list_items: Maximum items in any list (default: 10000)
        max_dict_keys: Maximum keys in any dict (default: 5000)
        max_string_length: Maximum string length (default: 100000)
        drop_keys: Set of dictionary keys to exclude from serialization
        truncate_lists: Whether to truncate long lists (default: True)
        field_name: Name of the field being serialized (for logging)
        
    Returns:
        JSON string that is guaranteed to be within bounds
    """
    # Apply defaults
    if max_bytes is None:
        max_bytes = DEFAULT_MAX_BYTES
    if max_list_items is None:
        max_list_items = DEFAULT_MAX_LIST_ITEMS
    if max_dict_keys is None:
        max_dict_keys = DEFAULT_MAX_DICT_KEYS
    if max_string_length is None:
        max_string_length = DEFAULT_MAX_STRING_LENGTH
    if drop_keys is None:
        drop_keys = set()
    
    try:
        # Track metadata about transformations
        metadata = {
            'truncated': False,
            'original_size': None,
            'transformations': []
        }
        
        # Make object serializable
        serializable_obj = _make_serializable(obj, max_list_items, max_dict_keys, 
                                             max_string_length, drop_keys, metadata, 0, truncate_lists)
        
        # Add metadata if any truncation occurred.
        # IMPORTANT: Preserve top-level JSON types for schema stability:
        # - dict stays dict (we can inject a metadata key)
        # - list stays list (we append a metadata sentinel item)
        if metadata['truncated']:
            if isinstance(serializable_obj, dict):
                serializable_obj['_serialization_metadata'] = {
                    'truncated': True,
                    'transformations': metadata['transformations']
                }
            elif isinstance(serializable_obj, list):
                serializable_obj.append({
                    "_serialization_metadata": {
                        "truncated": True,
                        "transformations": metadata["transformations"],
                    }
                })
        
        # Serialize to JSON
        json_str = json.dumps(serializable_obj, ensure_ascii=False, sort_keys=True)
        
        # Check size bounds
        json_bytes = len(json_str.encode('utf-8'))
        if json_bytes > max_bytes:
            metadata['original_size'] = json_bytes
            metadata['truncated'] = True
            
            # Try progressive truncation strategies
            if isinstance(serializable_obj, dict):
                # Strategy 1: Remove large fields
                serializable_obj = _truncate_large_dict_fields(serializable_obj, max_bytes)
                json_str = json.dumps(serializable_obj, ensure_ascii=False, sort_keys=True)
                json_bytes = len(json_str.encode('utf-8'))
            
            if json_bytes > max_bytes:
                # Strategy 2: Aggressive truncation
                warning_msg = (f"Field '{field_name}' exceeded max size ({json_bytes} > {max_bytes} bytes). "
                              f"Truncating to prevent database corruption.")
                debug_print(f"WARNING - {warning_msg}")
                
                # Create minimal error object
                error_obj = {
                    '_error': 'size_limit_exceeded',
                    'original_size_bytes': json_bytes,
                    'max_bytes': max_bytes,
                    'field_name': field_name,
                    'message': warning_msg
                }
                json_str = json.dumps(error_obj)
        
        return json_str
        
    except Exception as e:
        # Last resort: return error JSON
        import traceback
        error_json = {
            '_error': 'serialization_failed',
            'field_name': field_name,
            'error_message': str(e),
            'error_type': type(e).__name__
        }
        debug_print(f"ERROR - Failed to serialize field '{field_name}': {str(e)}")
        debug_print(traceback.format_exc())
        return json.dumps(error_json)


def _make_serializable(obj: Any, max_list_items: int, max_dict_keys: int,
                      max_string_length: int, drop_keys: Set[str],
                      metadata: Dict[str, Any], depth: int = 0, truncate_lists: bool = True) -> Any:
    """
    Recursively makes an object JSON-serializable with bounds checking.
    
    Args:
        obj: Object to make serializable
        max_list_items: Maximum list items
        max_dict_keys: Maximum dict keys
        max_string_length: Maximum string length
        drop_keys: Keys to drop
        metadata: Metadata dict to track transformations (modified in-place)
        depth: Current recursion depth (for cycle detection)
        truncate_lists: Whether to truncate lists to max_list_items
        
    Returns:
        A JSON-serializable object
    """
    # Prevent infinite recursion
    MAX_DEPTH = 50
    if depth > MAX_DEPTH:
        metadata['truncated'] = True
        metadata['transformations'].append(f'max_depth_exceeded_at_{depth}')
        return "<max_recursion_depth_exceeded>"
    
    # Handle None and basic types first (most common case)
    if obj is None or isinstance(obj, (str, int, float, bool)):
        if isinstance(obj, str) and len(obj) > max_string_length:
            metadata['truncated'] = True
            metadata['transformations'].append(f'string_truncated_from_{len(obj)}_to_{max_string_length}')
            return obj[:max_string_length] + "...[TRUNCATED]"
        return obj
    
    # Handle dictionaries
    if isinstance(obj, dict):
        result = {}
        keys_processed = 0
        
        for k, v in obj.items():
            # Skip keys in drop list
            if k in drop_keys:
                continue
            
            # Enforce key limit
            if keys_processed >= max_dict_keys:
                metadata['truncated'] = True
                metadata['transformations'].append(f'dict_keys_truncated_from_{len(obj)}_to_{max_dict_keys}')
                result['_truncated_keys'] = len(obj) - keys_processed
                break
            
            # Ensure key is string
            key_str = str(k) if not isinstance(k, str) else k
            
            # Recursively process value
            result[key_str] = _make_serializable(v, max_list_items, max_dict_keys,
                                                max_string_length, drop_keys, metadata, depth + 1, truncate_lists)
            keys_processed += 1
        
        return result
    
    # Handle lists and tuples
    elif isinstance(obj, (list, tuple)):
        result = []
        original_len = len(obj)
        
        # Enforce list size limit
        items_to_process = min(len(obj), max_list_items) if truncate_lists else len(obj)
        
        for i in range(items_to_process):
            result.append(_make_serializable(obj[i], max_list_items, max_dict_keys,
                                           max_string_length, drop_keys, metadata, depth + 1, truncate_lists))
        
        if original_len > max_list_items and truncate_lists:
            metadata['truncated'] = True
            metadata['transformations'].append(f'list_truncated_from_{original_len}_to_{max_list_items}')
            # Add metadata about truncation
            result.append({
                '_truncated': True,
                'original_count': original_len,
                'shown_count': len(result)
            })
        
        return result
    
    # Handle sets
    elif isinstance(obj, set):
        # Convert to sorted list for consistency
        return _make_serializable(sorted(list(obj), key=str), max_list_items, max_dict_keys,
                                 max_string_length, drop_keys, metadata, depth + 1, truncate_lists)
    
    # Handle bytes
    elif isinstance(obj, (bytes, bytearray)):
        try:
            # Try to decode as UTF-8 first
            decoded = obj.decode('utf-8')
            if len(decoded) > max_string_length:
                metadata['truncated'] = True
                decoded = decoded[:max_string_length] + "...[TRUNCATED]"
            return decoded
        except UnicodeDecodeError:
            # Fall back to hex representation
            hex_str = obj.hex().upper()
            if len(hex_str) > max_string_length:
                metadata['truncated'] = True
                metadata['transformations'].append(f'bytes_hex_truncated_from_{len(hex_str)}_to_{max_string_length}')
                hex_str = hex_str[:max_string_length] + "...[TRUNCATED]"
            return f"<hex:{hex_str}>"
    
    # Handle datetime objects
    elif isinstance(obj, datetime):
        return obj.isoformat()
    
    # Handle Decimal (for precise numeric values)
    elif isinstance(obj, Decimal):
        return float(obj)
    
    # Handle complex numbers
    elif isinstance(obj, complex):
        return {"real": obj.real, "imag": obj.imag, "_type": "complex"}
    
    # Handle numpy arrays (if numpy is available)
    try:
        import numpy as np
        if isinstance(obj, np.ndarray):
            # Convert to list but respect size limits
            as_list = obj.tolist()
            return _make_serializable(as_list, max_list_items, max_dict_keys,
                                    max_string_length, drop_keys, metadata, depth + 1, truncate_lists)
        elif isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        elif isinstance(obj, np.bool_):
            return bool(obj)
    except ImportError:
        pass
    except Exception:
        # If numpy operations fail, continue to other handlers
        pass
    
    # Handle custom IDA types
    try:
        # IDA Pro types that might appear in metadata
        if hasattr(obj, '__class__') and obj.__class__.__module__.startswith('ida_'):
            # Try to extract relevant attributes
            if hasattr(obj, 'value'):
                return _make_serializable(obj.value, max_list_items, max_dict_keys,
                                        max_string_length, drop_keys, metadata, depth + 1, truncate_lists)
            elif hasattr(obj, '__int__'):
                return int(obj)
            elif hasattr(obj, '__str__'):
                return str(obj)
    except Exception:
        pass
    
    # Handle objects with __dict__ (custom classes)
    if hasattr(obj, '__dict__'):
        try:
            return _make_serializable(obj.__dict__, max_list_items, max_dict_keys,
                                    max_string_length, drop_keys, metadata, depth + 1, truncate_lists)
        except Exception:
            return str(obj)
    
    # Handle enums
    try:
        from enum import Enum
        if isinstance(obj, Enum):
            return obj.value
    except ImportError:
        pass
    
    # Fallback to string representation
    try:
        str_repr = str(obj)
        if len(str_repr) > max_string_length:
            metadata['truncated'] = True
            str_repr = str_repr[:max_string_length] + "...[TRUNCATED]"
        return str_repr
    except Exception:
        return f"<unserializable: {type(obj).__name__}>"


def _truncate_large_dict_fields(obj: dict, target_bytes: int) -> dict:
    """
    Progressively removes largest fields from a dict until size is under target.
    
    Args:
        obj: Dictionary to truncate
        target_bytes: Target size in bytes
        
    Returns:
        Truncated dictionary
    """
    # Calculate field sizes
    field_sizes = []
    for key, value in obj.items():
        try:
            field_json = json.dumps({key: value})
            field_size = len(field_json.encode('utf-8'))
            field_sizes.append((key, field_size, value))
        except:
            # If we can't serialize this field, it's a good candidate for removal
            field_sizes.append((key, sys.maxsize, value))
    
    # Sort by size (descending)
    field_sizes.sort(key=lambda x: x[1], reverse=True)
    
    # Rebuild dict, skipping largest fields until we're under target
    result = {}
    removed_fields = []
    current_size = 0
    
    for key, size, value in reversed(field_sizes):  # Process smallest first
        test_dict = result.copy()
        test_dict[key] = value
        
        try:
            test_json = json.dumps(test_dict)
            test_size = len(test_json.encode('utf-8'))
            
            if test_size <= target_bytes:
                result[key] = value
                current_size = test_size
            else:
                removed_fields.append(key)
        except:
            removed_fields.append(key)
    
    # Add metadata about removed fields
    if removed_fields:
        result['_removed_fields'] = {
            'count': len(removed_fields),
            'fields': removed_fields[:20],  # Show first 20
            'reason': 'size_limit_exceeded'
        }
    
    return result


def validate_json_field(json_str: str, field_name: str, max_bytes: int = DEFAULT_MAX_BYTES) -> Tuple[bool, Optional[str]]:
    """
    Validates that a JSON string meets safety requirements.
    
    Args:
        json_str: The JSON string to validate
        field_name: Name of the field (for error messages)
        max_bytes: Maximum allowed size in bytes
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Check size
        size_bytes = len(json_str.encode('utf-8'))
        if size_bytes > max_bytes:
            return False, f"Field '{field_name}' exceeds size limit: {size_bytes} > {max_bytes} bytes"
        
        # Validate it's parseable
        parsed = json.loads(json_str)
        
        # Check for problematic patterns
        if isinstance(parsed, dict):
            if len(parsed) > DEFAULT_MAX_DICT_KEYS:
                return False, f"Field '{field_name}' has too many keys: {len(parsed)}"
        elif isinstance(parsed, list):
            if len(parsed) > DEFAULT_MAX_LIST_ITEMS:
                return False, f"Field '{field_name}' has too many items: {len(parsed)}"
        
        return True, None
        
    except json.JSONDecodeError as e:
        return False, f"Field '{field_name}' is not valid JSON: {str(e)}"
    except Exception as e:
        return False, f"Field '{field_name}' validation error: {str(e)}"


def safe_json_dumps(obj: Any, field_name: str = "unknown", **kwargs) -> str:
    """
    Wrapper around json.dumps with automatic safety handling.
    
    Args:
        obj: Object to serialize
        field_name: Field name for logging
        **kwargs: Additional arguments passed to to_json_safe
        
    Returns:
        Safe JSON string
    """
    return to_json_safe(obj, field_name=field_name, **kwargs)


def create_truncation_summary(original_count: int, shown_count: int, item_type: str) -> Dict[str, Any]:
    """
    Creates a standardized truncation summary object.
    
    Args:
        original_count: Original number of items
        shown_count: Number of items shown after truncation
        item_type: Type of items (e.g., "xrefs", "strings", "methods")
        
    Returns:
        Truncation summary dictionary
    """
    # Validate inputs to prevent negative percentages
    if original_count < 0 or shown_count < 0:
        debug_print(f"WARNING - Invalid truncation counts: original={original_count}, shown={shown_count}")
        original_count = max(0, original_count)
        shown_count = max(0, shown_count)
    
    # Ensure shown_count doesn't exceed original_count
    if shown_count > original_count:
        debug_print(f"WARNING - shown_count ({shown_count}) exceeds original_count ({original_count}), capping to original")
        shown_count = original_count
    
    return {
        '_truncated': True,
        'original_count': original_count,
        'shown_count': shown_count,
        'item_type': item_type,
        'truncation_percentage': round((1 - shown_count / original_count) * 100, 2) if original_count > 0 else 0
    }


def apply_field_limits(xref_list: List[Any], max_xrefs: int = 5000) -> List[Any]:
    """
    Applies limits to cross-reference lists to prevent unbounded growth.
    
    Args:
        xref_list: List of xref objects
        max_xrefs: Maximum number of xrefs to keep
        
    Returns:
        Potentially truncated xref list with metadata
    """
    if len(xref_list) <= max_xrefs:
        return xref_list
    
    # Truncate and add summary
    truncated_list = xref_list[:max_xrefs]
    truncated_list.append(create_truncation_summary(len(xref_list), max_xrefs, "xrefs"))
    
    debug_print(f"WARNING - Truncated xref list from {len(xref_list)} to {max_xrefs} entries")
    return truncated_list


# Convenience functions for common field types
def safe_serialize_xrefs(xrefs: List[Dict[str, Any]], field_name: str = "xrefs") -> str:
    """Safely serialize cross-reference list."""
    # Apply xref-specific limits
    limited_xrefs = apply_field_limits(xrefs, max_xrefs=5000)
    return to_json_safe(limited_xrefs, field_name=field_name)


def safe_serialize_strings(strings: List[str], field_name: str = "strings") -> str:
    """Safely serialize string list."""
    return to_json_safe(strings, max_list_items=2000, field_name=field_name)


def safe_serialize_vtable_contexts(contexts: List[Dict[str, Any]], field_name: str = "vtable_contexts") -> str:
    """Safely serialize vtable contexts."""
    return to_json_safe(contexts, max_list_items=100, field_name=field_name)


def safe_serialize_loop_analysis(loop_data: Dict[str, Any], field_name: str = "loop_analysis") -> str:
    """Safely serialize loop analysis data."""
    return to_json_safe(loop_data, max_list_items=500, field_name=field_name)


__all__ = [
    'JSONSerializationError',
    'to_json_safe',
    'validate_json_field',
    'safe_json_dumps',
    'create_truncation_summary',
    'apply_field_limits',
    'safe_serialize_xrefs',
    'safe_serialize_strings',
    'safe_serialize_vtable_contexts',
    'safe_serialize_loop_analysis',
    'DEFAULT_MAX_BYTES',
    'DEFAULT_MAX_LIST_ITEMS',
    'DEFAULT_MAX_DICT_KEYS',
    'DEFAULT_MAX_STRING_LENGTH',
]
