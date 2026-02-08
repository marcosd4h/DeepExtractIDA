"""
Configuration dataclass for PE binary analysis.

This module defines the AnalysisConfig dataclass that consolidates all configuration
parameters, replacing scattered argument dictionaries and global variables.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any
import json
import os


@dataclass
class AnalysisConfig:
    """Configuration for PE binary analysis.
    
    This dataclass consolidates all analysis configuration parameters, including
    file paths, extraction flags, and behavior settings. It replaces the previous
    approach of passing dictionaries and using global variables.
    
    Attributes:
        sqlite_db_path: Path to the SQLite database for analysis results
        input_file_path: Path to the PE binary being analyzed
        output_dir: Directory containing the SQLite database (computed)
        common_db_path: Path to the common tracking database (computed)
        idb_cache_path: Path to the IDA database cache file
        
        # Extraction flags
        extract_dangerous_apis: Whether to identify dangerous API calls
        extract_strings: Whether to extract string literals
        extract_stack_frame: Whether to analyze stack frames
        extract_globals: Whether to track global variable accesses
        analyze_loops: Whether to perform loop analysis
        extract_pe_info: Whether to extract PE version info
        extract_pe_metadata: Whether to extract PE metadata
        extract_advanced_pe: Whether to extract advanced PE info (Rich header, TLS)
        extract_runtime_info: Whether to extract runtime info (.NET, delay-load)
        generate_cpp: Whether to generate C++ output files
        
        # Behavior flags
        force_reanalyze: Force re-analysis even if already completed
        thunk_depth: Maximum depth for thunk resolution
        min_conf: Minimum confidence for function call validation
        
        # Computed file metadata
        file_hashes: MD5/SHA256 hashes of the input file
    """
    
    # Required paths
    sqlite_db_path: Path
    input_file_path: Path
    
    # Derived paths (computed in __post_init__)
    output_dir: Path = field(init=False)
    common_db_path: Path = field(init=False)
    idb_cache_path: Optional[str] = None
    
    # Extraction flags
    extract_dangerous_apis: bool = True
    extract_strings: bool = True
    extract_stack_frame: bool = True
    extract_globals: bool = True
    analyze_loops: bool = True
    extract_pe_info: bool = True
    extract_pe_metadata: bool = True
    extract_advanced_pe: bool = True
    extract_runtime_info: bool = True
    generate_cpp: bool = False
    cpp_output_dir: Optional[Path] = None  # Custom directory for C++ output (defaults to extracted_raw_code/ next to db)
    
    # Behavior flags
    force_reanalyze: bool = False
    thunk_depth: Optional[int] = None
    min_conf: Optional[int] = None
    
    # Advanced analysis options
    use_interprocedural_analysis: bool = True  # Enable deeper indirect call resolution

    # SQLite runtime behavior (applied on connection creation).
    # NOTE: These are intentionally NOT included in `to_dict()` / analysis_flags to
    # avoid forcing re-analysis just because DB tuning changed.
    sqlite_pragmas: Dict[str, Any] = field(default_factory=lambda: {
        "journal_mode": "WAL",
        "synchronous": "NORMAL",
        "cache_size": -2000000,
        "temp_store": "MEMORY",
        "busy_timeout_ms": 20000,
    })
    common_db_pragmas: Dict[str, Any] = field(default_factory=lambda: {
        "journal_mode": "WAL",
        "synchronous": "NORMAL",
        "cache_size": -2000000,
        "temp_store": "MEMORY",
        "busy_timeout_ms": 20000,
    })
    
    # Computed file metadata
    file_hashes: dict = field(default_factory=dict)
    
    def __post_init__(self):
        """
        Compute derived paths and validate configuration after initialization.
        
        Raises:
            ValueError: If configuration parameters are invalid
        """
        # Ensure paths are Path objects
        if not isinstance(self.sqlite_db_path, Path):
            self.sqlite_db_path = Path(self.sqlite_db_path)
        if not isinstance(self.input_file_path, Path):
            self.input_file_path = Path(self.input_file_path)
        
        # Validate paths exist (for input file)
        if not self.input_file_path.exists():
            raise ValueError(f"Input file does not exist: {self.input_file_path}")
        
        if not self.input_file_path.is_file():
            raise ValueError(f"Input path is not a file: {self.input_file_path}")
        
        # Validate thunk_depth if specified
        if self.thunk_depth is not None:
            if not isinstance(self.thunk_depth, int) or self.thunk_depth < 0:
                raise ValueError(f"thunk_depth must be a non-negative integer, got: {self.thunk_depth}")
            if self.thunk_depth > 100:  # Sanity check
                raise ValueError(f"thunk_depth seems unreasonably large: {self.thunk_depth}. Max recommended: 100")
        
        # Validate min_conf if specified
        if self.min_conf is not None:
            if not isinstance(self.min_conf, (int, float)):
                raise ValueError(f"min_conf must be a number, got: {type(self.min_conf)}")
            if not 10 <= self.min_conf <= 100:
                raise ValueError(f"min_conf must be between 10 and 100, got: {self.min_conf}")
        
        # Validate boolean flags
        bool_fields = [
            'extract_dangerous_apis', 'extract_strings', 'extract_stack_frame',
            'extract_globals', 'analyze_loops', 'extract_pe_info',
            'extract_pe_metadata', 'extract_advanced_pe', 'extract_runtime_info',
            'generate_cpp', 'force_reanalyze', 'use_interprocedural_analysis'
        ]
        for field_name in bool_fields:
            value = getattr(self, field_name)
            if not isinstance(value, bool):
                raise ValueError(f"{field_name} must be a boolean, got: {type(value)}")
        
        # Compute derived paths
        self.output_dir = self.sqlite_db_path.parent
        self.common_db_path = self.output_dir / 'analyzed_files.db'

        # Allow optional environment overrides for DB pragmas (JSON object).
        # These are best-effort and will be ignored if malformed.
        for env_name, attr_name in (
            ("EXTRACTOR_SQLITE_PRAGMAS_JSON", "sqlite_pragmas"),
            ("EXTRACTOR_COMMON_DB_PRAGMAS_JSON", "common_db_pragmas"),
        ):
            raw = os.environ.get(env_name)
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    setattr(self, attr_name, parsed)
            except Exception:
                # Keep defaults on parse errors
                pass

    def get_sqlite_pragmas(self) -> Dict[str, Any]:
        """PRAGMAs for per-binary analysis DB connections."""
        return dict(self.sqlite_pragmas or {})

    def get_common_db_pragmas(self) -> Dict[str, Any]:
        """PRAGMAs for the common tracking DB connections."""
        return dict(self.common_db_pragmas or {})
    
    @classmethod
    def from_ida_args(cls, args: dict, input_file: str) -> 'AnalysisConfig':
        """Factory method to create config from parsed IDA arguments.
        
        This method bridges the existing argument parsing system with the new
        configuration dataclass, providing backward compatibility.
        
        Includes path traversal prevention and argument sanitization.
        
        Args:
            args: Dictionary of validated arguments from validate_arguments()
            input_file: Path to the input PE file from ida_nalt.get_input_file_path()
        
        Returns:
            Configured AnalysisConfig instance
            
        Raises:
            ValueError: If arguments contain invalid or malicious paths
        """
        # Sanitize and validate paths to prevent path traversal attacks
        sqlite_db_path = Path(args['sqlite_db'])
        input_file_path = Path(input_file)
        
        # Resolve paths to absolute form and check for path traversal
        try:
            sqlite_db_path = sqlite_db_path.resolve()
            input_file_path = input_file_path.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid path resolution: {e}")
        
        # Check for suspicious path components
        suspicious_components = ['..', '~', '$', '`', ';', '|', '&', '>', '<']
        for component in suspicious_components:
            if component in str(sqlite_db_path) or component in str(input_file_path):
                raise ValueError(f"Suspicious path component detected: '{component}'. "
                               f"Paths must not contain shell metacharacters or traversal sequences.")
        
        # Validate input file exists
        if not input_file_path.exists():
            raise ValueError(f"Input file does not exist: {input_file_path}")
        
        # Validate thunk_depth if provided
        thunk_depth = args.get('thunk_depth')
        if thunk_depth is not None:
            try:
                thunk_depth = int(thunk_depth)
                if thunk_depth < 0 or thunk_depth > 100:
                    raise ValueError(f"thunk_depth must be 0-100, got: {thunk_depth}")
            except (TypeError, ValueError) as e:
                raise ValueError(f"Invalid thunk_depth: {e}")
        
        # Validate min_conf if provided
        # Note: argparse stores --min-call-conf as 'min_call_conf' (hyphens -> underscores)
        min_conf = args.get('min_call_conf') or args.get('min_conf')
        if min_conf is not None:
            try:
                min_conf = float(min_conf)
                if not 10 <= min_conf <= 100:
                    raise ValueError(f"min_conf must be 10-100, got: {min_conf}")
            except (TypeError, ValueError) as e:
                raise ValueError(f"Invalid min_conf: {e}")
        
        return cls(
            sqlite_db_path=sqlite_db_path,
            input_file_path=input_file_path,
            extract_dangerous_apis=bool(args.get('extract_dangerous_apis', True)),
            extract_strings=bool(args.get('extract_strings', True)),
            extract_stack_frame=bool(args.get('extract_stack_frame', True)),
            extract_globals=bool(args.get('extract_globals', True)),
            analyze_loops=bool(args.get('analyze_loops', True)),
            extract_pe_info=bool(args.get('extract_pe_info', True)),
            extract_pe_metadata=bool(args.get('extract_pe_metadata', True)),
            extract_advanced_pe=bool(args.get('extract_advanced_pe', True)),
            extract_runtime_info=bool(args.get('extract_runtime_info', True)),
            generate_cpp=bool(args.get('generate_cpp', False)),
            cpp_output_dir=Path(args['cpp_output_dir']) if args.get('cpp_output_dir') else None,
            force_reanalyze=bool(args.get('force_reanalyze', False)),
            use_interprocedural_analysis=bool(args.get('use_interprocedural_analysis', True)),
            thunk_depth=thunk_depth,
            min_conf=min_conf,
        )
    
    def to_dict(self) -> dict:
        """Convert config to dictionary for database storage.
        
        Returns a dictionary containing all configuration parameters,
        with paths converted to strings for JSON serialization.
        
        Returns:
            Dictionary of configuration parameters
        """
        return {
            'sqlite_db': str(self.sqlite_db_path),
            'extract_dangerous_apis': self.extract_dangerous_apis,
            'extract_strings': self.extract_strings,
            'extract_stack_frame': self.extract_stack_frame,
            'extract_globals': self.extract_globals,
            'analyze_loops': self.analyze_loops,
            'extract_pe_info': self.extract_pe_info,
            'extract_pe_metadata': self.extract_pe_metadata,
            'extract_advanced_pe': self.extract_advanced_pe,
            'extract_runtime_info': self.extract_runtime_info,
            'generate_cpp': self.generate_cpp,
            'force_reanalyze': self.force_reanalyze,
            'use_interprocedural_analysis': self.use_interprocedural_analysis,
            'thunk_depth': self.thunk_depth,
            'min_conf': self.min_conf,
        }
    
    def to_analysis_flags_json(self) -> str:
        """Serialize analysis flags to JSON for database storage.
        
        This creates a normalized JSON representation of the analysis flags,
        excluding volatile parameters like force_reanalyze. The JSON is sorted
        by keys for consistent comparison.
        
        Returns:
            JSON string of analysis flags
        """
        flags = self.to_dict()
        # Remove force_reanalyze for comparison purposes
        flags_normalized = {k: v for k, v in flags.items() if k != 'force_reanalyze'}
        return json.dumps(flags_normalized, sort_keys=True)
    
    def get_analysis_args_dict(self) -> dict:
        """Get analysis arguments in the format expected by extract_all_functions().
        
        Returns:
            Dictionary of analysis parameters for function extraction
        """
        return {
            'extract_dangerous_apis': self.extract_dangerous_apis,
            'extract_strings': self.extract_strings,
            'extract_stack_frame': self.extract_stack_frame,
            'extract_globals': self.extract_globals,
            'analyze_loops': self.analyze_loops,
            'force_reanalyze': self.force_reanalyze,
            'generate_cpp': self.generate_cpp,
        }

