"""
GUI Configuration Dialog for DeepExtract Plugin

This module provides an interactive dialog for configuring analysis options
when running DeepExtract from IDA Pro's GUI.
"""

import os
from pathlib import Path

# IDA Pro imports
import ida_kernwin
import ida_nalt

# Local imports
try:
    from .config import AnalysisConfig
    from .logging_utils import debug_print
except ImportError:
    from config import AnalysisConfig
    from logging_utils import debug_print


class DeepExtractConfigDialog(ida_kernwin.Form):
    """
    Interactive configuration dialog for DeepExtract analysis.
    
    This dialog allows users to configure:
    - Output paths (SQLite database, C++ code directory)
    - Analysis features (dangerous APIs, strings, stack frames, etc.)
    - PE metadata extraction options
    - Advanced settings (thunk depth, confidence thresholds)
    """
    
    def __init__(self, default_db_path: str, default_cpp_path: str):
        """
        Initialize the configuration dialog.
        
        Args:
            default_db_path: Default path for SQLite database output
            default_cpp_path: Default path for C++ code output directory
        """
        F = ida_kernwin.Form
        
        # Initialize form with layout and controls
        F.__init__(
            self,
            r"""STARTITEM {id:iDbPath}
DeepExtract - Analysis Configuration

{FormChangeCb}
<#Path to output SQLite database#SQLite Database:{iDbPath}>
<#Directory for C++ code output (enabled when Generate C++ is checked)#C++ Output Dir:{iCppPath}>

<##Analysis Features##Extract dangerous API calls:{chkDangerousApis}>
<Extract string literals:{chkStrings}>
<Extract stack frame info:{chkStackFrame}>
<Extract global variables:{chkGlobals}>
<Analyze loops (Tarjan's algorithm):{chkLoops}>{cAnalysisGroup}>

<##PE Metadata##Extract PE version info:{chkPeInfo}>
<Extract PE metadata (imports/exports/sections):{chkPeMetadata}>
<Extract advanced PE (Rich header, TLS callbacks):{chkAdvancedPe}>
<Extract runtime info (.NET, delay-load):{chkRuntimeInfo}>{cPeGroup}>

<##Output Options##Generate C++ files for AI review:{chkGenerateCpp}>{cOutputGroup}>

<Thunk Depth (1-50):{iThunkDepth}>
<Min Confidence (10-100):{iMinConf}>
""", {
                'FormChangeCb': F.FormChangeCb(self.OnFormChange),
                
                # Output paths
                'iDbPath': F.FileInput(swidth=60, save=True, value=default_db_path),
                'iCppPath': F.DirInput(swidth=60, value=default_cpp_path),
                
                # Analysis features group (all default to checked = 0x1F = bits 0-4 set)
                'cAnalysisGroup': F.ChkGroupControl((
                    "chkDangerousApis",
                    "chkStrings", 
                    "chkStackFrame",
                    "chkGlobals",
                    "chkLoops"
                ), value=0x1F),
                
                # PE metadata group (all default to checked = 0x0F = bits 0-3 set)
                'cPeGroup': F.ChkGroupControl((
                    "chkPeInfo",
                    "chkPeMetadata",
                    "chkAdvancedPe",
                    "chkRuntimeInfo"
                ), value=0x0F),
                
                # Output options (default unchecked)
                'cOutputGroup': F.ChkGroupControl((
                    "chkGenerateCpp",
                ), value=0x00),
                
                # Advanced numeric inputs
                'iThunkDepth': F.NumericInput(tp=F.FT_DEC, value=10, swidth=10, width=50),
                'iMinConf': F.NumericInput(tp=F.FT_DEC, value=70, swidth=10, width=50),
            }
        )
        
        self.default_cpp_path = default_cpp_path
    
    def OnFormChange(self, fid):
        """
        Handle form control changes.
        
        This callback is triggered when form controls change state.
        We use it to enable/disable the C++ output path based on the
        "Generate C++" checkbox.
        
        Args:
            fid: Field ID that changed (-1 = init, -2 = OK button)
        
        Returns:
            1 to continue, 0 to reject change
        """
        # Form initialization
        if fid == -1:
            # Disable C++ path initially since Generate C++ is unchecked
            self.EnableField(self.iCppPath, False)
            return 1
        
        # OK button clicked - validate before accepting
        elif fid == -2:
            # Validate database path
            db_path = self.GetControlValue(self.iDbPath)
            if not db_path:
                ida_kernwin.warning("Please specify a SQLite database path.")
                return 0
            
            # Validate thunk depth
            thunk_depth = self.GetControlValue(self.iThunkDepth)
            if thunk_depth is None or thunk_depth < 1 or thunk_depth > 50:
                ida_kernwin.warning("Thunk depth must be between 1 and 50.")
                return 0
            
            # Validate min confidence
            min_conf = self.GetControlValue(self.iMinConf)
            if min_conf is None or min_conf < 10 or min_conf > 100:
                ida_kernwin.warning("Minimum confidence must be between 10 and 100.")
                return 0
            
            # If Generate C++ is checked, validate C++ path
            output_flags = self.GetControlValue(self.cOutputGroup)
            if output_flags and (output_flags & 1):
                cpp_path = self.GetControlValue(self.iCppPath)
                if not cpp_path:
                    ida_kernwin.warning("Please specify a C++ output directory when 'Generate C++' is enabled.")
                    return 0
            
            return 1
        
        # Output options group changed (includes Generate C++ checkbox)
        elif fid == self.cOutputGroup.id:
            output_flags = self.GetControlValue(self.cOutputGroup)
            is_checked = bool(output_flags and (output_flags & 1))
            self.EnableField(self.iCppPath, is_checked)
            return 1
        
        return 1
    
    def get_config(self, input_file_path: str) -> AnalysisConfig:
        """
        Build an AnalysisConfig object from the dialog values.
        
        This method should be called AFTER Execute() returns successfully.
        It accesses control values via the .value property (SDK pattern).
        
        Args:
            input_file_path: Path to the input binary being analyzed
        
        Returns:
            AnalysisConfig object populated with user selections
        """
        # Get output paths - access via .value property after Execute()
        db_path = self.iDbPath.value if self.iDbPath.value else ""
        
        # Get analysis feature flags from group value (bitmask)
        analysis_flags = self.cAnalysisGroup.value
        extract_dangerous_apis = bool(analysis_flags & 0x01)
        extract_strings = bool(analysis_flags & 0x02)
        extract_stack_frame = bool(analysis_flags & 0x04)
        extract_globals = bool(analysis_flags & 0x08)
        analyze_loops = bool(analysis_flags & 0x10)
        
        # Get PE metadata flags from group value (bitmask)
        pe_flags = self.cPeGroup.value
        extract_pe_info = bool(pe_flags & 0x01)
        extract_pe_metadata = bool(pe_flags & 0x02)
        extract_advanced_pe = bool(pe_flags & 0x04)
        extract_runtime_info = bool(pe_flags & 0x08)
        
        # Get output options from group value
        output_flags = self.cOutputGroup.value
        generate_cpp = bool(output_flags & 0x01)
        
        # Get advanced options via .value property
        thunk_depth = self.iThunkDepth.value
        min_conf = self.iMinConf.value
        
        # Build config object (matches AnalysisConfig dataclass signature)
        config = AnalysisConfig(
            sqlite_db_path=Path(db_path),
            input_file_path=Path(input_file_path),
            
            # Analysis features
            extract_dangerous_apis=extract_dangerous_apis,
            extract_strings=extract_strings,
            extract_stack_frame=extract_stack_frame,
            extract_globals=extract_globals,
            analyze_loops=analyze_loops,
            
            # PE metadata
            extract_pe_info=extract_pe_info,
            extract_pe_metadata=extract_pe_metadata,
            extract_advanced_pe=extract_advanced_pe,
            extract_runtime_info=extract_runtime_info,
            
            # Output options
            generate_cpp=generate_cpp,
            
            # Advanced options
            thunk_depth=thunk_depth,
            min_conf=min_conf,
            
            # GUI mode specific
            force_reanalyze=True,
        )
        
        return config


def show_config_dialog() -> AnalysisConfig:
    """
    Display the configuration dialog and return the user's configuration.
    
    This is the main entry point for GUI mode. It:
    1. Gets the current binary path from IDA
    2. Generates sensible default paths
    3. Shows the dialog
    4. Returns the configuration if user clicked OK, None if cancelled
    
    Returns:
        AnalysisConfig object if user clicked OK, None if cancelled
    """
    # Get the input file path from IDA
    input_file = ida_nalt.get_input_file_path()
    if not input_file:
        ida_kernwin.warning("No binary is currently open in IDA.")
        return None
    
    input_path = Path(input_file)
    
    # Generate default paths
    # SQLite DB: same directory as binary, with .analysis.db extension
    default_db_path = str(input_path.with_suffix(input_path.suffix + '.analysis.db'))
    
    # C++ output: extracted_code subdirectory in binary's directory
    default_cpp_path = str(input_path.parent / 'extracted_code')
    
    debug_print(f"Opening configuration dialog for: {input_file}")
    debug_print(f"Default DB path: {default_db_path}")
    debug_print(f"Default C++ path: {default_cpp_path}")
    
    # Create and compile the dialog
    dialog = DeepExtractConfigDialog(default_db_path, default_cpp_path)
    dialog.Compile()
    
    # Execute the dialog (modal)
    ok = dialog.Execute()
    
    if ok == 1:
        # User clicked OK - build config from dialog values
        debug_print("User confirmed configuration")
        config = dialog.get_config(input_file)
        dialog.Free()
        return config
    else:
        # User cancelled
        debug_print("User cancelled configuration dialog")
        dialog.Free()
        return None
