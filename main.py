r"""
DeepExtract IDA Pro Plugin - Main Entry Point

This plugin provides PE binary analysis and context extraction for AI-driven
vulnerability research. It supports both headless (command-line) and interactive
(GUI) modes.

Headless Usage:
    idat.exe -A -S"main.py --sqlite-db C:\out\test.db" "C:\target.dll"

Interactive Usage:
    Open binary in IDA GUI -> Edit -> Plugins -> DeepExtract
"""

import sys
from pathlib import Path

# IDA Pro imports
try:
    import ida_idaapi
    import ida_kernwin
    import ida_nalt
    import ida_pro
    import idc
except ImportError as e:
    print(f"ERROR: Failed to import IDA modules: {e}")
    print("This plugin must be run within IDA Pro 9.x or later")
    sys.exit(1)

# Deep Extract package imports
# Handle both installed plugin and development scenarios
try:
    from deep_extract import (
        AnalysisConfig,
        debug_print,
        set_log_level,
        show_config_dialog,
    )
    from deep_extract.pe_context_extractor import (
        run_analysis_pipeline,
        parse_arguments,
        validate_arguments,
    )
except ImportError:
    # Fallback for development: add parent directory to path
    _script_dir = Path(__file__).resolve().parent
    if str(_script_dir) not in sys.path:
        sys.path.insert(0, str(_script_dir))
    
    try:
        from deep_extract import (
            AnalysisConfig,
            debug_print,
            set_log_level,
            show_config_dialog,
        )
        from deep_extract.pe_context_extractor import (
            run_analysis_pipeline,
            parse_arguments,
            validate_arguments,
        )
    except ImportError as e:
        print(f"ERROR: Failed to import deep_extract package: {e}")
        print(f"Script directory: {_script_dir}")
        print(f"Python path: {sys.path}")
        sys.exit(1)


class DeepExtractModule(ida_idaapi.plugmod_t):
    """
    Plugin module implementing per-database state and execution logic.
    
    This class inherits from plugmod_t to follow IDA 9.x plugin architecture,
    enabling proper lifecycle management and multi-database support.
    """
    
    def __init__(self):
        """Initialize the plugin module instance."""
        super().__init__()
        debug_print("DeepExtract plugin module initialized")
    
    def __del__(self):
        """Cleanup when the plugin module is destroyed."""
        debug_print("DeepExtract plugin module destroyed")
    
    def run(self, arg: int) -> int:
        """
        Main plugin execution method.
        
        This method is called when the plugin is invoked, either automatically
        in headless mode or via the menu/hotkey in GUI mode.
        
        Args:
            arg: Plugin argument (typically 0 for default invocation)
            
        Returns:
            0 on success, non-zero on failure
        """
        try:
            # Detect execution mode based on command-line arguments
            if self._has_headless_args():
                return self._run_headless_mode()
            else:
                return self._run_gui_mode()
        except Exception as e:
            debug_print(f"ERROR - Plugin execution failed: {str(e)}")
            import traceback
            debug_print(traceback.format_exc())
            return 1
    
    def _has_headless_args(self) -> bool:
        """
        Check if the script was invoked with headless command-line arguments.
        
        In headless mode, arguments are passed via IDA's -S flag and appear
        in idc.ARGV. The presence of --sqlite-db indicates headless execution.
        
        Returns:
            True if headless arguments are present, False otherwise
        """
        try:
            # idc.ARGV[0] is the script path, [1:] are user arguments
            argv = idc.ARGV if hasattr(idc, 'ARGV') else []
            
            # Check for the required --sqlite-db argument
            if len(argv) > 1:
                for arg in argv[1:]:
                    if isinstance(arg, str) and arg.startswith('--sqlite-db'):
                        return True
            
            return False
        except Exception as e:
            debug_print(f"WARNING - Error checking for headless args: {e}")
            return False
    
    def _run_headless_mode(self) -> int:
        """
        Execute the plugin in headless (non-interactive) mode.
        
        This mode is triggered when the script is invoked via IDA's -S flag
        with command-line arguments. It performs the full analysis pipeline
        and exits IDA upon completion.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        return_code = 1
        
        try:
            debug_print("=" * 80)
            debug_print("DeepExtract - Headless Mode")
            debug_print("=" * 80)
            
            # Parse command-line arguments
            args = parse_arguments()
            if not args:
                debug_print("ERROR - Failed to parse command-line arguments")
                return 1
            
            # Validate arguments
            validated_args = validate_arguments(args)
            if not validated_args:
                debug_print("ERROR - Argument validation failed")
                return 1
            
            # Get the input file path from IDA
            input_file = ida_nalt.get_input_file_path()
            if not input_file:
                debug_print("ERROR - Could not determine input file path")
                return 1
            
            # Create configuration
            try:
                config = AnalysisConfig.from_ida_args(validated_args, input_file)
            except Exception as e:
                debug_print(f"ERROR - Failed to create configuration: {e}")
                return 1
            
            # Apply optional configuration overrides
            if config.thunk_depth:
                from deep_extract import set_max_thunk_depth
                set_max_thunk_depth(config.thunk_depth)
                debug_print(f"Set thunk depth to: {config.thunk_depth}")
            
            if config.min_conf:
                from deep_extract import set_min_validation_conf
                set_min_validation_conf(config.min_conf)
                debug_print(f"Set min validation confidence to: {config.min_conf}")
            
            # Run the analysis pipeline
            debug_print("Starting analysis pipeline...")
            return_code = run_analysis_pipeline(config)
            
            if return_code == 0:
                debug_print("=" * 80)
                debug_print("Analysis completed successfully")
                debug_print("=" * 80)
            else:
                debug_print("=" * 80)
                debug_print("Analysis completed with errors")
                debug_print("=" * 80)
        
        except Exception as e:
            debug_print(f"ERROR - Headless execution failed: {str(e)}")
            import traceback
            debug_print(traceback.format_exc())
            return_code = 1
        
        finally:
            # In headless mode, we must exit IDA after completion
            # This is critical for batch processing workflows
            debug_print(f"Exiting IDA with code: {return_code}")
            ida_pro.qexit(return_code)
        
        return return_code
    
    def _run_gui_mode(self) -> int:
        """
        Execute the plugin in interactive (GUI) mode.
        
        This mode is triggered when the user manually invokes the plugin
        from IDA's menu or via a hotkey. It displays a configuration dialog
        and runs the analysis pipeline based on user selections.
        
        Returns:
            0 on success, 1 on failure or cancellation
        """
        try:
            debug_print("=" * 80)
            debug_print("DeepExtract - Interactive GUI Mode")
            debug_print("=" * 80)
            
            # Check if we have a valid database open
            input_file = ida_nalt.get_input_file_path()
            if not input_file:
                ida_kernwin.warning(
                    "DeepExtract: No database is open.\n\n"
                    "Please open a binary file first."
                )
                return 1
            
            debug_print(f"Input file: {input_file}")
            
            # Show configuration dialog
            config = show_config_dialog()
            
            if config is None:
                # User cancelled the dialog
                debug_print("Analysis cancelled by user")
                return 1
            
            # Display configuration summary
            debug_print("=" * 80)
            debug_print("Starting analysis with configuration:")
            debug_print(f"  SQLite DB: {config.sqlite_db_path}")
            if config.generate_cpp:
                debug_print(f"  C++ Output: {config.output_dir}")
            debug_print(f"  Dangerous APIs: {config.extract_dangerous_apis}")
            debug_print(f"  Strings: {config.extract_strings}")
            debug_print(f"  Stack Frames: {config.extract_stack_frame}")
            debug_print(f"  Globals: {config.extract_globals}")
            debug_print(f"  Loops: {config.analyze_loops}")
            debug_print(f"  PE Info: {config.extract_pe_info}")
            debug_print(f"  PE Metadata: {config.extract_pe_metadata}")
            debug_print(f"  Advanced PE: {config.extract_advanced_pe}")
            debug_print(f"  Runtime Info: {config.extract_runtime_info}")
            debug_print(f"  Generate C++: {config.generate_cpp}")
            debug_print(f"  Thunk Depth: {config.thunk_depth}")
            debug_print(f"  Min Confidence: {config.min_conf}")
            debug_print("=" * 80)
            
            # Apply optional configuration overrides
            if config.thunk_depth:
                from deep_extract import set_max_thunk_depth
                set_max_thunk_depth(config.thunk_depth)
                debug_print(f"Set thunk depth to: {config.thunk_depth}")
            
            if config.min_conf:
                from deep_extract import set_min_validation_conf
                set_min_validation_conf(config.min_conf)
                debug_print(f"Set min validation confidence to: {config.min_conf}")
            
            # Show a "working" message
            ida_kernwin.show_wait_box("DeepExtract is analyzing...\nThis may take several minutes.")
            
            try:
                # Run the analysis pipeline
                debug_print("Starting analysis pipeline...")
                return_code = run_analysis_pipeline(config)
                
                if return_code == 0:
                    debug_print("=" * 80)
                    debug_print("Analysis completed successfully")
                    debug_print("=" * 80)
                    
                    # Show success message
                    ida_kernwin.hide_wait_box()
                    ida_kernwin.info(
                        f"DeepExtract Analysis Complete!\n\n"
                        f"Results saved to:\n"
                        f"  {config.sqlite_db_path}\n\n"
                        f"{'C++ files generated in:\n  ' + str(config.output_dir) if config.generate_cpp else ''}"
                    )
                else:
                    debug_print("=" * 80)
                    debug_print("Analysis completed with errors")
                    debug_print("=" * 80)
                    
                    ida_kernwin.hide_wait_box()
                    ida_kernwin.warning(
                        f"DeepExtract encountered errors during analysis.\n\n"
                        f"Check the IDA Output window for details.\n\n"
                        f"Partial results may be available in:\n"
                        f"  {config.sqlite_db_path}"
                    )
                
                return return_code
            
            finally:
                # Always hide wait box
                ida_kernwin.hide_wait_box()
        
        except Exception as e:
            debug_print(f"ERROR - GUI mode failed: {str(e)}")
            import traceback
            debug_print(traceback.format_exc())
            
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"DeepExtract GUI Error:\n\n{str(e)}")
            return 1


class DeepExtractPlugin(ida_idaapi.plugin_t):
    """
    Plugin factory class defining plugin metadata and initialization.
    
    This class inherits from plugin_t and serves as the entry point for
    IDA's plugin system. It creates and returns the plugin module instance.
    """
    
    # Plugin flags
    flags = ida_idaapi.PLUGIN_MULTI  # Support multiple instances (per-database)
    
    # Plugin metadata
    comment = "PE Context Extraction for AI-driven Vulnerability Research"
    help = (
        "DeepExtract - Headless PE Analysis Framework\n\n"
        "Extracts comprehensive binary context into structured SQLite databases.\n"
        "Supports both headless batch processing and interactive analysis.\n\n"
        "Headless usage:\n"
        '  idat.exe -A -S"main.py --sqlite-db <output.db>" "<binary>"\n\n'
        "For more information, see: https://github.com/StagerLabs/DeepExtractIDA"
    )
    wanted_name = "DeepExtract"
    wanted_hotkey = "Ctrl-Shift-E"  # Optional hotkey for GUI invocation
    
    def init(self):
        """
        Initialize the plugin and create the plugin module instance.
        
        This method is called once when IDA loads the plugin. It performs
        environment checks and returns a plugin module instance if the
        plugin should be loaded.
        
        Returns:
            DeepExtractModule instance if successful, None to prevent loading
        """
        try:
            # Check IDA version compatibility
            import ida_pro
            ida_version = ida_pro.IDA_SDK_VERSION
            
            # IDA 9.0 = 900, 9.1 = 910, 9.2 = 920, etc.
            if ida_version < 900:
                print(
                    "DeepExtract: This plugin requires IDA Pro 9.0 or later.\n"
                    f"Current version: {ida_version}"
                )
                return None
            
            # Log plugin initialization
            debug_print("=" * 80)
            debug_print(f"DeepExtract Plugin v1.0.0 - IDA SDK {ida_version}")
            debug_print("=" * 80)
            
            # Create and return the plugin module
            return DeepExtractModule()
        
        except Exception as e:
            print(f"DeepExtract: Failed to initialize plugin: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def run(self, arg: int) -> None:
        """
        Legacy run method (unused in PLUGIN_MULTI mode).
        
        This method is not called when PLUGIN_MULTI is set, as the
        plugin module's run() method is used instead.
        """
        pass
    
    def term(self):
        """
        Plugin termination method (unused in PLUGIN_MULTI mode).
        
        Cleanup is handled by the plugin module's destructor.
        """
        pass


def PLUGIN_ENTRY():
    """
    Plugin entry point function required by IDA.
    
    This function is called by IDA's plugin loader to obtain the plugin
    instance. It must return a plugin_t subclass instance.
    
    Returns:
        DeepExtractPlugin instance
    """
    return DeepExtractPlugin()


# =============================================================================
# Direct Script Execution Support
# =============================================================================
# When IDA runs a script via -S"main.py --args", it executes the script as a
# regular Python file, NOT as a plugin. The PLUGIN_ENTRY() function is only
# called when the script is installed in IDA's plugins directory.
#
# This section detects headless script mode and manually triggers execution.
# =============================================================================

def _run_as_script():
    """
    Execute the plugin logic when running as a standalone script via -S flag.
    
    This function is called at module load time when headless arguments
    are detected. It waits for auto-analysis to complete, then creates
    and runs the plugin module directly.
    """
    import ida_auto
    
    debug_print("=" * 80)
    debug_print("DeepExtract - Running as standalone script")
    debug_print("=" * 80)
    
    # Wait for IDA's auto-analysis to complete before running our analysis
    # This is critical - we need the disassembly database to be fully populated
    debug_print("Waiting for auto-analysis to complete...")
    ida_auto.auto_wait()
    debug_print("Auto-analysis complete.")
    
    # Create and run the plugin module directly
    module = DeepExtractModule()
    module.run(0)


def _check_script_mode():
    """
    Check if we're running as a standalone script with headless arguments.
    
    Returns:
        True if --sqlite-db argument is present in idc.ARGV, False otherwise
    """
    try:
        argv = idc.ARGV if hasattr(idc, 'ARGV') else []
        if len(argv) > 1:
            for arg in argv[1:]:
                if isinstance(arg, str) and '--sqlite-db' in arg:
                    return True
        return False
    except Exception:
        return False


# Auto-execute when running as a script with headless arguments
if _check_script_mode():
    _run_as_script()
