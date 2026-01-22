"""
C++ file generation for the extraction tool.
Adapted from file_generator.py to work with extraction_tool database schema.
"""
import json
import pathlib
import re
import sqlite3
import textwrap
from typing import List, Set, Tuple, Optional, Any

# Use consistent logging approach across modules
from .logging_utils import debug_print


class CppGenerator:
    """Handles generating C++ files from extracted decompiled functions."""
    
    def __init__(self, output_dir: pathlib.Path, module_name: str):
        self.output_dir = output_dir
        self.module_name = module_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def sanitize_filename(name: str) -> str:
        """Sanitizes a string to be a valid filename component."""
        # Replace common C++ scope resolution with underscore
        name = name.replace("::", "_")
        # Remove or replace other invalid characters
        name = re.sub(r'[^a-zA-Z0-9_.-]', '_', name)
        # Limit length to avoid OS issues
        return name[:100]
    
    def generate_cpp_files(self, processed_funcs: List[sqlite3.Row]) -> Tuple[int, int]:
        """Generate C++ source files from extracted functions."""
        class_methods_data = []
        standalone_functions_data = []
        cpp_files_generated = 0
        md_files_generated = 0
        
        # Process and categorize functions
        for func_row in processed_funcs:
            original_name = func_row['function_name']
            original_signature = func_row['function_signature']
            decompiled_code = func_row['decompiled_code']  # This is our C++ source
            
            if not original_name or not original_signature or not decompiled_code:
                debug_print(f"WARNING - Skipping entry with missing data: Name='{original_name}'")
                continue
            
            # Skip functions where decompilation failed
            if decompiled_code.startswith("Decompilation failed:") or decompiled_code == "Decompiler not available":
                debug_print(f"TRACE - Skipping function '{original_name}': {decompiled_code}")
                continue
            
            # For extraction_tool, decompiled_code is already raw C++ from Hex-Rays
            # No need for JSON parsing like the original file_generator.py
            actual_cpp_code = decompiled_code
            
            if not actual_cpp_code or not isinstance(actual_cpp_code, str):
                debug_print(f"WARNING - Function '{original_name}': No valid C++ code extracted.")
                continue
            
            # Categorize function using same logic as original file_generator.py
            match = re.match(r"^(\w+)::~?(\w+)", original_name)
            if match:
                class_name = match.group(1)
                method_name = match.group(2)
                class_methods_data.append(
                    (class_name, method_name, original_signature, actual_cpp_code)
                )
            else:
                standalone_functions_data.append(
                    (original_name, original_signature, actual_cpp_code)
                )
        
        debug_print(f"Identified {len(class_methods_data)} class methods and "
                   f"{len(standalone_functions_data)} standalone functions.")
        
        # Generate class method files
        cpp_count = self._generate_class_method_files(class_methods_data)
        cpp_files_generated += cpp_count
        
        # Generate standalone function files
        cpp_count = self._generate_standalone_function_files(standalone_functions_data)
        cpp_files_generated += cpp_count
        
        return cpp_files_generated, md_files_generated
    
    def generate_cpp_files_with_markdown(self, processed_funcs: List[sqlite3.Row], 
                                        db_path: str) -> Tuple[int, int, int]:
        """
        Generate C++ source files and markdown documentation.
        
        This is the main entry point that generates both C++ files and markdown
        documentation in one operation, similar to the references system workflow.
        
        :param processed_funcs: List of function rows from the database
        :param db_path: Path to the SQLite database for file info extraction
        :return: Tuple of (cpp_files_generated, md_files_generated, report_files_generated)
        """
        debug_print("Starting C++ and markdown generation...")
        
        # Generate C++ files first
        cpp_files_generated, md_files_generated = self.generate_cpp_files(processed_funcs)
        
        # Extract function names for markdown generation
        function_names = []
        for func_row in processed_funcs:
            original_name = func_row['function_name']
            decompiled_code = func_row['decompiled_code']
            
            # Only include functions that have valid decompiled code (same filter as C++ generation)
            if (original_name and decompiled_code and 
                not decompiled_code.startswith("Decompilation failed:") and 
                decompiled_code != "Decompiler not available"):
                function_names.append(original_name)
        
        # Generate markdown documentation
        report_files_generated = 0
        if function_names:
            try:
                report_files_generated = self.generate_file_info_markdown(function_names, db_path)
                debug_print("Successfully generated markdown documentation")
            except Exception as e:
                debug_print(f"ERROR - Failed to generate markdown documentation "
                           f"(db_path='{db_path}', {len(function_names)} functions): {e}")
        else:
            debug_print("WARNING - No valid functions found for markdown generation")
        
        # Summary logging
        debug_print(f"Generation complete: {cpp_files_generated} C++ files, "
                   f"{report_files_generated} markdown documentation files")
        
        return cpp_files_generated, md_files_generated, report_files_generated
    
    def _generate_class_method_files(self, class_methods_data: List[tuple]) -> int:
        """Generate files for class methods."""
        cpp_files_generated = 0
        used_filenames = set()
        
        debug_print(f"Generating C++ files for {len(class_methods_data)} class methods...")
        
        for class_name, method_name, signature, cpp_code_str in sorted(class_methods_data):
            sanitized_class_name = self.sanitize_filename(class_name)
            sanitized_method_name = self.sanitize_filename(method_name)
            
            # Generate unique filename
            base_filename = f"{self.module_name}_{sanitized_class_name}_{sanitized_method_name}"
            output_filename = f"{base_filename}.cpp"
            counter = 1
            while (self.output_dir / output_filename) in used_filenames:
                output_filename = f"{base_filename}_{counter}.cpp"
                counter += 1
            
            class_method_path = self.output_dir / output_filename
            used_filenames.add(class_method_path)
            
            # Write C++ file
            debug_print(f"TRACE - Writing class method '{class_name}::{method_name}' to {class_method_path}")
            self._write_cpp_file(class_method_path, signature, cpp_code_str)
            cpp_files_generated += 1
        
        debug_print("Generated C++ files for class methods.")
        return cpp_files_generated
    
    def _generate_standalone_function_files(self, standalone_functions_data: List[tuple]) -> int:
        """Generate files for standalone functions."""
        if not standalone_functions_data:
            debug_print("No standalone functions found to generate files for.")
            return 0
        
        cpp_files_generated = 0
        used_filenames = set()
        
        debug_print(f"Generating individual C++ files for {len(standalone_functions_data)} standalone functions...")
        
        sorted_standalone = sorted(standalone_functions_data, key=lambda item: (item[0], item[1]))
        
        for original_name, signature, cpp_code_str in sorted_standalone:
            sanitized_func_name = self.sanitize_filename(original_name)
            if not sanitized_func_name:
                sanitized_func_name = "unnamed_standalone_function"
            
            # Generate unique filename
            base_filename = f"{self.module_name}_standalone_{sanitized_func_name}"
            output_filename = f"{base_filename}.cpp"
            counter = 1
            while (self.output_dir / output_filename) in used_filenames:
                output_filename = f"{base_filename}_{counter}.cpp"
                counter += 1
            
            standalone_file_path = self.output_dir / output_filename
            used_filenames.add(standalone_file_path)
            
            # Write C++ file
            debug_print(f"TRACE - Writing standalone function '{original_name}' to {standalone_file_path}")
            self._write_cpp_file(standalone_file_path, signature, cpp_code_str)
            cpp_files_generated += 1
        
        debug_print("Generated C++ files for standalone functions.")
        return cpp_files_generated
    
    def _write_cpp_file(self, file_path: pathlib.Path, signature: str, 
                       cpp_code: str):
        """Write a C++ source file."""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"// Function Signature: {signature}\n\n")
            
            # Process and write the C++ code
            processed_cpp = cpp_code.replace("\\n", "\n").replace("`", "'").strip()
            
            # Wrap long lines in the C++ code (comments and string literals only)
            wrapped_cpp_lines = []
            in_multiline_comment = False
            
            for line in processed_cpp.splitlines():
                # Check if we're entering or in a multi-line comment
                if '/*' in line and not in_multiline_comment:
                    in_multiline_comment = True
                
                # Check if this is a comment line
                stripped = line.strip()
                if stripped.startswith('//') or in_multiline_comment:
                    # Comment line - wrap it
                    indent = len(line) - len(line.lstrip())
                    indent_str = line[:indent]
                    
                    if len(line) > 120 and not stripped.startswith('//'):
                        # Multi-line comment content - wrap but preserve structure
                        wrapped_cpp_lines.append(line)
                    elif stripped.startswith('//'):
                        # Single-line comment
                        comment_content = stripped[2:].strip()
                        
                        if len(line) > 120:
                            wrapped = textwrap.wrap(comment_content, width=120 - indent - 3,
                                                  break_long_words=False,
                                                  replace_whitespace=False,
                                                  break_on_hyphens=False)
                            for i, wrapped_line in enumerate(wrapped):
                                wrapped_cpp_lines.append(f"{indent_str}// {wrapped_line}")
                        else:
                            wrapped_cpp_lines.append(line)
                    else:
                        wrapped_cpp_lines.append(line)
                elif len(line) > 120:
                    # Long non-comment line - keep as is to avoid breaking code
                    debug_print(f"TRACE - Long line ({len(line)} chars) in C++ code kept as-is to preserve functionality")
                    wrapped_cpp_lines.append(line)
                else:
                    # Regular code line - keep as is
                    wrapped_cpp_lines.append(line)
                
                # Check if we're exiting a multi-line comment
                if '*/' in line and in_multiline_comment:
                    in_multiline_comment = False
            
            f.write("\n".join(wrapped_cpp_lines))
            f.write("\n")
    
    
    def generate_file_info_json(self, function_names: List[str], 
                                db_path: str) -> int:
        """
        Generate file info JSON documentation.
        
        Creates a machine-readable JSON file with the same content as file_info.md
        for easier parsing by scripts and automation tools.
        
        :param function_names: List of function names that were processed
        :param db_path: Path to the SQLite database containing the analysis data
        :return: Number of JSON files generated (1 for file_info.json)
        """
        json_files_generated = 0
        
        # Generate file info JSON
        json_file_path = self.output_dir / "file_info.json"
        
        # Get file info from database
        file_infos = self._get_file_info_from_db(db_path)
        
        if not file_infos and not function_names:
            debug_print("WARNING - No file info entries and no processed functions found.")
            return json_files_generated
        
        # extraction_tool processes exactly one file per database
        file_info = file_infos[0] if file_infos else None
        
        debug_print(f"Writing {len(function_names)} function names and "
                   f"file info to {json_file_path}")
        
        # Build structured dictionary
        data_dict = self._build_file_info_dict(file_info, function_names, db_path)
        
        # Write JSON file
        with open(json_file_path, 'w', encoding='utf-8') as json_file:
            json.dump(data_dict, json_file, indent=4, ensure_ascii=False)
        
        debug_print(f"Successfully generated file info JSON: {json_file_path}")
        json_files_generated += 1
        
        return json_files_generated
    
    def generate_file_info_markdown(self, function_names: List[str], 
                                   db_path: str) -> int:
        """
        Generate file info markdown documentation.
        
        This function creates the same detailed markdown documentation as the references
        system, including all PE metadata, imports/exports, and function information.
        
        :param function_names: List of function names that were processed
        :param db_path: Path to the SQLite database containing the analysis data
        :return: Number of report files generated (2 for file_info.md and file_info.json)
        """
        report_files_generated = 0
        
        # Generate file info markdown
        markdown_file_path = self.output_dir / "file_info.md"
        
        # Get file info from database
        file_infos = self._get_file_info_from_db(db_path)
        
        if not file_infos and not function_names:
            debug_print("WARNING - No file info entries and no processed functions found.")
            return report_files_generated
        
        # extraction_tool processes exactly one file per database
        file_info = file_infos[0] if file_infos else None
        
        debug_print(f"Writing {len(function_names)} function names and "
                   f"file info to {markdown_file_path}")
        
        with open(markdown_file_path, 'w', encoding='utf-8') as md_file:
            md_file.write(f"# File Information for Module: {self.module_name}\n\n")
                         
            # Write file info sections
            self._write_file_info_section(md_file, file_info)
            
            # Write function list section
            if function_names:
                self._write_function_list_section(md_file, function_names, db_path)
        
        debug_print(f"Successfully generated file info markdown: {markdown_file_path}")
        report_files_generated += 1
        
        # Also generate JSON file
        json_generated = self.generate_file_info_json(function_names, db_path)
        report_files_generated += json_generated
        
        return report_files_generated
    
    def _get_file_info_from_db(self, db_path: str) -> List[sqlite3.Row]:
        """
        Retrieve file info from extraction_tool database.
        
        Uses a context manager for safe connection handling.
        
        Args:
            db_path: Path to the SQLite database file
            
        Returns:
            List of file_info rows from the database
        """
        try:
            with sqlite3.connect(db_path, timeout=20) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                try:
                    cursor.execute("SELECT * FROM file_info;")
                    return cursor.fetchall()
                except sqlite3.OperationalError as e:
                    if "no such table: file_info" in str(e):
                        debug_print("WARNING - 'file_info' table not found in the database.")
                        return []
                    else:
                        raise
        
        except sqlite3.Error as e:
            debug_print(f"ERROR - Database error retrieving file info from '{db_path}': {e}")
            import traceback
            debug_print(traceback.format_exc())
            return []
    
    @staticmethod
    def _write_info_field(md_file, label: str, value: Any, is_code: bool = True):
        """Writes a single key-value field to the markdown file."""
        if value is None or str(value).strip() == "":
            value = "N/A"
        
        if is_code and value != "N/A":
            md_file.write(f"- **{label}:** `{value}`\n")
        else:
            md_file.write(f"- **{label}:** {value}\n")

    def _write_json_section(self, md_file, section_name: str, json_data: Optional[str]):
        """Write a JSON section to markdown with pretty formatting."""
        md_file.write(f"\n## {section_name}\n")
        
        if json_data and json_data.strip():
            try:
                data = json.loads(json_data)
                # Check for empty list or dict
                if not data:
                    md_file.write(f"*No {section_name.lower()} data available.*\n")
                    return

                pretty_json = json.dumps(data, indent=4)
                md_file.write("```json\n")
                md_file.write(pretty_json)
                md_file.write("\n```\n")
            except json.JSONDecodeError:
                debug_print(f"WARNING - Could not parse {section_name.lower()} JSON. Writing raw.")
                md_file.write("```\n")
                md_file.write(json_data)
                md_file.write("\n```\n")
        else:
            md_file.write(f"*No {section_name.lower()} data available.*\n")
    
    def _write_file_info_section(self, md_file, file_info: sqlite3.Row):
        """Write the file info section to markdown."""
        if not file_info:
            return
        
        row_keys = file_info.keys()
        
        # --- Basic File Information ---
        md_file.write("## Basic File Information\n")
        self._write_info_field(md_file, "Full Path", file_info['file_path'] if 'file_path' in row_keys else None)
        self._write_info_field(md_file, "Base Directory", file_info['base_dir'] if 'base_dir' in row_keys else None)
        self._write_info_field(md_file, "File Name", file_info['file_name'] if 'file_name' in row_keys else None)
        self._write_info_field(md_file, "Extension", file_info['file_extension'] if 'file_extension' in row_keys else None)
        self._write_info_field(md_file, "Size (Bytes)", file_info['file_size_bytes'] if 'file_size_bytes' in row_keys else None, is_code=False)
        self._write_info_field(md_file, "MD5 Hash", file_info['md5_hash'] if 'md5_hash' in row_keys else None)
        self._write_info_field(md_file, "SHA256 Hash", file_info['sha256_hash'] if 'sha256_hash' in row_keys else None)
        self._write_info_field(md_file, "Analysis Timestamp", file_info['analysis_timestamp'] if 'analysis_timestamp' in row_keys else None)
        md_file.write("\n")

        # --- PE Version Information ---
        md_file.write("## PE Version Information\n")
        self._write_info_field(md_file, "File Version", file_info['file_version'] if 'file_version' in row_keys else None)
        self._write_info_field(md_file, "Product Version", file_info['product_version'] if 'product_version' in row_keys else None)
        self._write_info_field(md_file, "Company Name", file_info['company_name'] if 'company_name' in row_keys else None, is_code=False)
        self._write_info_field(md_file, "Product Name", file_info['product_name'] if 'product_name' in row_keys else None, is_code=False)
        self._write_info_field(md_file, "File Description", file_info['file_description'] if 'file_description' in row_keys else None, is_code=False)
        self._write_info_field(md_file, "Internal Name", file_info['internal_name'] if 'internal_name' in row_keys else None)
        self._write_info_field(md_file, "Original Filename", file_info['original_filename'] if 'original_filename' in row_keys else None)
        self._write_info_field(md_file, "Legal Copyright", file_info['legal_copyright'] if 'legal_copyright' in row_keys else None, is_code=False)
        md_file.write("\n")

        # --- Key PE Metadata ---
        md_file.write("## Key PE Metadata\n")
        self._write_info_field(md_file, "Compilation Timestamp", file_info['time_date_stamp_str'] if 'time_date_stamp_str' in row_keys else None)
        self._write_info_field(md_file, "File Modified Date", file_info['file_modified_date_str'] if 'file_modified_date_str' in row_keys else None)
        self._write_info_field(md_file, "PDB Path", file_info['pdb_path'] if 'pdb_path' in row_keys else None)
        # Convert .NET Assembly boolean/int to Yes/No for readability
        is_net_raw = file_info['is_net_assembly'] if 'is_net_assembly' in row_keys else None
        is_net_display = "Yes" if is_net_raw else "No" if is_net_raw is not None else None
        self._write_info_field(md_file, ".NET Assembly", is_net_display, is_code=False)
        self._write_info_field(md_file, "IDA Pro DB Cache Path", file_info['idb_cache_path'] if 'idb_cache_path' in row_keys else None)
        md_file.write("\n")

        # --- Detailed JSON Sections ---
        # Entry Points with multi-method detection
        self._write_json_section(md_file, "Entry Points", file_info['entry_point'] if 'entry_point' in row_keys else None)
        
        # Imports with API-set resolution and delay-load support
        imports_data = None
        if 'imports' in row_keys and file_info['imports']:
            imports_data = file_info['imports']
        elif 'combined_imports' in row_keys and file_info['combined_imports']:
            imports_data = file_info['combined_imports']
        self._write_json_section(md_file, "Imports", imports_data)
        
        # Exports with forwarding information
        self._write_json_section(md_file, "Exports", file_info['exports'] if 'exports' in row_keys else None)
        
        # PE Sections - memory layout and characteristics
        self._write_json_section(md_file, "PE Sections", file_info['sections'] if 'sections' in row_keys else None)
        
        # Security Features - ASLR, DEP, CFG, etc.
        self._write_json_section(md_file, "Security Features", file_info['security_features'] if 'security_features' in row_keys else None)
        
        # DLL Characteristics flags
        self._write_json_section(md_file, "DLL Characteristics", file_info['dll_characteristics'] if 'dll_characteristics' in row_keys else None)
        
        # Rich Header - compiler/linker toolchain identification
        self._write_json_section(md_file, "Rich Header", file_info['rich_header'] if 'rich_header' in row_keys else None)
        
        # TLS Callbacks - thread local storage callbacks (important for malware analysis)
        self._write_json_section(md_file, "TLS Callbacks", file_info['tls_callbacks'] if 'tls_callbacks' in row_keys else None)
        
        # Load Config - SEH, CFG guard tables, etc.
        self._write_json_section(md_file, "Load Configuration", file_info['load_config'] if 'load_config' in row_keys else None)
        
        # Exception Info - exception handling data
        self._write_json_section(md_file, "Exception Information", file_info['exception_info'] if 'exception_info' in row_keys else None)
        
        # .NET/CLR Metadata - only if this is a .NET assembly
        is_net = file_info['is_net_assembly'] if 'is_net_assembly' in row_keys else False
        if is_net:
            self._write_json_section(md_file, "CLR Metadata (.NET)", file_info['clr_metadata'] if 'clr_metadata' in row_keys else None)

    def _write_function_list_section(self, md_file, function_names: List[str], db_path: str):
        """
        Write the function list section to markdown.
        
        Groups functions by type (class methods vs standalone) and provides
        a summary with links to generated C++ files.
        
        Args:
            md_file: Open file handle to write to
            function_names: List of function names that were processed
            db_path: Path to the database for additional function info
        """
        if not function_names:
            return
        
        md_file.write("\n## Function Summary\n\n")
        md_file.write(f"**Total Functions Extracted:** {len(function_names):,}\n\n")
        
        # Try to get function signatures from database for richer output
        func_details = []
        try:
            with sqlite3.connect(db_path, timeout=20) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT function_name, function_signature, function_signature_extended
                    FROM functions
                    ORDER BY function_name
                """)
                func_details = cursor.fetchall()
        except Exception as e:
            debug_print(f"WARNING - Could not retrieve function details: {e}")
        
        # Categorize functions
        class_methods = []
        standalone_functions = []
        
        for row in func_details:
            name = row['function_name'] if row else ''
            sig = row['function_signature_extended'] or row['function_signature'] or name
            
            # Detect class methods by looking for :: in the name
            if '::' in name:
                class_name = name.split('::')[0]
                method_name = name.split('::', 1)[1] if '::' in name else name
                class_methods.append((class_name, method_name, sig))
            else:
                standalone_functions.append((name, sig))
        
        # Write class methods section
        if class_methods:
            md_file.write("### Class Methods\n\n")
            md_file.write(f"**{len(class_methods):,} class methods** identified across ")
            
            # Count unique classes
            unique_classes = set(cm[0] for cm in class_methods)
            md_file.write(f"**{len(unique_classes):,} classes**.\n\n")
            
            # Group by class
            classes_dict = {}
            for class_name, method_name, sig in class_methods:
                if class_name not in classes_dict:
                    classes_dict[class_name] = []
                classes_dict[class_name].append((method_name, sig))
            
            # Write collapsible sections for each class (limit to top 20 classes by method count)
            sorted_classes = sorted(classes_dict.items(), key=lambda x: -len(x[1]))[:20]
            for class_name, methods in sorted_classes:
                md_file.write(f"<details>\n<summary><b>{class_name}</b> ({len(methods)} methods)</summary>\n\n")
                md_file.write("| Method | Signature |\n")
                md_file.write("|--------|----------|\n")
                for method_name, sig in sorted(methods, key=lambda x: x[0])[:50]:  # Limit to 50 methods per class
                    # Escape pipe characters in signature
                    safe_sig = sig.replace('|', '\\|') if sig else ''
                    # Truncate very long signatures
                    if len(safe_sig) > 100:
                        safe_sig = safe_sig[:97] + "..."
                    md_file.write(f"| `{method_name}` | `{safe_sig}` |\n")
                if len(methods) > 50:
                    md_file.write(f"| ... | *{len(methods) - 50} more methods* |\n")
                md_file.write("\n</details>\n\n")
            
            if len(classes_dict) > 20:
                md_file.write(f"*... and {len(classes_dict) - 20} more classes*\n\n")
        
        # Write standalone functions section
        if standalone_functions:
            md_file.write("### Standalone Functions\n\n")
            md_file.write(f"**{len(standalone_functions):,} standalone functions** identified.\n\n")
            
            md_file.write("<details>\n<summary>View function list</summary>\n\n")
            md_file.write("| Function Name | Signature |\n")
            md_file.write("|---------------|----------|\n")
            
            # Sort and limit output
            for name, sig in sorted(standalone_functions, key=lambda x: x[0])[:200]:
                safe_sig = sig.replace('|', '\\|') if sig else ''
                if len(safe_sig) > 100:
                    safe_sig = safe_sig[:97] + "..."
                md_file.write(f"| `{name}` | `{safe_sig}` |\n")
            
            if len(standalone_functions) > 200:
                md_file.write(f"| ... | *{len(standalone_functions) - 200} more functions* |\n")
            
            md_file.write("\n</details>\n\n")
        
        # Write generated files note
        md_file.write("---\n\n")
        md_file.write(f"*Generated C++ files are located in the same directory as this file.*\n")
    
    def _build_file_info_dict(self, file_info: Optional[sqlite3.Row], 
                             function_names: List[str], db_path: str) -> dict:
        """
        Build structured dictionary for JSON export from database data.
        
        Parses JSON string fields into Python objects and structures the data
        into logical sections matching the markdown format.
        
        Args:
            file_info: SQLite Row containing file_info table data
            function_names: List of function names that were processed
            db_path: Path to the database for function details
            
        Returns:
            Dictionary containing all file information structured for JSON export
        """
        result = {
            "module_name": self.module_name
        }
        
        if not file_info:
            return result
        
        row_keys = file_info.keys()
        
        # Helper to safely get and parse JSON fields
        def parse_json_field(field_name: str) -> Any:
            if field_name not in row_keys or not file_info[field_name]:
                return None
            try:
                return json.loads(file_info[field_name])
            except (json.JSONDecodeError, TypeError):
                return file_info[field_name]  # Return raw if parsing fails
        
        # Basic File Information
        result["basic_file_info"] = {
            "file_path": file_info['file_path'] if 'file_path' in row_keys else None,
            "base_dir": file_info['base_dir'] if 'base_dir' in row_keys else None,
            "file_name": file_info['file_name'] if 'file_name' in row_keys else None,
            "extension": file_info['file_extension'] if 'file_extension' in row_keys else None,
            "size_bytes": file_info['file_size_bytes'] if 'file_size_bytes' in row_keys else None,
            "md5_hash": file_info['md5_hash'] if 'md5_hash' in row_keys else None,
            "sha256_hash": file_info['sha256_hash'] if 'sha256_hash' in row_keys else None,
            "analysis_timestamp": file_info['analysis_timestamp'] if 'analysis_timestamp' in row_keys else None
        }
        
        # PE Version Information
        result["pe_version_info"] = {
            "file_version": file_info['file_version'] if 'file_version' in row_keys else None,
            "product_version": file_info['product_version'] if 'product_version' in row_keys else None,
            "company_name": file_info['company_name'] if 'company_name' in row_keys else None,
            "product_name": file_info['product_name'] if 'product_name' in row_keys else None,
            "file_description": file_info['file_description'] if 'file_description' in row_keys else None,
            "internal_name": file_info['internal_name'] if 'internal_name' in row_keys else None,
            "original_filename": file_info['original_filename'] if 'original_filename' in row_keys else None,
            "legal_copyright": file_info['legal_copyright'] if 'legal_copyright' in row_keys else None
        }
        
        # Key PE Metadata
        is_net_raw = file_info['is_net_assembly'] if 'is_net_assembly' in row_keys else None
        result["pe_metadata"] = {
            "compilation_timestamp": file_info['time_date_stamp_str'] if 'time_date_stamp_str' in row_keys else None,
            "file_modified_date": file_info['file_modified_date_str'] if 'file_modified_date_str' in row_keys else None,
            "pdb_path": file_info['pdb_path'] if 'pdb_path' in row_keys else None,
            "is_net_assembly": bool(is_net_raw) if is_net_raw is not None else None,
            "idb_cache_path": file_info['idb_cache_path'] if 'idb_cache_path' in row_keys else None
        }
        
        # Parse JSON sections
        result["entry_points"] = parse_json_field('entry_point')
        
        # Handle imports (check both 'imports' and 'combined_imports')
        imports_data = None
        if 'imports' in row_keys and file_info['imports']:
            imports_data = parse_json_field('imports')
        elif 'combined_imports' in row_keys and file_info['combined_imports']:
            imports_data = parse_json_field('combined_imports')
        result["imports"] = imports_data
        
        result["exports"] = parse_json_field('exports')
        result["sections"] = parse_json_field('sections')
        result["security_features"] = parse_json_field('security_features')
        result["dll_characteristics"] = parse_json_field('dll_characteristics')
        result["rich_header"] = parse_json_field('rich_header')
        result["tls_callbacks"] = parse_json_field('tls_callbacks')
        result["load_config"] = parse_json_field('load_config')
        result["exception_info"] = parse_json_field('exception_info')
        
        # CLR Metadata only if .NET assembly
        is_net = file_info['is_net_assembly'] if 'is_net_assembly' in row_keys else False
        if is_net:
            result["clr_metadata"] = parse_json_field('clr_metadata')
        else:
            result["clr_metadata"] = None
        
        # Function Summary
        if function_names:
            func_summary = {
                "total_functions": len(function_names),
                "class_methods": [],
                "standalone_functions": []
            }
            
            # Get function details from database
            try:
                with sqlite3.connect(db_path, timeout=20) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT function_name, function_signature, function_signature_extended
                        FROM functions
                        ORDER BY function_name
                    """)
                    func_details = cursor.fetchall()
                    
                    # Categorize functions
                    classes_dict = {}
                    for row in func_details:
                        name = row['function_name'] if row else ''
                        sig = row['function_signature_extended'] or row['function_signature'] or name
                        
                        if '::' in name:
                            class_name = name.split('::')[0]
                            method_name = name.split('::', 1)[1]
                            if class_name not in classes_dict:
                                classes_dict[class_name] = []
                            classes_dict[class_name].append({
                                "name": method_name,
                                "signature": sig
                            })
                        else:
                            func_summary["standalone_functions"].append({
                                "name": name,
                                "signature": sig
                            })
                    
                    # Convert classes_dict to list format
                    for class_name, methods in sorted(classes_dict.items()):
                        func_summary["class_methods"].append({
                            "class_name": class_name,
                            "method_count": len(methods),
                            "methods": methods
                        })
                    
            except Exception as e:
                debug_print(f"WARNING - Could not retrieve function details for JSON: {e}")
            
            result["function_summary"] = func_summary
        else:
            result["function_summary"] = None
        
        return result


def generate_standalone_markdown_documentation(db_path: str, output_dir: str, module_name: str = None) -> bool:
    """
    Standalone function to generate markdown documentation from extraction database.
    
    This function can be called independently to generate the same markdown documentation
    as the references system, using only the extraction_tool database as input.
    
    :param db_path: Path to the extraction_tool SQLite database
    :param output_dir: Directory where markdown files should be generated
    :param module_name: Optional module name (derived from database if not provided)
    :return: True if generation was successful, False otherwise
    """
    try:
        # Derive module name from database path if not provided
        if not module_name:
            db_path_obj = pathlib.Path(db_path)
            module_name = db_path_obj.stem
            # Remove hash suffix if present (e.g., "kernel32_dll_a1b2c3d4" -> "kernel32_dll")
            import re
            module_name = re.sub(r'_[a-fA-F0-9]{8,}$', '', module_name)
        
        # Create output directory
        output_path = pathlib.Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize generator
        generator = CppGenerator(output_path, module_name)
        
        # Connect to database and extract function information
        conn = None
        try:
            conn = sqlite3.connect(db_path, timeout=20)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all functions with valid decompiled code
            cursor.execute('''
                SELECT function_name, function_signature, decompiled_code
                FROM functions
                WHERE decompiled_code IS NOT NULL 
                AND decompiled_code != 'Decompiler not available'
                AND decompiled_code NOT LIKE 'Decompilation failed:%'
                ORDER BY function_name
            ''')
            
            functions_data = cursor.fetchall()
            
            # Extract function names
            function_names = [func['function_name'] for func in functions_data if func['function_name']]
            
            if function_names:
                # Generate markdown and JSON documentation
                report_files_generated = generator.generate_file_info_markdown(function_names, db_path)
                
                debug_print(f"Successfully generated {report_files_generated} documentation files for {len(function_names)} functions")
                debug_print(f"Output directory: {output_path}")
                debug_print(f"Generated files: file_info.md, file_info.json")
                
                return True
            else:
                debug_print("WARNING - No valid functions found in database for documentation generation")
                return False
                
        finally:
            # Ensure connection is always closed
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass  # Ignore errors during cleanup
            
    except Exception as e:
        import traceback
        module_info = f"module='{module_name}'" if 'module_name' in locals() else "module=unknown"
        output_info = f"output='{output_dir}'" if 'output_dir' in locals() else "output=unknown"
        debug_print(f"ERROR - Failed to generate standalone markdown documentation "
                   f"(db_path='{db_path}', {module_info}, {output_info}): {e}")
        debug_print(traceback.format_exc())
        return False


# Convenience function for backward compatibility
def generate_extraction_documentation(db_path: str, output_dir: str, module_name: str = None) -> bool:
    """
    Convenience function that wraps generate_standalone_markdown_documentation.
    
    :param db_path: Path to the extraction_tool SQLite database
    :param output_dir: Directory where markdown files should be generated  
    :param module_name: Optional module name (derived from database if not provided)
    :return: True if generation was successful, False otherwise
    """
    return generate_standalone_markdown_documentation(db_path, output_dir, module_name)