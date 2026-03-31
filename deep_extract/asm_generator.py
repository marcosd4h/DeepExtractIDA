"""
Assembly file generation for the extraction tool.

Generates .asm files grouped by class membership and address order, with
library/CRT functions separated into dedicated files.  Each function is
preceded by a structured header block containing cross-references, string
literals, and dangerous API metadata so that AI agents can navigate the
assembly efficiently.
"""

import json
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from .logging_utils import debug_print
from .cpp_generator import CppGenerator


class AsmGenerator:
    """Generates grouped .asm files from extracted function assembly."""

    ASM_GROUP_TARGET_LINES = 2500
    ASM_GROUP_MIN_LINES = 2000

    def __init__(self, output_dir: pathlib.Path, module_name: str):
        self.output_dir = output_dir
        self.module_name = module_name
        self._long_path(self.output_dir).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Shared helpers delegated to CppGenerator statics
    # ------------------------------------------------------------------

    @staticmethod
    def sanitize_filename(name: str) -> str:
        return CppGenerator.sanitize_filename(name)

    @staticmethod
    def _long_path(p: pathlib.Path) -> pathlib.Path:
        return CppGenerator._long_path(p)

    @classmethod
    def _cap_filename_length(cls, base_filename: str,
                             output_dir: 'pathlib.Path | None' = None) -> str:
        return CppGenerator._cap_filename_length(base_filename, output_dir)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def generate_asm_files(self, all_functions: List[Dict[str, Any]]) -> Tuple[int, dict]:
        """Generate .asm files and return (files_generated, asm_function_index).

        *all_functions* is a list of dicts with at least the keys produced by
        the SQL query in ``generate_asm_output_files`` (function_id,
        function_name, mangled_name, function_signature,
        function_signature_extended, assembly_code, simple_inbound_xrefs,
        simple_outbound_xrefs, string_literals, dangerous_api_calls).
        """
        class_methods, standalone, library = self._categorize_functions(all_functions)

        asm_files_generated = 0
        function_index: Dict[str, Any] = {}

        count, idx = self._generate_class_asm_files(class_methods)
        asm_files_generated += count
        function_index.update(idx)

        count, idx = self._generate_standalone_asm_files(standalone)
        asm_files_generated += count
        function_index.update(idx)

        count, idx = self._generate_library_asm_file(library)
        asm_files_generated += count
        function_index.update(idx)

        return asm_files_generated, function_index

    # ------------------------------------------------------------------
    # Categorisation
    # ------------------------------------------------------------------

    def _categorize_functions(
        self, functions: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, List[Dict]], List[Dict], List[Dict]]:
        """Split functions into class methods, standalone, and library."""
        class_methods: Dict[str, List[Dict]] = {}
        standalone: List[Dict] = []
        library: List[Dict] = []

        for func in functions:
            name = func.get('function_name') or ''
            mangled = func.get('mangled_name') or ''
            asm = func.get('assembly_code') or ''
            if not asm:
                continue

            lib_tag = CppGenerator._detect_library_tag(name, mangled)
            if lib_tag:
                func['_library_tag'] = lib_tag
                library.append(func)
                continue

            match = re.match(r'^(\w+)::~?(\w+)', name)
            if match:
                class_name = match.group(1)
                class_methods.setdefault(class_name, []).append(func)
            else:
                standalone.append(func)

        return class_methods, standalone, library

    # ------------------------------------------------------------------
    # File generators
    # ------------------------------------------------------------------

    def _generate_class_asm_files(
        self, class_methods: Dict[str, List[Dict]]
    ) -> Tuple[int, Dict[str, Any]]:
        if not class_methods:
            return 0, {}

        files_generated = 0
        function_index: Dict[str, Any] = {}
        used_filenames: set = set()

        for class_name in sorted(class_methods):
            methods = sorted(class_methods[class_name],
                             key=lambda f: f.get('function_id', 0))
            groups = self._split_into_groups(methods)

            sanitized = self.sanitize_filename(class_name)
            for group_idx, group in enumerate(groups, start=1):
                base = self._cap_filename_length(
                    f"{self.module_name}_{sanitized}_group_{group_idx}",
                    output_dir=self.output_dir,
                )
                filename = f"{base}.asm"
                counter = 1
                while (self.output_dir / filename) in used_filenames:
                    filename = f"{base}_{counter}.asm"
                    counter += 1

                path = self.output_dir / filename
                used_filenames.add(path)

                label = f"{class_name}_group_{group_idx}"
                self._write_asm_file(path, group, label)
                self._index_functions(group, filename, function_index)
                files_generated += 1

        debug_print(f"Generated {files_generated} class ASM file(s).")
        return files_generated, function_index

    def _generate_standalone_asm_files(
        self, standalone: List[Dict]
    ) -> Tuple[int, Dict[str, Any]]:
        if not standalone:
            return 0, {}

        standalone.sort(key=lambda f: f.get('function_id', 0))
        groups = self._split_into_groups(standalone)

        files_generated = 0
        function_index: Dict[str, Any] = {}
        used_filenames: set = set()

        for group_idx, group in enumerate(groups, start=1):
            base = self._cap_filename_length(
                f"{self.module_name}_standalone_group_{group_idx}",
                output_dir=self.output_dir,
            )
            filename = f"{base}.asm"
            counter = 1
            while (self.output_dir / filename) in used_filenames:
                filename = f"{base}_{counter}.asm"
                counter += 1

            path = self.output_dir / filename
            used_filenames.add(path)

            label = f"standalone_group_{group_idx}"
            self._write_asm_file(path, group, label)
            self._index_functions(group, filename, function_index)
            files_generated += 1

        debug_print(f"Generated {files_generated} standalone ASM file(s).")
        return files_generated, function_index

    def _generate_library_asm_file(
        self, library: List[Dict]
    ) -> Tuple[int, Dict[str, Any]]:
        if not library:
            return 0, {}

        library.sort(key=lambda f: f.get('function_id', 0))
        groups = self._split_into_groups(library)

        files_generated = 0
        function_index: Dict[str, Any] = {}
        used_filenames: set = set()

        for group_idx, group in enumerate(groups, start=1):
            suffix = f"_library_group_{group_idx}" if len(groups) > 1 else "_library"
            base = self._cap_filename_length(
                f"{self.module_name}{suffix}",
                output_dir=self.output_dir,
            )
            filename = f"{base}.asm"
            counter = 1
            while (self.output_dir / filename) in used_filenames:
                filename = f"{base}_{counter}.asm"
                counter += 1

            path = self.output_dir / filename
            used_filenames.add(path)

            label = f"library{suffix.replace('_library', '')}"
            self._write_asm_file(path, group, label)
            self._index_functions(group, filename, function_index, is_library=True)
            files_generated += 1

        debug_print(f"Generated {files_generated} library ASM file(s).")
        return files_generated, function_index

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    def _split_into_groups(self, functions: List[Dict]) -> List[List[Dict]]:
        """Split a sorted function list into groups respecting the line budget."""
        groups: List[List[Dict]] = []
        current_group: List[Dict] = []
        current_lines = 0

        for func in functions:
            est = self._estimate_lines(func)
            if not current_group:
                current_group.append(func)
                current_lines = est
                continue

            if current_lines + est > self.ASM_GROUP_TARGET_LINES:
                groups.append(current_group)
                current_group = [func]
                current_lines = est
            else:
                current_group.append(func)
                current_lines += est

        if current_group:
            groups.append(current_group)
        return groups

    @staticmethod
    def _estimate_lines(func: Dict) -> int:
        asm = func.get('assembly_code') or ''
        header_lines = 12
        return header_lines + asm.count('\n') + 1

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def _write_asm_file(self, path: pathlib.Path,
                        functions: List[Dict], group_label: str) -> None:
        safe_path = self._long_path(path)
        with open(safe_path, 'w', encoding='utf-8') as f:
            file_header = self._build_file_header(group_label, functions)
            f.write('\n'.join(file_header))
            f.write('\n\n')

            for idx, func in enumerate(functions):
                header = self._build_function_header(func)
                f.write('\n'.join(header))
                f.write('\n')

                asm = (func.get('assembly_code') or '').rstrip()
                if asm:
                    f.write(asm)
                    f.write('\n')

                if idx != len(functions) - 1:
                    f.write('\n')

    def _build_file_header(self, group_label: str,
                           functions: List[Dict]) -> List[str]:
        ids = [f.get('function_id', 0) for f in functions if f.get('function_id')]
        if ids:
            min_addr = f"0x{min(ids):X}"
            max_addr = f"0x{max(ids):X}"
            addr_range = f"{min_addr} - {max_addr}"
        else:
            addr_range = "unknown"

        return [
            f"; Module: {self.module_name}",
            f"; Group: {group_label}",
            f"; Functions: {len(functions)}",
            f"; Address range: {addr_range}",
        ]

    def _build_function_header(self, func: Dict) -> List[str]:
        name = func.get('function_name') or 'unknown'
        mangled = func.get('mangled_name') or ''
        func_id = func.get('function_id', 0)
        sig = func.get('function_signature_extended') or func.get('function_signature') or ''

        asm = func.get('assembly_code') or ''
        asm_lines = asm.count('\n') + 1 if asm else 0

        lines = [
            '; ' + '=' * 60,
            f'; Function: {name}',
        ]
        if func_id:
            lines.append(f'; Address: 0x{func_id:X}')
        if mangled and mangled != name:
            lines.append(f'; Mangled: {mangled}')
        if sig and sig != name:
            lines.append(f'; Signature: {sig}')

        lib_tag = func.get('_library_tag')
        if lib_tag:
            lines.append(f'; Library: {lib_tag}')

        lines.append(f'; Instructions: ~{asm_lines}')

        callers = self._format_xrefs(func.get('simple_inbound_xrefs'))
        if callers:
            lines.append(f'; Callers: {callers}')

        callees = self._format_xrefs(func.get('simple_outbound_xrefs'))
        if callees:
            lines.append(f'; Callees: {callees}')

        strings = self._format_strings(func.get('string_literals'))
        if strings:
            lines.append(f'; Strings: {strings}')

        dangerous = self._format_dangerous_apis(func.get('dangerous_api_calls'))
        if dangerous:
            lines.append(f'; Dangerous APIs: {dangerous}')

        lines.append('; ' + '=' * 60)
        return lines

    # ------------------------------------------------------------------
    # Header data formatters
    # ------------------------------------------------------------------

    @staticmethod
    def _format_xrefs(xrefs_json: Any) -> str:
        if not xrefs_json:
            return ''
        try:
            xrefs = json.loads(xrefs_json) if isinstance(xrefs_json, str) else xrefs_json
        except (json.JSONDecodeError, TypeError):
            return ''
        if not isinstance(xrefs, list):
            return ''

        parts: List[str] = []
        for x in xrefs[:20]:
            name = x.get('function_name', '?')
            module = x.get('module_name', '')
            fid = x.get('function_id')
            if module and module != 'internal':
                parts.append(f"{name} [{module}]")
            elif fid is not None:
                parts.append(f"{name} (id:{fid})")
            else:
                parts.append(name)
        suffix = f" ... (+{len(xrefs) - 20} more)" if len(xrefs) > 20 else ""
        return ', '.join(parts) + suffix

    @staticmethod
    def _format_strings(strings_json: Any) -> str:
        if not strings_json:
            return ''
        try:
            strings = json.loads(strings_json) if isinstance(strings_json, str) else strings_json
        except (json.JSONDecodeError, TypeError):
            return ''
        if not isinstance(strings, list):
            return ''

        parts: List[str] = []
        for s in strings[:10]:
            val = s.get('value', s) if isinstance(s, dict) else str(s)
            truncated = val[:60] + '...' if len(str(val)) > 60 else str(val)
            parts.append(f'"{truncated}"')
        suffix = f" ... (+{len(strings) - 10} more)" if len(strings) > 10 else ""
        return ', '.join(parts) + suffix

    @staticmethod
    def _format_dangerous_apis(dangerous_json: Any) -> str:
        if not dangerous_json:
            return ''
        try:
            apis = json.loads(dangerous_json) if isinstance(dangerous_json, str) else dangerous_json
        except (json.JSONDecodeError, TypeError):
            return ''
        if isinstance(apis, list):
            names = [a.get('name', str(a)) if isinstance(a, dict) else str(a) for a in apis[:15]]
            return ', '.join(names)
        return ''

    # ------------------------------------------------------------------
    # Index helpers
    # ------------------------------------------------------------------

    def _index_functions(self, functions: List[Dict], filename: str,
                         function_index: Dict[str, Any],
                         is_library: bool = False) -> None:
        for func in functions:
            name = func.get('function_name')
            if not name:
                continue
            mangled = func.get('mangled_name')
            func_id = func.get('function_id')
            has_asm = bool(func.get('assembly_code'))

            if name in function_index:
                existing = function_index[name]
                if filename not in existing.get('asm_files', []):
                    existing.setdefault('asm_files', []).append(filename)
                continue

            lib_tag = func.get('_library_tag') or (
                CppGenerator._detect_library_tag(name, mangled) if not is_library else None
            )

            function_index[name] = {
                'asm_files': [filename],
                'library': lib_tag if is_library else CppGenerator._detect_library_tag(name, mangled),
                'function_id': func_id,
                'has_assembly': has_asm,
            }

    def merge_into_function_index(self, asm_index: Dict[str, Any]) -> None:
        """Merge ASM index entries into an existing function_index.json on disk."""
        index_path = self.output_dir / "function_index.json"
        existing: Dict[str, Any] = {}

        safe_path = self._long_path(index_path)
        try:
            if safe_path.exists():
                with open(safe_path, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
        except Exception:
            pass

        for name, entry in asm_index.items():
            if name in existing:
                existing[name].setdefault('asm_files', [])
                for af in entry.get('asm_files', []):
                    if af not in existing[name]['asm_files']:
                        existing[name]['asm_files'].append(af)
                if 'has_assembly' not in existing[name]:
                    existing[name]['has_assembly'] = entry.get('has_assembly', False)
            else:
                existing[name] = entry

        try:
            with open(safe_path, 'w', encoding='utf-8') as f:
                json.dump(existing, f, indent=4, ensure_ascii=False, sort_keys=True)
            debug_print(f"Merged ASM index ({len(asm_index)} entries) into {index_path}")
        except Exception as e:
            debug_print(f"ERROR - Failed to write merged function index: {e}")
