import sys
import os
import sqlite3
import hashlib
import json
import base64
from datetime import datetime, timedelta

def calculate_file_hashes(file_path):
    """Calculate MD5 and SHA256 hashes of a file"""
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                
        return {
            'md5': md5_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
    except Exception as e:
        print(f"Error calculating file hashes for {file_path}: {str(e)}", file=sys.stderr)
        return None

def check_files_for_analysis(common_db_path, candidate_paths, current_flags_json):
    """
    Checks a batch of files to see if they need analysis based on hash, flags, or stale locks.
    
    Returns a list of file paths that require analysis.
    """
    if not os.path.exists(common_db_path):
        # If the DB doesn't exist, all candidate files need analysis.
        print(f"INFO: Analysis database does not exist at '{common_db_path}'. All {len(candidate_paths)} candidate files will be analyzed.", file=sys.stderr)
        return candidate_paths

    try:
        # Validate input parameters
        if not candidate_paths:
            print("INFO: No candidate files provided for analysis check.", file=sys.stderr)
            return []
            
        current_flags = json.loads(current_flags_json)
        # Normalize for comparison: remove force_reanalyze as it's handled by the caller
        current_flags_norm = {k: v for k, v in current_flags.items() if k != 'force_reanalyze'}

        files_to_process = []
        valid_candidate_paths = []
        
        # Pre-filter valid file paths to avoid database queries for non-existent files
        for path in candidate_paths:
            if not os.path.exists(path):
                print(f"Warning: Skipping non-existent file path: {path}", file=sys.stderr)
                continue
            valid_candidate_paths.append(path)
        
        if not valid_candidate_paths:
            print("INFO: No valid candidate files found after path validation.", file=sys.stderr)
            return []
        
        conn = None
        try:
            conn = sqlite3.connect(common_db_path)
            cursor = conn.cursor()
            
            # Create a placeholder string for the query
            placeholders = ','.join('?' for _ in valid_candidate_paths)
            query = f'SELECT file_path, status, md5_hash, sha256_hash, analysis_flags, analysis_start_timestamp FROM analyzed_files WHERE file_path IN ({placeholders})'
            
            cursor.execute(query, valid_candidate_paths)
            db_results = {row[0]: row[1:] for row in cursor.fetchall()}
            
        finally:
            if conn:
                conn.close()

        for path in valid_candidate_paths:
            needs_analysis = False
            reason = ""

            db_record = db_results.get(path)

            if not db_record:
                needs_analysis = True
                reason = "No previous analysis found."
            else:
                status, stored_md5, stored_sha256, stored_flags_json, start_time_str = db_record
                
                # 1. Check for stale locks
                if status == 'ANALYZING':
                    if start_time_str:
                        try:
                            lock_time = datetime.strptime(start_time_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
                            if datetime.now() - lock_time > timedelta(hours=3):
                                needs_analysis = True
                                reason = "Stale lock found (>3 hours)."
                        except (ValueError, TypeError):
                            needs_analysis = True # Take over if timestamp is malformed
                            reason = "Malformed timestamp on locked file."
                    else:
                        needs_analysis = True # Take over if status is ANALYZING but no timestamp
                        reason = "ANALYZING status without a start time."
                
                # 2. If not stale-locked, check file hash
                if not needs_analysis:
                    current_hashes = calculate_file_hashes(path)
                    if not current_hashes or current_hashes['md5'] != stored_md5 or current_hashes['sha256'] != stored_sha256:
                        needs_analysis = True
                        reason = "File hash has changed."

                # 3. If hash matches, check analysis flags
                if not needs_analysis:
                    try:
                        stored_flags = json.loads(stored_flags_json or '{}')
                        stored_flags_norm = {k: v for k, v in stored_flags.items() if k != 'force_reanalyze'}
                        if current_flags_norm != stored_flags_norm:
                            needs_analysis = True
                            reason = "Analysis flags have changed."
                    except (json.JSONDecodeError, TypeError):
                        needs_analysis = True
                        reason = "Could not parse stored analysis flags."

            if needs_analysis:
                files_to_process.append(path)
                print(f"INFO: Queuing file '{os.path.basename(path)}' for analysis. Reason: {reason}", file=sys.stderr)

        # Provide summary feedback
        if files_to_process:
            print(f"INFO: Analysis check complete. {len(files_to_process)} out of {len(valid_candidate_paths)} files require analysis.", file=sys.stderr)
        else:
            print(f"INFO: Analysis check complete. All {len(valid_candidate_paths)} files are up to date.", file=sys.stderr)

        return files_to_process
            
    except Exception as e:
        print(f"CRITICAL: An error occurred during batch analysis check: {str(e)}", file=sys.stderr)
        # In case of a critical error, return no files to be safe and prevent a flood of re-analysis.
        return []

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python check_file_analyzed.py <path_to_analyzed_files.db> <current_flags_base64>", file=sys.stderr)
        sys.exit(2)
        
    db_path = sys.argv[1]
    flags_base64 = sys.argv[2]
    
    # Decode Base64 JSON to avoid command line parsing issues
    try:
        flags_json = base64.b64decode(flags_base64).decode('utf-8')
    except Exception as e:
        print(f"Error decoding Base64 flags: {e}", file=sys.stderr)
        sys.exit(2)

    # Read all file paths from stdin
    candidate_paths = [line.strip() for line in sys.stdin if line.strip() and os.path.exists(line.strip())]

    if not candidate_paths:
        sys.exit(0)

    paths_to_process = check_files_for_analysis(db_path, candidate_paths, flags_json)
    
    # Print the filtered list of files to stdout
    for path in paths_to_process:
        print(path) 