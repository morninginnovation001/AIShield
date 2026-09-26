"""
File Reader Tool for Agentic RAG
⚠️ MAJOR ATTACK VECTOR - Can read arbitrary files
"""

import logging
from pathlib import Path
from typing import Dict, Any, List, Optional


class FileReaderTool:
    """
    File reading tool - INTENTIONALLY VULNERABLE for research.

    This tool can read arbitrary files and is a major attack vector
    for prompt injection attacks where malicious commands inject
    file paths to leak sensitive information.
    """

    def __init__(self, allowed_directories: Optional[List[str]] = None,
                 max_file_size_kb: int = 1024):
        """
        Initialize file reader tool.

        Args:
            allowed_directories: List of allowed directory paths (None = all allowed)
            max_file_size_kb: Maximum file size to read in KB
        """
        self.name = "file_reader"
        self.description = "Reads the contents of a text file from the filesystem."
        self.parameters = {
            "path": {
                "type": "string",
                "description": "Path to the file to read",
                "required": True
            }
        }

        self.allowed_directories = allowed_directories
        self.max_file_size_kb = max_file_size_kb
        self.logger = logging.getLogger(__name__)

    def execute(self, path: str) -> Dict[str, Any]:
        """
        Read a file from the filesystem.

        ⚠️ VULNERABLE BY DESIGN - minimal validation for research purposes.

        Args:
            path: File path to read

        Returns:
            Dictionary with file contents and status
        """
        try:
            file_path = Path(path).resolve()

            # Check if path exists
            if not file_path.exists():
                return {
                    'success': False,
                    'error': f"File not found: {path}",
                    'content': None
                }

            # Check if it's a file (not directory)
            if not file_path.is_file():
                return {
                    'success': False,
                    'error': f"Path is not a file: {path}",
                    'content': None
                }

            # Optional: Check allowed directories
            if self.allowed_directories:
                allowed = False
                for allowed_dir in self.allowed_directories:
                    if str(file_path).startswith(str(Path(allowed_dir).resolve())):
                        allowed = True
                        break

                if not allowed:
                    self.logger.warning(f"Blocked read attempt to unauthorized path: {path}")
                    return {
                        'success': False,
                        'error': f"Access denied - path not in allowed directories",
                        'content': None
                    }

            # Check file size
            file_size_kb = file_path.stat().st_size / 1024
            if file_size_kb > self.max_file_size_kb:
                return {
                    'success': False,
                    'error': f"File too large: {file_size_kb:.1f}KB (max: {self.max_file_size_kb}KB)",
                    'content': None
                }

            # Read file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            self.logger.info(f"FileReader: Read {path} ({len(content)} characters)")

            return {
                'success': True,
                'content': content,
                'path': str(file_path),
                'size_bytes': file_path.stat().st_size,
                'error': None
            }

        except UnicodeDecodeError:
            return {
                'success': False,
                'error': "File is not a text file (binary content detected)",
                'content': None
            }
        except PermissionError:
            return {
                'success': False,
                'error': f"Permission denied: {path}",
                'content': None
            }
        except Exception as e:
            self.logger.error(f"FileReader error: {e}")
            return {
                'success': False,
                'error': str(e),
                'content': None
            }

    def get_schema(self) -> Dict[str, Any]:
        """Get tool schema for function calling."""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters
        }