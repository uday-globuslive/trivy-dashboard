"""
File-based metadata tracker for persistent incremental refresh.
Stores file metadata (path, lastModified, project, scan_id) in a JSON file
to survive app restarts.
"""

import json
import os
import logging
from threading import Lock
from datetime import datetime

logger = logging.getLogger(__name__)


class MetadataTracker:
    """Persistent file-based metadata tracker for incremental refresh."""
    
    def __init__(self, metadata_file='.trivy_metadata.json'):
        """
        Initialize the metadata tracker.
        
        Args:
            metadata_file: Path to the JSON file storing metadata
        """
        self.metadata_file = metadata_file
        self.metadata = {}
        self.lock = Lock()
        self._load_metadata()
    
    def _load_metadata(self):
        """Load metadata from JSON file."""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
                logger.info(f"📂 Loaded {len(self.metadata)} file metadata records from {self.metadata_file}")
            else:
                logger.info(f"📂 No existing metadata file found, starting fresh")
                self.metadata = {}
        except Exception as e:
            logger.error(f"❌ Error loading metadata file: {e}")
            self.metadata = {}
    
    def _save_metadata(self):
        """Save metadata to JSON file atomically."""
        try:
            # Write to temp file first, then rename for atomic operation
            temp_file = f"{self.metadata_file}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2, default=str)
            
            # Atomic rename
            if os.path.exists(self.metadata_file):
                os.replace(temp_file, self.metadata_file)
            else:
                os.rename(temp_file, self.metadata_file)
            
            logger.debug(f"💾 Saved {len(self.metadata)} metadata records to {self.metadata_file}")
        except Exception as e:
            logger.error(f"❌ Error saving metadata file: {e}")
    
    def has_file(self, file_path):
        """
        Check if a file is already tracked in metadata.
        
        Args:
            file_path: Unique identifier for the file
            
        Returns:
            True if file exists in metadata, False otherwise
        """
        with self.lock:
            return file_path in self.metadata
    
    def get_all_files(self):
        """
        Get all tracked file paths.
        
        Returns:
            Set of all tracked file paths
        """
        with self.lock:
            return set(self.metadata.keys())
    
    def get_file_metadata(self, file_path):
        """
        Get metadata for a specific file.
        
        Args:
            file_path: Unique identifier for the file
            
        Returns:
            Dictionary with file metadata, or None if not found
        """
        with self.lock:
            return self.metadata.get(file_path)
    
    def has_changed(self, file_path, current_last_modified):
        """
        Check if a file has changed since last refresh.
        
        Args:
            file_path: Unique identifier for the file
            current_last_modified: Current lastModified timestamp string
            
        Returns:
            True if file is new or has changed, False otherwise
        """
        with self.lock:
            if file_path not in self.metadata:
                return True  # New file
            
            stored_last_modified = self.metadata[file_path].get('lastModified', '')
            return stored_last_modified != current_last_modified
    
    def update_file(self, file_path, last_modified, project_key, scan_id):
        """
        Update metadata for a file.
        
        Args:
            file_path: Unique identifier for the file
            last_modified: lastModified timestamp string
            project_key: Project name/key
            scan_id: Scan identifier
        """
        with self.lock:
            self.metadata[file_path] = {
                'lastModified': last_modified,
                'project': project_key,
                'scan_id': scan_id,
                'updated_at': datetime.now().isoformat()
            }
    
    def get_deleted_files(self, current_files):
        """
        Find files that were tracked but no longer exist in current fetch.
        
        Args:
            current_files: Set of current file paths
            
        Returns:
            List of (file_path, project, scan_id) tuples for deleted files
        """
        with self.lock:
            deleted = []
            for file_path, metadata in list(self.metadata.items()):
                if file_path not in current_files:
                    deleted.append((
                        file_path,
                        metadata.get('project'),
                        metadata.get('scan_id')
                    ))
                    # Remove from metadata
                    del self.metadata[file_path]
            
            return deleted
    
    def save(self):
        """Explicitly save metadata to disk."""
        with self.lock:
            self._save_metadata()
    
    def clear_all(self):
        """Clear all metadata (force full refresh)."""
        with self.lock:
            self.metadata = {}
            self._save_metadata()
            logger.info("🗑️ Cleared all file metadata - force full refresh")
    
    def get_stats(self):
        """Get statistics about tracked files."""
        with self.lock:
            # Calculate file size if it exists
            file_size = 0
            if os.path.exists(self.metadata_file):
                try:
                    file_size = os.path.getsize(self.metadata_file)
                except:
                    pass
            
            return {
                'total_files': len(self.metadata),
                'projects': len(set(m.get('project') for m in self.metadata.values())),
                'file': self.metadata_file,
                'exists': os.path.exists(self.metadata_file),
                'metadata_size_bytes': file_size
            }
