"""
Disk-based caching system for Trivy Dashboard
Uses SQLite for structured data storage and JSON for scan/vulnerability details
Implements hybrid in-memory + disk caching with automatic memory management
"""

import logging
import sqlite3
import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Any, Optional, List, Dict
from pathlib import Path
import threading

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class DiskCacheManager:
    """Hybrid disk + memory cache manager for large datasets"""
    
    def __init__(self, cache_dir: str = './data/cache', max_memory_mb: int = 500):
        """
        Initialize disk cache manager
        
        Args:
            cache_dir: Directory to store cache files
            max_memory_mb: Maximum memory to use for in-memory cache (MB)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.cache_dir / 'trivy_cache.db'
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.current_memory_usage = 0
        
        # In-memory cache for frequently accessed data
        self.memory_cache = {}
        self.lock = threading.RLock()
        
        # Initialize database
        self._init_database()
        
        logger.info(f"🗄️ Initialized disk cache at {self.cache_dir}")
        logger.info(f"📊 Memory limit: {max_memory_mb}MB")
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Projects table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS projects (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Scans table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        id TEXT PRIMARY KEY,
                        project_name TEXT NOT NULL,
                        build_number TEXT NOT NULL,
                        timestamp TIMESTAMP,
                        data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (project_name) REFERENCES projects(name)
                    )
                ''')
                
                # Index for scans table
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_scans_project_timestamp 
                    ON scans(project_name, timestamp)
                ''')
                
                # Vulnerabilities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id TEXT PRIMARY KEY,
                        cve_id TEXT NOT NULL,
                        scan_id TEXT NOT NULL,
                        severity TEXT,
                        data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans(id)
                    )
                ''')
                
                # Indexes for vulnerabilities table
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id 
                    ON vulnerabilities(cve_id)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id 
                    ON vulnerabilities(scan_id)
                ''')
                
                # Cache metadata table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cache_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                logger.info("✅ Database schema initialized")
                
        except Exception as e:
            logger.error(f"❌ Error initializing database: {str(e)}")
            raise
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate size of object in bytes"""
        try:
            if isinstance(obj, str):
                return len(obj.encode('utf-8'))
            elif isinstance(obj, (dict, list)):
                return len(json.dumps(obj, cls=DateTimeEncoder).encode('utf-8'))
            else:
                return len(str(obj).encode('utf-8'))
        except:
            return 1000  # Conservative estimate
    
    def _evict_cache(self, required_size: int):
        """Evict least recently used items from memory cache"""
        if not self.memory_cache:
            return
        
        # Sort by last access time and remove oldest items
        sorted_items = sorted(
            self.memory_cache.items(),
            key=lambda x: x[1].get('last_access', datetime.now())
        )
        
        freed_size = 0
        for key, item in sorted_items:
            if freed_size >= required_size:
                break
            freed_size += item.get('size', 0)
            del self.memory_cache[key]
        
        self.current_memory_usage = max(0, self.current_memory_usage - freed_size)
        logger.debug(f"🗑️ Evicted {freed_size} bytes from memory cache")
    
    # ==================== PROJECTS ====================
    def save_projects(self, projects: Dict[str, Any]) -> bool:
        """Save all projects to disk"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Clear existing projects
                    cursor.execute('DELETE FROM projects')
                    
                    # Insert new projects
                    for project_name, project_data in projects.items():
                        project_json = json.dumps(project_data, cls=DateTimeEncoder)
                        cursor.execute('''
                            INSERT OR REPLACE INTO projects (id, name, data, updated_at)
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                        ''', (project_name, project_name, project_json))
                    
                    conn.commit()
                    logger.info(f"💾 Saved {len(projects)} projects to disk")
                    return True
        except Exception as e:
            logger.error(f"❌ Error saving projects: {str(e)}")
            return False
    
    def load_projects(self) -> Dict[str, Any]:
        """Load all projects from disk"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT name, data FROM projects')
                    
                    projects = {}
                    for name, data in cursor.fetchall():
                        projects[name] = json.loads(data)
                    
                    logger.info(f"📂 Loaded {len(projects)} projects from disk")
                    return projects
        except Exception as e:
            logger.error(f"❌ Error loading projects: {str(e)}")
            return {}
    
    # ==================== SCANS ====================
    def save_scan(self, scan_id: str, scan_data: Dict[str, Any]) -> bool:
        """Save a single scan to disk"""
        try:
            with self.lock:
                project_name = scan_data.get('project')
                build_number = scan_data.get('build_number')
                timestamp = scan_data.get('timestamp')
                
                scan_json = json.dumps(scan_data, cls=DateTimeEncoder)
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO scans (id, project_name, build_number, timestamp, data, updated_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (scan_id, project_name, build_number, timestamp, scan_json))
                    
                    conn.commit()
                    logger.debug(f"💾 Saved scan {scan_id} to disk")
                    return True
        except Exception as e:
            logger.error(f"❌ Error saving scan {scan_id}: {str(e)}")
            return False
    
    def load_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Load a single scan from disk"""
        try:
            with self.lock:
                # Check memory cache first
                if scan_id in self.memory_cache:
                    item = self.memory_cache[scan_id]
                    item['last_access'] = datetime.now()
                    return item['data']
                
                # Load from disk
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT data FROM scans WHERE id = ?', (scan_id,))
                    result = cursor.fetchone()
                    
                    if result:
                        scan_data = json.loads(result[0])
                        
                        # Cache in memory if space available
                        data_size = self._estimate_size(scan_data)
                        if self.current_memory_usage + data_size > self.max_memory_bytes:
                            self._evict_cache(data_size)
                        
                        self.memory_cache[scan_id] = {
                            'data': scan_data,
                            'size': data_size,
                            'last_access': datetime.now()
                        }
                        self.current_memory_usage += data_size
                        
                        return scan_data
                    
                    return None
        except Exception as e:
            logger.error(f"❌ Error loading scan {scan_id}: {str(e)}")
            return None
    
    def load_all_scans(self) -> Dict[str, Dict[str, Any]]:
        """Load all scan metadata from disk (without vulnerability details)"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT id, data FROM scans')
                    
                    scans = {}
                    for scan_id, data in cursor.fetchall():
                        scans[scan_id] = json.loads(data)
                    
                    logger.info(f"📂 Loaded {len(scans)} scans from disk")
                    return scans
        except Exception as e:
            logger.error(f"❌ Error loading all scans: {str(e)}")
            return {}
    
    def load_scans_by_project(self, project_name: str) -> Dict[str, Dict[str, Any]]:
        """Load all scans for a specific project"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'SELECT id, data FROM scans WHERE project_name = ? ORDER BY timestamp DESC',
                        (project_name,)
                    )
                    
                    scans = {}
                    for scan_id, data in cursor.fetchall():
                        scans[scan_id] = json.loads(data)
                    
                    return scans
        except Exception as e:
            logger.error(f"❌ Error loading scans for project {project_name}: {str(e)}")
            return {}
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its vulnerabilities"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
                    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
                    conn.commit()
                    
                    # Remove from memory cache
                    if scan_id in self.memory_cache:
                        del self.memory_cache[scan_id]
                    
                    logger.debug(f"🗑️ Deleted scan {scan_id}")
                    return True
        except Exception as e:
            logger.error(f"❌ Error deleting scan {scan_id}: {str(e)}")
            return False
    
    # ==================== VULNERABILITIES ====================
    def save_vulnerability(self, vuln_id: str, scan_id: str, vuln_data: Dict[str, Any]) -> bool:
        """Save a vulnerability to disk"""
        try:
            with self.lock:
                cve_id = vuln_data.get('id', '')
                severity = vuln_data.get('severity', '')
                
                vuln_json = json.dumps(vuln_data, cls=DateTimeEncoder)
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO vulnerabilities (id, cve_id, scan_id, severity, data, updated_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (vuln_id, cve_id, scan_id, severity, vuln_json))
                    
                    conn.commit()
                    return True
        except Exception as e:
            logger.error(f"❌ Error saving vulnerability {vuln_id}: {str(e)}")
            return False
    
    def load_vulnerabilities_by_scan(self, scan_id: str) -> Dict[str, Dict[str, Any]]:
        """Load all vulnerabilities for a scan"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'SELECT id, data FROM vulnerabilities WHERE scan_id = ?',
                        (scan_id,)
                    )
                    
                    vulns = {}
                    for vuln_id, data in cursor.fetchall():
                        vulns[vuln_id] = json.loads(data)
                    
                    return vulns
        except Exception as e:
            logger.error(f"❌ Error loading vulnerabilities for scan {scan_id}: {str(e)}")
            return {}
    
    def load_vulnerability_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """Load all vulnerability instances by CVE ID"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'SELECT data FROM vulnerabilities WHERE cve_id = ?',
                        (cve_id,)
                    )
                    
                    vulns = [json.loads(row[0]) for row in cursor.fetchall()]
                    return vulns
        except Exception as e:
            logger.error(f"❌ Error loading vulnerabilities for CVE {cve_id}: {str(e)}")
            return []
    
    # ==================== CACHE OPERATIONS ====================
    def clear_all(self) -> bool:
        """Clear all cache data"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM vulnerabilities')
                    cursor.execute('DELETE FROM scans')
                    cursor.execute('DELETE FROM projects')
                    conn.commit()
                
                self.memory_cache.clear()
                self.current_memory_usage = 0
                
                logger.info("🧹 Cleared all cache data")
                return True
        except Exception as e:
            logger.error(f"❌ Error clearing cache: {str(e)}")
            return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('SELECT COUNT(*) FROM projects')
                    project_count = cursor.fetchone()[0]
                    
                    cursor.execute('SELECT COUNT(*) FROM scans')
                    scan_count = cursor.fetchone()[0]
                    
                    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
                    vuln_count = cursor.fetchone()[0]
                    
                    # Get database file size
                    db_size = os.path.getsize(self.db_path) / (1024 * 1024)  # MB
                    
                    return {
                        'projects': project_count,
                        'scans': scan_count,
                        'vulnerabilities': vuln_count,
                        'memory_usage_mb': self.current_memory_usage / (1024 * 1024),
                        'memory_limit_mb': self.max_memory_bytes / (1024 * 1024),
                        'cached_items': len(self.memory_cache),
                        'disk_size_mb': db_size
                    }
        except Exception as e:
            logger.error(f"❌ Error getting cache stats: {str(e)}")
            return {}
