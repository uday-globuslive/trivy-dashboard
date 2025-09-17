"""
Caching utilities for improved performance
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Optional
import json
import hashlib

logger = logging.getLogger(__name__)

class CacheManager:
    """In-memory cache manager for dashboard data"""
    
    def __init__(self, default_ttl: int = 3600):
        self.cache = {}
        self.default_ttl = default_ttl  # Default TTL in seconds
        logger.info(f"🗄️ Initialized cache manager with {default_ttl}s default TTL")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            item = self.cache[key]
            if datetime.now() < item['expires_at']:
                logger.debug(f"📋 Cache hit for key: {key}")
                return item['value']
            else:
                # Cache expired, remove it
                del self.cache[key]
                logger.debug(f"⏰ Cache expired for key: {key}")
        
        logger.debug(f"📋 Cache miss for key: {key}")
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        if ttl is None:
            ttl = self.default_ttl
        
        expires_at = datetime.now() + timedelta(seconds=ttl)
        self.cache[key] = {
            'value': value,
            'expires_at': expires_at,
            'created_at': datetime.now()
        }
        
        logger.debug(f"💾 Cached value for key: {key} (TTL: {ttl}s)")
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if key in self.cache:
            del self.cache[key]
            logger.debug(f"🗑️ Deleted cache key: {key}")
            return True
        return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        count = len(self.cache)
        self.cache.clear()
        logger.info(f"🧹 Cleared {count} cache entries")
    
    def cleanup_expired(self) -> int:
        """Remove expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, item in self.cache.items()
            if now >= item['expires_at']
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logger.info(f"🧹 Cleaned up {len(expired_keys)} expired cache entries")
        
        return len(expired_keys)
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        total_entries = len(self.cache)
        now = datetime.now()
        
        expired_count = sum(
            1 for item in self.cache.values()
            if now >= item['expires_at']
        )
        
        valid_count = total_entries - expired_count
        
        return {
            'total_entries': total_entries,
            'valid_entries': valid_count,
            'expired_entries': expired_count,
            'hit_rate': getattr(self, '_hit_count', 0) / max(getattr(self, '_total_requests', 1), 1)
        }
    
    def generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = {
            'args': args,
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        
        return f"cache_{key_hash}"


class MemoizedCache:
    """Decorator for caching function results"""
    
    def __init__(self, ttl: int = 3600, cache_manager: Optional[CacheManager] = None):
        self.ttl = ttl
        self.cache_manager = cache_manager or CacheManager(ttl)
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{func.__name__}_{self.cache_manager.generate_key(*args, **kwargs)}"
            
            # Try to get from cache
            result = self.cache_manager.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            self.cache_manager.set(cache_key, result, self.ttl)
            
            return result
        
        return wrapper


# Global cache manager instance
cache_manager = CacheManager()

# Convenience decorators
def cache_for(seconds: int):
    """Decorator to cache function results for specified seconds"""
    return MemoizedCache(ttl=seconds, cache_manager=cache_manager)

def cache_short_term(func):
    """Decorator for short-term caching (5 minutes)"""
    return MemoizedCache(ttl=300, cache_manager=cache_manager)(func)

def cache_medium_term(func):
    """Decorator for medium-term caching (1 hour)"""
    return MemoizedCache(ttl=3600, cache_manager=cache_manager)(func)

def cache_long_term(func):
    """Decorator for long-term caching (24 hours)"""
    return MemoizedCache(ttl=86400, cache_manager=cache_manager)(func)
