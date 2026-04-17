"""
Storage module for persisting attack results and campaigns.
"""

from .memory_store import MemoryStore, get_store

__all__ = ["MemoryStore", "get_store"]
