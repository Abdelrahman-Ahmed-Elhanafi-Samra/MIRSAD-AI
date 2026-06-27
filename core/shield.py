import ipaddress
from collections import OrderedDict
from typing import Any, Optional

from core.decorators import monitor_performance
from core.models import NetworkPacket


class CoreShield:
    """
    The Gateway Sanitizer: Transforms raw incoming dictionaries into
    Machine-Learning ready Feature Vectors, backed by a bounded LRU Cache.
    """
    
    def __init__(self, max_cache_size: int = 1000) -> None:
        self._max_cache_size = max_cache_size
        # OrderedDict maintains insertion order, making LRU eviction O(1)
        self._safe_cache: OrderedDict[str, bool] = OrderedDict()
        
    @monitor_performance
    def process_payload(self, raw_data: dict[str, Any]) -> Optional[list[float]]:
        """
        Returns:
            - None: If packet is known safe (Fast-Passed via Cache).
            - list[float]: Cleaned numerical vector ready for the ML Brain.
        """
        # 1. Hydrate raw dictionary into an Immutable Domain Model
        packet = NetworkPacket(
            source_ip=raw_data["source_ip"],
            destination_port=raw_data["destination_port"],
            packet_size_bytes=raw_data["packet_size_bytes"],
            protocol=raw_data["protocol"],
            timestamp=raw_data["timestamp"],
        )
        
        cache_key = packet.generate_cache_key()
        
        # 2. Fast-Path (Cache Lookup)
        if cache_key in self._safe_cache:
            # LRU Rule: If accessed, move it to the end (Mark as recently used)
            self._safe_cache.move_to_end(cache_key)
            return None  # Drop packet silently, do not wake up the ML brain
        
        # 3. Slow-Path (Feature Extraction for Scikit-Learn)
        # Convert IPv4 string -> 32-bit Mathematical Integer -> Float
        ip_as_int = int(ipaddress.ip_address(packet.source_ip))
        
        feature_vector = [
            float(ip_as_int),
            float(packet.destination_port),
            float(packet.packet_size_bytes),
        ]
        
        return feature_vector
    
    def register_as_safe(self, cache_key: str) -> None:
        """Called by the ML Brain when a payload scores as harmless."""
        self._safe_cache[cache_key] = True
        
        # LRU Eviction Rule: If cache exceeds limit, drop the OLDEST item (FIFO)
        if len(self._safe_cache) > self._max_cache_size:
            self._safe_cache.popitem(last=False)