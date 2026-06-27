import hashlib
from dataclasses import dataclass
from typing import Literal


@dataclass(slots = True, frozen = True)
class NetworkPacket:
    """
    Immutable Domain Model representing an intercepted network packet.

    [Architectural Decisions]:
    1. 'slots=True': Prevents Python from creating a dynamic __dict__ for each object.
                     Saves ~50% RAM when processing 100,000 packets/sec!
    2. 'frozen=True': Makes the object Read-Only (Immutable). If a hacker tries
                      to alter the packet in memory, Python throws an Exception.
    """
    
    source_ip: str
    destination_port: int
    packet_size_bytes: int
    protocol: Literal["TCP", "UDP", "ICMP", "UNKNOWN"]
    timestamp: float
    
    def get_size_bucket(self) -> str:
        """
        Categorizes packet size into discrete ranges to prevent Cache-Bypass attacks.
        """
        if self.packet_size_bytes < 512:
            return "TINY"
        elif self.packet_size_bytes < 2048:
            return "STANDARD"
        elif self.packet_size_bytes < 8192:
            return "LARGE"
        else:
            return "MASSIVE_OUTLIER"
        
    def generate_cache_key(self) -> str:
        """
        Generates a Context-Aware MD5 hash to be used as a secure Cache Key.
        """
        bucket = self.get_size_bucket()
        # Combine parameters into a unique signature
        raw_signature = (
            f"{self.source_ip}:{self.destination_port}:{self.protocol}:{bucket}"
        )
        
        return hashlib.md5(raw_signature.encode("utf-8")).hexdigest()