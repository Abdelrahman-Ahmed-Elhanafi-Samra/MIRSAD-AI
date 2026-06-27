import time
from core.models import NetworkPacket

def test_cache_key_poisoning_prevention():
    """
    Proves that a hacker sending a tiny packet followed by a massive packet
    from the SAME IP will generate TWO DIFFERENT cache keys (Bypassing the trap).
    """
    attacker_ip = "192.168.1.50"
    
    # 1. Attacker sends a harmless Ping (64 bytes)
    harmless_packet = NetworkPacket(
        source_ip=attacker_ip,
        destination_port=80,
        packet_size_bytes=64,  # TINY
        protocol="TCP",
        timestamp=time.time(),
    )
    
    # 2. Attacker sends a Data Exfiltration payload (15,000 bytes)
    malicious_packet = NetworkPacket(
        source_ip=attacker_ip,
        destination_port=80,
        packet_size_bytes=15000,  # MASSIVE_OUTLIER
        protocol="TCP",
        timestamp=time.time(),
    )
    
    key_1 = harmless_packet.generate_cache_key()
    key_2 = malicious_packet.generate_cache_key()
    
    # ASSERTION: The keys MUST NOT match, forcing the cache to reject key_2!
    assert (
        key_1 != key_2
    ), f"CRITICAL SECURITY FLAW: Keys matched! {key_1} == {key_2}"