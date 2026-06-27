import time
from core.shield import CoreShield


def test_core_shield_flow():
    # Cache capacity restricted to exactly 2 items for testing boundary conditions
    shield = CoreShield(max_cache_size=2)

    raw_packet_1 = {
        "source_ip": "10.0.0.1",
        "destination_port": 80,
        "packet_size_bytes": 100,
        "protocol": "TCP",
        "timestamp": time.time(),
    }

    # 1. First encounter -> Must trigger slow-path and return Feature Vector
    vector = shield.process_payload(raw_packet_1)
    assert vector is not None
    assert len(vector) == 3
    assert vector[1] == 80.0  # Port check

    # 2. Simulate ML Brain registering the signature as harmless
    from core.models import NetworkPacket

    p_model = NetworkPacket(**raw_packet_1)
    shield.register_as_safe(p_model.generate_cache_key())

    # 3. Second encounter of EXACT same payload -> Must return None (Cache Hit)
    assert shield.process_payload(raw_packet_1) is None


def test_lru_cache_eviction():
    shield = CoreShield(max_cache_size=2)

    # Register 3 keys sequentially into a size-2 buffer
    shield.register_as_safe("KEY_A")
    shield.register_as_safe("KEY_B")
    shield.register_as_safe("KEY_C")  # Triggers FIFO eviction of KEY_A

    assert "KEY_A" not in shield._safe_cache
    assert "KEY_B" in shield._safe_cache
    assert "KEY_C" in shield._safe_cache