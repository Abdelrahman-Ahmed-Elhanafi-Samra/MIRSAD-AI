import time
from core.decorators import monitor_performance


def test_monitor_performance_fast(capfd):
    """
    Test Case 1: A fast function should log the metric, but MUST NOT trigger an alert.
    """

    @monitor_performance
    def quick_network_ping() -> str:
        time.sleep(0.1)  # Fast task (0.1s)
        return "PONG"

    # Run function
    output = quick_network_ping()

    # 1. Assert the decorator didn't lose the return value
    assert output == "PONG"

    # 2. Capture what the decorator printed to the terminal
    captured_terminal = capfd.readouterr().out

    # Assert standard log exists, but security alert DOES NOT exist
    assert "[Mirsad Sentinel]" in captured_terminal
    assert "[SECURITY ALERT]" not in captured_terminal


def test_monitor_performance_slow(capfd):
    """
    Test Case 2: A slow function MUST trigger the [SECURITY ALERT].
    """

    @monitor_performance
    def heavy_malware_scan() -> bool:
        time.sleep(0.6)  # Slow task (0.6s) -> Exceeds 0.5s threshold
        return True

    heavy_malware_scan()

    captured_terminal = capfd.readouterr().out

    # Assert the security ambush caught it
    assert "[SECURITY ALERT]" in captured_terminal