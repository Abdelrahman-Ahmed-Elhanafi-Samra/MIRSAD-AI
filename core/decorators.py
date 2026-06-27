import time
from functools import wraps
from typing import Callable, Any


def monitor_performance(func: Callable) -> Callable:
    """
    Security Decorator: Measures the precise execution time of a target function.
    If the execution exceeds the safe threshold (0.5 seconds), it logs a
    high-priority security alert (Potential DoS attack or unoptimized DB query).
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # 1. Record the exact CPU start time
        start_time = time.perf_counter()

        # 2. Execute the original target function and save its returned value
        result = func(*args, **kwargs)

        # 3. Calculate total time taken
        execution_time = time.perf_counter() - start_time

        # 4. Log the standard health check metric
        print(
            f"[Mirsad Sentinel] '{func.__name__}' executed in {execution_time:.4f}s"
        )

        # 5. The Ambush Trigger (Threshold check)
        if execution_time > 0.5:
            print(
                f"[SECURITY ALERT] Bottleneck detected in '{func.__name__}'! Execution exceeded 0.5s limit."
            )

        return result

    return wrapper