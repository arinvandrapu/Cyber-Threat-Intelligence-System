"""Small statistics shared by the evaluations."""

from __future__ import annotations

import math


def wilson(k: float, n: int, z: float = 1.96, ndigits: int = 4) -> tuple[float, float]:
    """Wilson score interval for ``k`` successes in ``n`` trials, rounded to ``ndigits``.

    ``k`` may be fractional (expected hits under ties). ``n == 0`` gives ``(0.0, 0.0)``.
    Callers pass their own ``z``: risk-eval pre-registered 1.959964, the others use 1.96.
    """
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return round(max(0.0, centre - half), ndigits), round(min(1.0, centre + half), ndigits)
