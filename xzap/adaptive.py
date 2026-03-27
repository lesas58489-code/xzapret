"""
XZAP Adaptive Strategy.

Monitors retransmits/freezes and automatically escalates obfuscation:
  Level 0: normal (1 repeat, 32-64B fragments)
  Level 1: moderate (2 repeats, 16-48B, disorder)
  Level 2: aggressive (3 repeats, 8-32B, disorder + overlap)
  Level 3: extreme (3 repeats, 8-16B, full techniques)
"""

import time
from dataclasses import dataclass, field

MAX_LEVEL = 3
RETRANSMIT_THRESHOLD = 3
CALM_DOWN_SECONDS = 60


@dataclass
class StrategyLevel:
    repeats: int
    min_frag: int
    max_frag: int
    disorder: bool
    overlap: bool
    badseq: bool
    tls_mod: str


LEVELS = [
    StrategyLevel(1, 32, 64, False, False, False, "default"),
    StrategyLevel(2, 16, 48, True, False, False, "rnd"),
    StrategyLevel(3, 8, 32, True, True, False, "rnd,rndsni"),
    StrategyLevel(3, 8, 16, True, True, True, "rnd,rndsni,padencap"),
]


class AdaptiveStrategy:
    """Automatically adjust obfuscation based on connection quality."""

    def __init__(self):
        self._level = 0
        self._retransmits = 0
        self._last_retransmit = 0.0
        self._last_success = time.monotonic()

    @property
    def level(self) -> int:
        return self._level

    @property
    def config(self) -> StrategyLevel:
        return LEVELS[self._level]

    def on_retransmit(self):
        """Call when a retransmit is detected."""
        self._retransmits += 1
        self._last_retransmit = time.monotonic()
        if self._retransmits > RETRANSMIT_THRESHOLD:
            self._escalate()

    def on_success(self):
        """Call when data is successfully delivered."""
        self._last_success = time.monotonic()
        self._retransmits = max(0, self._retransmits - 1)
        # De-escalate if calm for CALM_DOWN_SECONDS
        if (self._last_success - self._last_retransmit > CALM_DOWN_SECONDS
                and self._level > 0):
            self._deescalate()

    def _escalate(self):
        if self._level < MAX_LEVEL:
            self._level += 1
            self._retransmits = 0

    def _deescalate(self):
        if self._level > 0:
            self._level -= 1
            self._retransmits = 0

    def reset(self):
        self._level = 0
        self._retransmits = 0
        self._last_retransmit = 0.0
        self._last_success = time.monotonic()

    @property
    def state(self) -> dict:
        cfg = self.config
        return {
            "level": self._level,
            "retransmits": self._retransmits,
            "repeats": cfg.repeats,
            "fragment_range": (cfg.min_frag, cfg.max_frag),
            "disorder": cfg.disorder,
            "overlap": cfg.overlap,
            "badseq": cfg.badseq,
            "tls_mod": cfg.tls_mod,
        }
