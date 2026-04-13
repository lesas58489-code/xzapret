"""
XZAP Memory Manager — prevents memory leaks in long-running server.

Based on solar-trading-bot MemoryManager pattern:
  - Periodic gc.collect() (gen0+gen1 every 60s)
  - malloc_trim() to return memory to OS
  - RSS monitoring with auto-restart at threshold
  - Lightweight: no psutil dependency, uses /proc/self/status
"""

import asyncio
import ctypes
import gc
import logging
import os
import signal
import time

log = logging.getLogger("xzap.memory")


class MemoryManager:
    def __init__(self, gc_interval: int = 60, cleanup_interval: int = 300,
                 max_rss_mb: int = 200):
        self.gc_interval = gc_interval
        self.cleanup_interval = cleanup_interval
        self.max_rss_mb = max_rss_mb
        self._running = False
        self._libc = None
        self._gc_task = None
        self._cleanup_task = None

        try:
            self._libc = ctypes.CDLL("libc.so.6")
        except Exception:
            pass

    async def start(self):
        if self._running:
            return
        self._running = True
        self._gc_task = asyncio.create_task(self._gc_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        log.info("MemoryManager started (gc=%ds, cleanup=%ds, max_rss=%dMB)",
                 self.gc_interval, self.cleanup_interval, self.max_rss_mb)

    async def stop(self):
        self._running = False
        for t in [self._gc_task, self._cleanup_task]:
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

    async def _gc_loop(self):
        """Gen0+Gen1 collection every 60s — fast, prevents accumulation."""
        while self._running:
            try:
                await asyncio.sleep(self.gc_interval)
                collected = gc.collect(1)  # gen0 + gen1
                if collected > 0:
                    log.debug("GC: collected %d refs", collected)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _cleanup_loop(self):
        """Full cleanup every 5 min: gc.collect(2) + malloc_trim + RSS check."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)

                # Full GC
                gc.collect(2)

                # Return memory to OS
                self._malloc_trim()

                # Check RSS
                rss_mb = self._get_rss_mb()
                if rss_mb > self.max_rss_mb:
                    log.warning("RSS %dMB > %dMB threshold, restarting",
                                rss_mb, self.max_rss_mb)
                    time.sleep(0.5)
                    os.kill(os.getpid(), signal.SIGTERM)
                elif rss_mb > self.max_rss_mb * 0.7:
                    log.info("RSS %dMB (%.0f%% of %dMB limit)",
                             rss_mb, rss_mb / self.max_rss_mb * 100, self.max_rss_mb)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("Cleanup error: %s", e)

    def _malloc_trim(self):
        if self._libc:
            try:
                self._libc.malloc_trim(0)
            except Exception:
                pass

    def _get_rss_mb(self) -> int:
        """Get RSS from /proc/self/status (no psutil needed)."""
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) // 1024
        except Exception:
            pass
        return 0
