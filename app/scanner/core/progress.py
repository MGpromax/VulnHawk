"""
VulnHawk Real-Time Scan Progress Tracker

Advanced progress tracking with:
- Exponential Moving Average (EMA) for smooth time estimation
- Phase-based progress tracking (crawling, passive, active)
- Real-time updates via Server-Sent Events (SSE)
- Human-readable time formatting

Author: Manoj Gowda
"""

import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass, field
from enum import Enum
import json
import threading


class ScanPhase(Enum):
    """Scan phases with their weight contributions to total progress."""
    INITIALIZING = ("initializing", 0, 5, "Initializing scanner...")
    CRAWLING = ("crawling", 5, 35, "Crawling website...")
    PASSIVE_ANALYSIS = ("passive_analysis", 35, 55, "Analyzing responses...")
    ACTIVE_TESTING = ("active_testing", 55, 95, "Testing for vulnerabilities...")
    FINALIZING = ("finalizing", 95, 100, "Finalizing results...")
    COMPLETED = ("completed", 100, 100, "Scan completed")
    FAILED = ("failed", -1, -1, "Scan failed")

    def __init__(self, phase_id: str, start_pct: int, end_pct: int, default_msg: str):
        self.phase_id = phase_id
        self.start_pct = start_pct
        self.end_pct = end_pct
        self.default_msg = default_msg


@dataclass
class PhaseProgress:
    """Progress within a single phase."""
    phase: ScanPhase
    total_items: int = 0
    completed_items: int = 0
    current_item: str = ""
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    @property
    def progress_pct(self) -> float:
        """Progress percentage within this phase (0-100)."""
        if self.total_items == 0:
            return 0.0
        return min(100.0, (self.completed_items / self.total_items) * 100)

    @property
    def overall_progress(self) -> float:
        """Map phase progress to overall scan progress."""
        phase_range = self.phase.end_pct - self.phase.start_pct
        return self.phase.start_pct + (self.progress_pct / 100.0) * phase_range

    @property
    def elapsed_seconds(self) -> float:
        """Seconds elapsed in this phase."""
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at


@dataclass
class ScanProgress:
    """
    Comprehensive scan progress tracker with EMA-based time estimation.

    Uses Exponential Moving Average (EMA) to smooth time estimates:
    - More responsive to recent changes
    - Less jumpy than simple average
    - Adapts to varying scan speeds
    """

    # EMA smoothing factor (0.3 = 30% weight to new value, 70% to history)
    # Lower = smoother but slower to adapt
    # Higher = more responsive but jumpier
    EMA_ALPHA: float = 0.3

    # State
    scan_id: str = ""
    target_url: str = ""
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    # Current phase
    current_phase: ScanPhase = field(default=ScanPhase.INITIALIZING)
    phase_progress: Dict[str, PhaseProgress] = field(default_factory=dict)

    # EMA-smoothed rates (items per second)
    _ema_rate: float = 0.0
    _last_update_time: float = 0.0
    _last_completed_items: int = 0

    # Statistics
    urls_crawled: int = 0
    forms_found: int = 0
    parameters_tested: int = 0
    vulnerabilities_found: int = 0

    # Current activity message
    current_message: str = ""

    # Callback for updates
    _update_callback: Optional[Callable] = field(default=None, repr=False)

    # Thread safety
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def start(self, target_url: str = ""):
        """Start the scan timer."""
        with self._lock:
            self.started_at = time.time()
            self.target_url = target_url
            self.current_phase = ScanPhase.INITIALIZING
            self._last_update_time = self.started_at
            self._notify_update()

    def start_phase(self, phase: ScanPhase, total_items: int = 0):
        """Start a new scan phase."""
        with self._lock:
            self.current_phase = phase
            self.phase_progress[phase.phase_id] = PhaseProgress(
                phase=phase,
                total_items=total_items,
                started_at=time.time()
            )
            self.current_message = phase.default_msg
            self._last_completed_items = 0
            self._last_update_time = time.time()
            self._notify_update()

    def update_phase(self, completed_items: int, current_item: str = "", message: str = ""):
        """
        Update progress within the current phase.

        Uses EMA to smooth the rate calculation for better time estimates.
        """
        with self._lock:
            if self.current_phase.phase_id not in self.phase_progress:
                return

            pp = self.phase_progress[self.current_phase.phase_id]
            pp.completed_items = completed_items
            pp.current_item = current_item

            if message:
                self.current_message = message

            # Calculate and smooth rate using EMA
            now = time.time()
            time_delta = now - self._last_update_time

            if time_delta > 0 and completed_items > self._last_completed_items:
                items_delta = completed_items - self._last_completed_items
                current_rate = items_delta / time_delta

                # Apply EMA smoothing
                if self._ema_rate == 0:
                    self._ema_rate = current_rate
                else:
                    self._ema_rate = (self.EMA_ALPHA * current_rate +
                                      (1 - self.EMA_ALPHA) * self._ema_rate)

            self._last_update_time = now
            self._last_completed_items = completed_items
            self._notify_update()

    def set_phase_total(self, total_items: int):
        """Update total items for current phase (when we learn the total mid-phase)."""
        with self._lock:
            if self.current_phase.phase_id in self.phase_progress:
                self.phase_progress[self.current_phase.phase_id].total_items = total_items
                self._notify_update()

    def complete_phase(self):
        """Mark current phase as complete."""
        with self._lock:
            if self.current_phase.phase_id in self.phase_progress:
                pp = self.phase_progress[self.current_phase.phase_id]
                pp.completed_at = time.time()
                pp.completed_items = pp.total_items
            self._notify_update()

    def complete(self):
        """Mark scan as complete."""
        with self._lock:
            self.completed_at = time.time()
            self.current_phase = ScanPhase.COMPLETED
            self.current_message = "Scan completed successfully"
            self._notify_update()

    def fail(self, error: str = ""):
        """Mark scan as failed."""
        with self._lock:
            self.completed_at = time.time()
            self.current_phase = ScanPhase.FAILED
            self.current_message = f"Scan failed: {error}" if error else "Scan failed"
            self._notify_update()

    def update_stats(self, urls: int = 0, forms: int = 0, params: int = 0, vulns: int = 0):
        """Update scan statistics."""
        with self._lock:
            if urls:
                self.urls_crawled = urls
            if forms:
                self.forms_found = forms
            if params:
                self.parameters_tested = params
            if vulns:
                self.vulnerabilities_found = vulns
            self._notify_update()

    @property
    def elapsed_seconds(self) -> float:
        """Total elapsed time in seconds."""
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def remaining_seconds(self) -> float:
        """Estimated remaining time in seconds using EMA rate."""
        with self._lock:
            if self.current_phase in (ScanPhase.COMPLETED, ScanPhase.FAILED):
                return 0.0

            if self.current_phase.phase_id not in self.phase_progress:
                return 0.0

            pp = self.phase_progress[self.current_phase.phase_id]

            # Items remaining in current phase
            remaining_items = max(0, pp.total_items - pp.completed_items)

            if remaining_items == 0 or self._ema_rate == 0:
                # Fallback: estimate based on phases remaining
                return self._estimate_remaining_by_phases()

            # Time for remaining items in current phase
            phase_remaining = remaining_items / self._ema_rate

            # Add estimated time for remaining phases
            remaining_phases_time = self._estimate_remaining_phases_time()

            return phase_remaining + remaining_phases_time

    def _estimate_remaining_by_phases(self) -> float:
        """Estimate remaining time based on completed phases."""
        if not self.started_at:
            return 0.0

        current_progress = self.progress_percentage
        if current_progress <= 0:
            return 0.0

        elapsed = self.elapsed_seconds
        total_estimated = (elapsed / current_progress) * 100
        return max(0, total_estimated - elapsed)

    def _estimate_remaining_phases_time(self) -> float:
        """Estimate time for phases after current one."""
        phases_order = [
            ScanPhase.CRAWLING,
            ScanPhase.PASSIVE_ANALYSIS,
            ScanPhase.ACTIVE_TESTING,
            ScanPhase.FINALIZING
        ]

        # Find completed phases and their average time
        completed_phase_times = []
        for phase in phases_order:
            if phase.phase_id in self.phase_progress:
                pp = self.phase_progress[phase.phase_id]
                if pp.completed_at and pp.started_at:
                    # Weight by phase size
                    phase_size = phase.end_pct - phase.start_pct
                    time_per_percent = pp.elapsed_seconds / max(1, phase_size)
                    completed_phase_times.append(time_per_percent)

        if not completed_phase_times:
            return 0.0

        avg_time_per_percent = sum(completed_phase_times) / len(completed_phase_times)

        # Calculate remaining phase percentages
        remaining_pct = 0
        found_current = False
        for phase in phases_order:
            if phase == self.current_phase:
                found_current = True
                continue
            if found_current:
                remaining_pct += phase.end_pct - phase.start_pct

        return avg_time_per_percent * remaining_pct

    @property
    def progress_percentage(self) -> float:
        """Overall scan progress (0-100)."""
        with self._lock:
            if self.current_phase == ScanPhase.COMPLETED:
                return 100.0
            if self.current_phase == ScanPhase.FAILED:
                return self._get_last_progress()

            if self.current_phase.phase_id in self.phase_progress:
                return self.phase_progress[self.current_phase.phase_id].overall_progress

            return self.current_phase.start_pct

    def _get_last_progress(self) -> float:
        """Get the last known progress before failure."""
        if self.phase_progress:
            last_pp = list(self.phase_progress.values())[-1]
            return last_pp.overall_progress
        return 0.0

    @property
    def eta(self) -> Optional[datetime]:
        """Estimated time of completion."""
        remaining = self.remaining_seconds
        if remaining <= 0:
            return None
        return datetime.now() + timedelta(seconds=remaining)

    def set_callback(self, callback: Callable):
        """Set callback for progress updates."""
        self._update_callback = callback

    def _notify_update(self):
        """Notify callback of update."""
        if self._update_callback:
            try:
                self._update_callback(self.to_dict())
            except Exception:
                pass

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "phase": self.current_phase.phase_id,
            "phase_name": self.current_phase.default_msg,
            "progress": round(self.progress_percentage, 1),
            "message": self.current_message,
            "elapsed": {
                "seconds": round(self.elapsed_seconds, 1),
                "formatted": format_duration(self.elapsed_seconds)
            },
            "remaining": {
                "seconds": round(self.remaining_seconds, 1),
                "formatted": format_duration(self.remaining_seconds)
            },
            "eta": self.eta.isoformat() if self.eta else None,
            "stats": {
                "urls_crawled": self.urls_crawled,
                "forms_found": self.forms_found,
                "parameters_tested": self.parameters_tested,
                "vulnerabilities_found": self.vulnerabilities_found
            },
            "rate": round(self._ema_rate, 2) if self._ema_rate else 0,
            "is_complete": self.current_phase == ScanPhase.COMPLETED,
            "is_failed": self.current_phase == ScanPhase.FAILED,
            "timestamp": datetime.now().isoformat()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


def format_duration(seconds: float) -> str:
    """
    Format duration in a human-readable way.

    Examples:
    - 45 -> "45s"
    - 125 -> "2m 5s"
    - 3725 -> "1h 2m 5s"
    - 0 -> "0s"
    """
    if seconds <= 0:
        return "0s"

    seconds = int(seconds)

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def format_time_remaining(seconds: float) -> str:
    """
    Format remaining time in a user-friendly way.

    Examples:
    - 45 -> "About 45 seconds"
    - 90 -> "About 2 minutes"
    - 180 -> "About 3 minutes"
    - 600 -> "About 10 minutes"
    - 3600 -> "About 1 hour"
    """
    if seconds <= 0:
        return "Almost done"

    if seconds < 60:
        return f"About {int(seconds)} second{'s' if seconds != 1 else ''}"

    minutes = seconds / 60
    if minutes < 60:
        rounded = round(minutes)
        return f"About {rounded} minute{'s' if rounded != 1 else ''}"

    hours = minutes / 60
    if hours < 24:
        rounded = round(hours, 1)
        if rounded == int(rounded):
            rounded = int(rounded)
        return f"About {rounded} hour{'s' if rounded != 1 else ''}"

    days = hours / 24
    rounded = round(days, 1)
    if rounded == int(rounded):
        rounded = int(rounded)
    return f"About {rounded} day{'s' if rounded != 1 else ''}"


# Global progress tracker registry
_progress_trackers: Dict[str, ScanProgress] = {}
_trackers_lock = threading.Lock()


def get_progress_tracker(scan_id: str) -> Optional[ScanProgress]:
    """Get progress tracker for a scan."""
    with _trackers_lock:
        return _progress_trackers.get(scan_id)


def create_progress_tracker(scan_id: str, target_url: str = "") -> ScanProgress:
    """Create and register a new progress tracker."""
    tracker = ScanProgress(scan_id=scan_id, target_url=target_url)
    with _trackers_lock:
        _progress_trackers[scan_id] = tracker
    return tracker


def remove_progress_tracker(scan_id: str):
    """Remove a progress tracker (cleanup)."""
    with _trackers_lock:
        if scan_id in _progress_trackers:
            del _progress_trackers[scan_id]


def list_active_trackers() -> List[str]:
    """List all active scan IDs."""
    with _trackers_lock:
        return list(_progress_trackers.keys())
