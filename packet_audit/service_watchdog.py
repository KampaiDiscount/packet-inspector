"""Main-process systemd notifications driven by completed capture iterations.

There is deliberately no timer thread: a wedged dispatcher must stop notifying.
Outside a notifying service manager this helper is inert.
"""
from __future__ import annotations

import os
import socket
import time
from typing import Mapping


class ServiceWatchdogError(RuntimeError):
    """Required service-manager notification could not be delivered."""


class ServiceWatchdog:
    def __init__(self, address: str | None = None, interval_seconds: float = 0.0):
        self.address = address
        self.interval_seconds = interval_seconds
        self.owner_pid = os.getpid()
        self.ready_sent = False
        self.stopping_sent = False
        self.last_notification = 0.0

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None):
        env = os.environ if environment is None else environment
        address = env.get("NOTIFY_SOCKET")
        watchdog_pid = env.get("WATCHDOG_PID")
        if watchdog_pid:
            try:
                intended_pid = int(watchdog_pid)
            except ValueError as exc:
                raise ServiceWatchdogError("invalid WATCHDOG_PID") from exc
            if intended_pid != os.getpid():
                return cls()  # Never impersonate the manager's main process.
        usec = env.get("WATCHDOG_USEC")
        interval = 0.0
        if usec:
            try:
                microseconds = int(usec)
                if microseconds <= 0 or microseconds > 2**63 - 1:
                    raise ValueError
            except ValueError as exc:
                raise ServiceWatchdogError("invalid WATCHDOG_USEC") from exc
            if not address:
                raise ServiceWatchdogError("WATCHDOG_USEC requires NOTIFY_SOCKET")
            interval = microseconds / 3_000_000.0
        if address and (len(address) < 2 or address[0] not in ("/", "@")):
            raise ServiceWatchdogError("NOTIFY_SOCKET must be an absolute or abstract socket")
        return cls(address, interval)

    def _send(self, message: str) -> None:
        if not self.address or os.getpid() != self.owner_pid:
            return
        address = "\0" + self.address[1:] if self.address.startswith("@") else self.address
        payload = message.encode("utf-8")
        try:
            # A full notify socket must not become another unbounded blocking call.
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
                channel.settimeout(0.25)
                sent = channel.sendto(payload, address)
                if sent != len(payload):
                    raise OSError("short service notification datagram")
        except (OSError, AttributeError) as exc:
            raise ServiceWatchdogError("service-manager notification failed") from exc

    def ready(self) -> None:
        if not self.address or self.ready_sent:
            return
        self._send("READY=1\nSTATUS=Capture initialized; monitoring capture-loop progress")
        self.ready_sent = True
        self.last_notification = time.monotonic()

    def progress(self) -> None:
        """Call only after a completed read, dispatch and child-health check."""
        if not self.address or not self.interval_seconds or self.stopping_sent:
            return
        if not self.ready_sent:
            raise ServiceWatchdogError("watchdog progress before capture startup completed")
        now = time.monotonic()
        if now - self.last_notification >= self.interval_seconds:
            self._send("WATCHDOG=1")
            self.last_notification = now

    def stopping(self) -> None:
        if not self.address or not self.ready_sent or self.stopping_sent:
            return
        self._send("STOPPING=1\nSTATUS=Draining capture workers and evidence writer")
        self.stopping_sent = True
