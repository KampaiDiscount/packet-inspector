"""Capture binding integrity gates: no callback fallback after consumption."""
from __future__ import annotations

from collections import deque
from types import SimpleNamespace

import pytest

from packet_audit.capture import CaptureError, PcapyLiveSource, PcapyOfflineSource


def _record(value: bytes):
    return SimpleNamespace(
        getts=lambda: (1, 25),
        getcaplen=lambda: len(value),
        getlen=lambda: len(value),
    ), value


class _NextHandle:
    def __init__(self, values=(), eof=(None, b"")):
        self.records = deque(_record(value) for value in values)
        self.end = eof
        self.next_calls = 0
        self.dispatch_calls = 0
        self.nonblocking = False

    def next(self):
        self.next_calls += 1
        return self.records.popleft() if self.records else self.end

    def dispatch(self, _limit, _callback):
        self.dispatch_calls += 1
        if self.records:
            self.records.popleft()  # Model the observed native consuming error.
        raise TypeError("synthetic callback missing 2 arguments after consumption")

    def datalink(self): return 1
    def setfilter(self, _value): pass
    def setnonblock(self, value): self.nonblocking = bool(value)
    def getnonblock(self): return int(self.nonblocking)
    def close(self): pass


def _source(handle, *, live=False, batch_size=4):
    if live:
        source = PcapyLiveSource(
            "synthetic0", batch_size=batch_size,
            pcapy_module=SimpleNamespace(open_live=lambda *_args: handle),
        )
        source._idle_stop = SimpleNamespace(wait=lambda _seconds: None, set=lambda: None)
        return source
    return PcapyOfflineSource(
        "synthetic.pcap", batch_size=batch_size,
        pcapy_module=SimpleNamespace(open_offline=lambda _path: handle),
    )


@pytest.mark.parametrize("live", [False, True])
def test_next_preferred_over_callback_that_consumes_then_raises(live):
    values = [f"packet-{index}".encode() for index in range(13)]
    handle = _NextHandle(values)
    source = _source(handle, live=live)
    batches = [source.read_batch() for _ in range(4)]
    assert [len(batch) for batch in batches] == [4, 4, 4, 1]
    records = [packet for batch in batches for packet in batch]
    assert [packet.raw for packet in records] == values
    assert [packet.packet_id for packet in records] == list(range(1, 14))
    assert handle.dispatch_calls == 0
    assert handle.next_calls == 14
    assert source.eof is not live
    assert handle.nonblocking is live


def test_live_next_batch_bound_and_idle_do_not_set_eof():
    handle = _NextHandle([b"one", b"two", b"three", b"four"])
    source = _source(handle, live=True, batch_size=3)
    waits = []
    source._idle_stop = SimpleNamespace(wait=waits.append)
    assert [packet.raw for packet in source.read_batch(max_packets=2)] == [b"one", b"two"]
    assert handle.next_calls == 2
    assert [packet.raw for packet in source.read_batch()] == [b"three", b"four"]
    assert handle.next_calls == 5
    assert waits == []  # A short, non-empty batch must not idle-sleep.
    assert source.read_batch() == []
    assert waits == [0.1]
    assert not source.eof
    handle.records.append(_record(b"after-idle"))
    assert [packet.raw for packet in source.read_batch()] == [b"after-idle"]


@pytest.mark.parametrize("end", [(None, None), (None, b"")])
def test_offline_eof_does_not_discard_a_partial_batch(end):
    handle = _NextHandle([b"one", b"two"], eof=end)
    source = _source(handle)
    assert len(source.read_batch()) == 2
    assert source.eof
    calls = handle.next_calls
    assert source.read_batch() == []
    assert handle.next_calls == calls


@pytest.mark.parametrize("malformed", [None, (), (None,), (None, b"unexpected"), (object(), None)])
@pytest.mark.parametrize("live", [False, True])
def test_malformed_next_result_is_fatal_not_idle_or_eof(malformed, live):
    handle = _NextHandle(eof=malformed)
    source = _source(handle, live=live)
    with pytest.raises(CaptureError, match="malformed|without"):
        source.read_batch()
    assert not source.eof
    assert handle.dispatch_calls == 0


@pytest.mark.parametrize("error", [TypeError, NotImplementedError, OSError, SystemError])
def test_next_error_after_a_record_never_falls_back_to_dispatch(error):
    handle = _NextHandle([b"first"])
    read_next = handle.next
    def failing_next():
        if handle.records:
            return read_next()
        raise error("synthetic native read failure")
    handle.next = failing_next
    source = _source(handle)
    with pytest.raises(CaptureError, match="capture next\\(\\) failed"):
        source.read_batch()
    assert handle.dispatch_calls == 0
    assert not source.eof


@pytest.mark.parametrize("mode", ["count_without_callback", "wrong_count", "missing_count", "interrupted", "callback_error", "over_limit"])
def test_dispatch_only_adapter_fails_loudly_on_delivery_integrity_error(mode):
    handle = _NextHandle()
    handle.next = None
    def dispatch(limit, callback):
        if mode == "count_without_callback": return 1
        if mode == "missing_count": return None
        if mode == "interrupted": return -2
        if mode == "callback_error":
            callback(*_record(b"consumed"))
            raise TypeError("synthetic callback failure after consumption")
        if mode == "over_limit":
            for _ in range(limit + 1): callback(*_record(b"packet"))
            return limit + 1
        callback(*_record(b"packet"))
        return 0
    handle.dispatch = dispatch
    source = _source(handle)
    with pytest.raises(CaptureError, match="capture dispatch"):
        source.read_batch()
    assert not source.eof


@pytest.mark.parametrize("payload", [None, "text", 5])
def test_next_non_byte_payload_is_not_coerced_to_capture_data(payload):
    handle = _NextHandle()
    header, _ = _record(b"x")
    handle.end = (header, payload)
    with pytest.raises(CaptureError, match="without data|bytes-like"):
        _source(handle).read_batch()


def test_next_capture_length_mismatch_fails_visibly():
    handle = _NextHandle()
    header, _ = _record(b"longer")
    handle.end = (header, b"x")
    with pytest.raises(CaptureError, match="lengths"):
        _source(handle).read_batch()
