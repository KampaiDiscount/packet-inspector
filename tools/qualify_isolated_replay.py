#!/usr/bin/env python3
"""Replay a preserved PCAP through an already isolated Linux veth sensor.

The namespace and veth pair must be provisioned separately.  This harness
never changes the production interface or service.  It emits only aggregate
metrics; unredacted findings stay in the mode-0700 run directory.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import psutil


def _events(path: Path):
    try:
        with path.open(encoding="utf-8") as source:
            for line in source:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except FileNotFoundError:
        return


def _latest(path: Path, event: str) -> dict | None:
    result = None
    for item in _events(path):
        if item.get("event") == event:
            result = item
    return result


def _tree_metrics(process: psutil.Process) -> dict[str, float]:
    members = [process]
    try:
        members.extend(process.children(recursive=True))
    except psutil.Error:
        pass
    rss = cpu = 0.0
    for member in members:
        try:
            rss += member.memory_info().rss
            times = member.cpu_times()
            cpu += times.user + times.system
        except psutil.Error:
            continue
    return {"rss_bytes": rss, "cpu_seconds": cpu, "processes": float(len(members))}


def _config(path: Path, args: argparse.Namespace) -> None:
    enabled = "true" if args.suppression else "false"
    content = f'''[capture]
interface = "{args.rx}"
workers = 4
queue_size = {args.queue_size}
max_worker_queue_bytes = 134217728
snaplen = 262144
capture_buffer_mb = 128
promiscuous = true
read_timeout_ms = 100
capture_batch_size = 128
forwarded_duplicate_suppression = {enabled}

[analysis]
heartbeat_seconds = 10

[output]
output_jsonl = "{args.run_dir}/findings.jsonl"
operational_jsonl = "{args.run_dir}/operations.jsonl"

[raw_capture]
raw_capture_enabled = true
raw_capture_dir = "{args.run_dir}/pcap-ring"
raw_capture_file_mb = 256
raw_capture_files = 4
raw_capture_duration_seconds = 300
'''
    path.write_text(content, encoding="utf-8")


def run(args: argparse.Namespace) -> dict:
    args.run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = args.run_dir / "config.toml"
    _config(config, args)
    operations = args.run_dir / "operations.jsonl"
    command = [
        "ip", "netns", "exec", args.namespace,
        args.python, "-m", "packet_audit", "live", "--config", str(config),
    ]
    env = dict(os.environ, PYTHONPATH=str(args.source))
    (args.run_dir / "command.json").write_text(
        json.dumps({"command": command, "pcap": str(args.pcap),
                    "source": str(args.source), "suppression": args.suppression,
                    "multiplier": args.multiplier,
                    "queue_size": args.queue_size}, indent=2)
    )
    started = time.monotonic()
    samples: list[dict] = []
    with (args.run_dir / "sensor.stdout").open("wb") as stdout, (
        args.run_dir / "sensor.stderr"
    ).open("wb") as stderr:
        sensor = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env,
                                  start_new_session=True)
        sensor_proc = psutil.Process(sensor.pid)
        replay = None
        try:
            deadline = time.monotonic() + args.startup_timeout
            while _latest(operations, "session_started") is None:
                if sensor.poll() is not None:
                    raise RuntimeError(f"sensor exited during startup: {sensor.returncode}")
                if time.monotonic() > deadline:
                    raise TimeoutError("sensor did not announce session_started")
                time.sleep(0.1)
            sample = _tree_metrics(sensor_proc)
            sample["elapsed_seconds"] = time.monotonic() - started
            samples.append(sample)
            # The writer can announce session_started before dumpcap's capture
            # handle is fully receiving.  Give both independent readers a
            # bounded settling period before injecting the first frame.
            time.sleep(args.pre_replay_seconds)
            replay_started = time.monotonic()
            with (args.run_dir / "tcpreplay.stdout").open("wb") as replay_out, (
                args.run_dir / "tcpreplay.stderr"
            ).open("wb") as replay_err:
                replay = subprocess.Popen(
                    ["ip", "netns", "exec", args.namespace, "tcpreplay",
                     f"--intf1={args.tx}", f"--multiplier={args.multiplier}",
                     str(args.pcap)],
                    stdout=replay_out, stderr=replay_err,
                    start_new_session=True,
                )
                deadline = time.monotonic() + args.replay_timeout
                while replay.poll() is None:
                    sample = _tree_metrics(sensor_proc)
                    sample["elapsed_seconds"] = time.monotonic() - started
                    samples.append(sample)
                    if time.monotonic() > deadline:
                        raise TimeoutError("tcpreplay exceeded replay timeout")
                    time.sleep(0.1)
            replay_seconds = time.monotonic() - replay_started
            if replay.returncode:
                raise RuntimeError(f"tcpreplay exited {replay.returncode}")
            drain_started = time.monotonic()
            while time.monotonic() - drain_started < args.drain_seconds:
                sample = _tree_metrics(sensor_proc)
                sample["elapsed_seconds"] = time.monotonic() - started
                samples.append(sample)
                if sensor.poll() is not None:
                    raise RuntimeError(f"sensor exited while draining: {sensor.returncode}")
                time.sleep(0.2)
            os.kill(sensor.pid, signal.SIGINT)
            sensor.wait(timeout=args.stop_timeout)
        finally:
            if replay is not None and replay.poll() is None:
                os.killpg(replay.pid, signal.SIGTERM)
                replay.wait(timeout=5)
            if sensor.poll() is None:
                os.kill(sensor.pid, signal.SIGINT)
                try:
                    sensor.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.kill(sensor.pid, signal.SIGTERM)
                    sensor.wait(timeout=5)
    result = None
    with (args.run_dir / "sensor.stdout").open(encoding="utf-8") as output:
        try:
            result = json.load(output)
        except ValueError:
            pass
    summary = {
        "mode": "suppression" if args.suppression else "baseline",
        "multiplier": args.multiplier,
        "queue_size": args.queue_size,
        "sensor_exit": sensor.returncode,
        "tcpreplay_exit": replay.returncode if replay is not None else None,
        "replay_seconds": replay_seconds,
        "total_seconds": time.monotonic() - started,
        "peak_rss_bytes": max((s["rss_bytes"] for s in samples), default=0),
        "cpu_seconds_last_sample": samples[-1]["cpu_seconds"] if samples else 0,
        "samples": len(samples),
        "session": result,
        "last_heartbeat": _latest(operations, "capture_heartbeat"),
        "raw_ring_stop": _latest(operations, "raw_capture_stopped"),
    }
    (args.run_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (args.run_dir / "resource-samples.jsonl").write_text(
        "".join(json.dumps(sample) + "\n" for sample in samples)
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--tx", required=True)
    parser.add_argument("--rx", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--suppression", action="store_true")
    parser.add_argument("--multiplier", type=float, default=1.0)
    parser.add_argument("--queue-size", type=int, default=1024)
    parser.add_argument("--startup-timeout", type=float, default=30)
    parser.add_argument("--pre-replay-seconds", type=float, default=1)
    parser.add_argument("--replay-timeout", type=float, default=120)
    parser.add_argument("--drain-seconds", type=float, default=15)
    parser.add_argument("--stop-timeout", type=float, default=60)
    args = parser.parse_args()
    if not 0.1 <= args.multiplier <= 4:
        parser.error("multiplier must be between 0.1 and 4")
    if not 8 <= args.queue_size <= 4096:
        parser.error("queue size must be between 8 and 4096")
    for item in (args.namespace, args.tx, args.rx):
        if not item or not all(char.isalnum() or char in "_.-" for char in item):
            parser.error("namespace and interface names must be simple identifiers")
    summary = run(args)
    safe = {key: value for key, value in summary.items()
            if key not in {"last_heartbeat", "raw_ring_stop"}}
    session = safe.get("session")
    if session:
        safe["session"] = {key: value for key, value in session.items()
                           if key not in {"output", "operations"}}
    print(json.dumps(safe, indent=2))
    return 0 if summary["sensor_exit"] == 0 and summary["tcpreplay_exit"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
