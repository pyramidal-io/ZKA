#!/usr/bin/env python3
"""Run one CI command with a hard deadline and machine-readable telemetry."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import resource
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


TIMEOUT_EXIT_CODE = 124
SAMPLE_INTERVAL_SECONDS = 0.2


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def memory_total_kb() -> int:
    try:
        return int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 1024)
    except (OSError, ValueError):
        return 0


def process_rows() -> list[tuple[int, int, int, int]]:
    """Return (pid, ppid, process_group_id, rss_kb) rows."""
    proc = Path("/proc")
    if proc.is_dir():
        rows: list[tuple[int, int, int, int]] = []
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / "status").read_text()
                stat = (entry / "stat").read_text()
                values: dict[str, str] = {}
                for line in status.splitlines():
                    key, separator, value = line.partition(":")
                    if separator:
                        values[key] = value.strip()
                # Fields after the final ')' start at state (field 3), then
                # ppid (4) and process group id (5). The command name itself
                # may contain spaces or parentheses, hence the right split.
                stat_fields = stat.rsplit(")", 1)[1].split()
                rows.append(
                    (
                        int(entry.name),
                        int(stat_fields[1]),
                        int(stat_fields[2]),
                        int(values.get("VmRSS", "0 kB").split()[0]),
                    )
                )
            # A process may exit between listing /proc and reading its status.
            # Linux can surface that race as either ENOENT or ESRCH.
            except (OSError, ValueError):
                continue
        return rows

    completed = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,pgid=,rss="],
        check=False,
        capture_output=True,
        text=True,
    )
    rows = []
    for line in completed.stdout.splitlines():
        try:
            pid, ppid, process_group_id, rss = (
                int(value) for value in line.split()
            )
        except ValueError:
            continue
        rows.append((pid, ppid, process_group_id, rss))
    return rows


def process_tree_rss_kb(root_pid: int) -> int:
    rows = process_rows()
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, ppid, _process_group_id, _rss in rows:
            if ppid in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    return sum(rss for pid, _ppid, _process_group_id, rss in rows if pid in descendants)


def process_group_rss_kb(process_group_id: int) -> int:
    return sum(
        rss
        for _pid, _ppid, row_process_group_id, rss in process_rows()
        if row_process_group_id == process_group_id
    )


def disk_used_kb(path: Path) -> int:
    return int(shutil.disk_usage(path).used / 1024)


def normalized_max_rss_kb(value: int) -> int:
    # Linux reports KiB while Darwin reports bytes.
    return int(value / 1024) if sys.platform == "darwin" else int(value)


def live_process_group_member_exists(process_group_id: int) -> bool | None:
    """Return whether a non-zombie process is in the group, or None off Linux.

    killpg(pgid, 0) also matches zombies. When PID 1 never reaps (the Forgejo
    runner containers run `tail -f /dev/null`), orphaned descendants of a
    killed group stay zombies forever, so killpg would report a finished group
    as alive until the caller's deadline.
    """
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        # A process may exit between listing /proc and reading its stat.
        except (OSError, IndexError):
            continue
        # Fields after the final ')' start at state (3), ppid (4), pgrp (5).
        if int(stat_fields[2]) == process_group_id and stat_fields[0] not in ("Z", "X"):
            return True
    return False


def process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    # poll() reaps the leader when it exits; otherwise its zombie can keep the
    # process group observable even after all live work is gone.
    leader_running = process.poll() is None
    live = live_process_group_member_exists(process.pid)
    if live is not None:
        if live:
            return True
        if leader_running:
            # The leader can fork after /proc was enumerated and exit before
            # its stat is read. Never accept that empty snapshot while the
            # leader still runs; if it exited during the scan, take a fresh
            # snapshot that can see the surviving child.
            if process.poll() is None:
                return True
            live = live_process_group_member_exists(process.pid)
            if live is not None:
                return live
        else:
            return False
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for_process_group_exit(
    process: subprocess.Popen[bytes], timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while process_group_exists(process):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if not wait_for_process_group_exit(process, 5):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        wait_for_process_group_exit(process, 5)
    if process.returncode is None:
        process.wait()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    if args.timeout_seconds is not None and args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    return args


def main() -> int:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    started = time.monotonic()
    disk_start_kb = disk_used_kb(Path.cwd())
    disk_peak_kb = disk_start_kb
    usage_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    process = subprocess.Popen(args.command, start_new_session=True)
    peak_tree_rss_kb = 0
    timed_out = False
    # The command runs in its own session, so a SIGTERM aimed at this wrapper
    # would otherwise orphan it. Forward it by tearing the group down.
    terminated = False

    def request_termination(_signum: int, _frame: object) -> None:
        nonlocal terminated
        terminated = True

    signal.signal(signal.SIGTERM, request_termination)

    while process_group_exists(process):
        if terminated:
            terminate_process_group(process)
            break
        peak_tree_rss_kb = max(peak_tree_rss_kb, process_group_rss_kb(process.pid))
        disk_peak_kb = max(disk_peak_kb, disk_used_kb(Path.cwd()))
        if args.timeout_seconds is not None and time.monotonic() - started >= args.timeout_seconds:
            timed_out = True
            print(
                f"ERROR: {args.label} timed out after {args.timeout_seconds:g}s",
                file=sys.stderr,
                flush=True,
            )
            terminate_process_group(process)
            break
        time.sleep(SAMPLE_INTERVAL_SECONDS)

    if not timed_out:
        process.wait()
    finished = time.monotonic()
    usage_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall_seconds = finished - started
    user_cpu_seconds = max(0.0, usage_end.ru_utime - usage_start.ru_utime)
    system_cpu_seconds = max(0.0, usage_end.ru_stime - usage_start.ru_stime)
    cpu_count = os.cpu_count() or 1
    exit_code = (
        TIMEOUT_EXIT_CODE
        if timed_out
        else 128 + signal.SIGTERM
        if terminated
        else int(process.returncode)
    )

    payload = {
        "schema": "zka:ci-resource-telemetry:v1",
        "label": args.label,
        "command": args.command,
        "started_at": started_at,
        "finished_at": utc_now(),
        "wall_seconds": round(wall_seconds, 3),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "timeout_seconds": args.timeout_seconds,
        "runner_name": os.environ.get("RUNNER_NAME"),
        "runner_label": os.environ.get("CI_RUNNER_LABEL"),
        "runner_os": os.environ.get("RUNNER_OS", platform.system()),
        "runner_arch": os.environ.get("RUNNER_ARCH", platform.machine()),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "github_job": os.environ.get("GITHUB_JOB"),
        "queue_seconds": float(os.environ["CI_QUEUE_SECONDS"])
        if os.environ.get("CI_QUEUE_SECONDS")
        else None,
        "cpu_count": cpu_count,
        "memory_total_kb": memory_total_kb(),
        "user_cpu_seconds": round(user_cpu_seconds, 3),
        "system_cpu_seconds": round(system_cpu_seconds, 3),
        "normalized_cpu_utilization_percent": round(
            100 * (user_cpu_seconds + system_cpu_seconds) / (wall_seconds * cpu_count), 2
        )
        if wall_seconds > 0
        else 0,
        "peak_process_tree_rss_kb": peak_tree_rss_kb,
        "max_child_rss_kb": normalized_max_rss_kb(usage_end.ru_maxrss),
        "disk_used_start_kb": disk_start_kb,
        "disk_used_peak_kb": disk_peak_kb,
        "disk_delta_peak_kb": max(0, disk_peak_kb - disk_start_kb),
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
