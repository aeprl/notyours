#!/usr/bin/env python3
"""
watchdog_companion.py — notyours self-defense watchdog.

Launched by detector.py / run_headless() on startup.
Monitors the EDR process (given by PID) and restarts it
if it terminates unexpectedly.

Usage (internal):
    python watchdog_companion.py <parent_pid> <detector_exe_or_script>
"""

import os
import sys
import time
import subprocess
import datetime

def _log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [watchdog] {msg}"
    print(line, flush=True)
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notyours.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def _pid_alive(pid):
    try:
        import psutil
        return psutil.pid_exists(pid) and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except Exception:
        # Fallback: try os.kill(pid, 0) on non-Windows
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

def main():
    if len(sys.argv) < 3:
        print("Usage: watchdog_companion.py <parent_pid> <detector_path> [args...]")
        sys.exit(1)

    try:
        parent_pid = int(sys.argv[1])
    except ValueError:
        print(f"Invalid PID: {sys.argv[1]}")
        sys.exit(1)

    detector_path = sys.argv[2]
    extra_args = sys.argv[3:]

    _log(f"Watchdog started. Monitoring EDR PID={parent_pid}, target={detector_path}")

    POLL_INTERVAL = 5   # seconds between liveness checks
    RESTART_DELAY = 2   # seconds to wait before restarting

    while True:
        time.sleep(POLL_INTERVAL)
        if not _pid_alive(parent_pid):
            _log(f"EDR process (PID={parent_pid}) is gone — restarting.")
            time.sleep(RESTART_DELAY)
            try:
                CREATE_NO_WINDOW = 0x08000000
                if detector_path.endswith(".exe"):
                    cmd = [detector_path, "cli"] + extra_args
                else:
                    cmd = [sys.executable, detector_path, "cli"] + extra_args
                proc = subprocess.Popen(
                    cmd,
                    creationflags=CREATE_NO_WINDOW,
                    cwd=os.path.dirname(os.path.abspath(detector_path)),
                )
                new_pid = proc.pid
                _log(f"EDR restarted with PID={new_pid}.")
                # Now watch the new PID going forward
                parent_pid = new_pid
            except Exception as exc:
                _log(f"Failed to restart EDR: {exc}")
                # Don't exit — keep trying to restart
                time.sleep(10)

if __name__ == "__main__":
    main()
