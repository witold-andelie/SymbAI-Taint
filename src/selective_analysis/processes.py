"""Bounded child processes; the isolated worker owns the POSIX process group."""

from dataclasses import dataclass
import os
import signal
import subprocess
import time


@dataclass(frozen=True)
class ProcessOutcome:
    returncode: int
    timed_out: bool
    elapsed_seconds: float


def _stop(process, isolated):
    if os.name == "posix" and isolated:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif os.name == "nt" and process.poll() is None:
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    elif process.poll() is None:
        process.kill()
    if process.poll() is None:
        process.kill()
    process.wait()


def run_bounded(command, log_path, timeout, env=None, isolated=True):
    """Never shell-expand a command. Nested exports inherit their worker's group."""
    started = time.monotonic()
    if timeout <= 0:
        return ProcessOutcome(-1, True, 0.0)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env,
                                   start_new_session=os.name == "posix" and isolated)
        expired = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            _stop(process, isolated)
        except BaseException:
            _stop(process, isolated)
            raise
        finally:
            # An isolated POSIX worker may have descendants even after its own exit.
            if os.name == "posix" and isolated:
                _stop(process, True)
    return ProcessOutcome(process.returncode, expired, time.monotonic() - started)
