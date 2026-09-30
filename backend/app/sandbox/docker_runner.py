"""DockerSandboxRunner: run the sandbox image once, disposably, with a fixed
hardening flag set, via the docker CLI (argument list, never a shell).

It knows nothing about tools or policy; SandboxManager decides *whether*
to run. There is no fallback: if Docker is unavailable, nothing runs.
"""

import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional

from app.config import Settings

CONTAINER_LABEL = "satg.sandbox=1"
# docker run's own exit codes (the command did not reach the tool).
DOCKER_DAEMON_ERROR = 125
DOCKER_CANNOT_INVOKE = (126, 127)
KILLED = 137  # SIGKILL: memory limit or explicit kill
_CLI_TIMEOUT = 15.0


@dataclass
class RawRun:
    sandbox_id: str
    exit_code: Optional[int]
    stdout: bytes
    stderr: bytes
    duration_ms: float
    timed_out: bool
    docker_unavailable: bool
    container_removed: Optional[bool]


class DockerSandboxRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run_args(self, name: str) -> List[str]:
        """The complete, fixed `docker run` flag set (no mounts, no host
        namespaces, no Docker socket, no network, non-root, read-only)."""
        s = self.settings
        return [
            "run", "--rm", "-i",
            "--name", name,
            "--label", CONTAINER_LABEL,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", s.sandbox_memory,
            "--memory-swap", s.sandbox_memory,  # no swap beyond the memory limit
            "--cpus", s.sandbox_cpus,
            "--pids-limit", str(s.sandbox_pids_limit),
            "--user", "65532:65532",
            "--ipc", "none",
            "--log-driver", "none",
            "--pull", "never",  # only the locally built, known image
        ]

    def run(self, payload: bytes, entrypoint: Optional[List[str]] = None) -> RawRun:
        """Run the image with `payload` on stdin. `entrypoint` exists only for
        the Docker security tests, which probe the container configuration
        with the same flags; the gateway never passes it."""
        sandbox_id = f"satg-sbx-{uuid.uuid4().hex[:16]}"
        args = [self.settings.docker_bin, *self.run_args(sandbox_id)]
        if entrypoint:
            args += ["--entrypoint", entrypoint[0], self.settings.sandbox_image, *entrypoint[1:]]
        else:
            args.append(self.settings.sandbox_image)

        started = time.perf_counter()
        elapsed = lambda: round((time.perf_counter() - started) * 1000, 1)  # noqa: E731
        try:
            proc = subprocess.run(args, input=payload, capture_output=True, timeout=self.settings.sandbox_timeout, check=False)
        except FileNotFoundError:
            return RawRun(sandbox_id, None, b"", b"docker CLI not found", elapsed(), False, True, None)
        except subprocess.TimeoutExpired as expired:
            self._force_remove(sandbox_id)
            return RawRun(
                sandbox_id, None, expired.stdout or b"", expired.stderr or b"", elapsed(), True, False, self._is_gone(sandbox_id)
            )

        unavailable = proc.returncode == DOCKER_DAEMON_ERROR or proc.returncode in DOCKER_CANNOT_INVOKE
        if proc.returncode != 0:
            # --rm removes the container on exit; make sure, whatever happened.
            self._force_remove(sandbox_id)
        return RawRun(sandbox_id, proc.returncode, proc.stdout, proc.stderr, elapsed(), False, unavailable, self._is_gone(sandbox_id))

    def _docker(self, *args: str) -> Optional[subprocess.CompletedProcess]:
        try:
            return subprocess.run([self.settings.docker_bin, *args], capture_output=True, timeout=_CLI_TIMEOUT, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _force_remove(self, name: str) -> None:
        self._docker("rm", "--force", name)

    def _is_gone(self, name: str) -> Optional[bool]:
        """True if no container with this name exists (None if Docker cannot tell)."""
        listed = self._docker("ps", "--all", "--quiet", "--filter", f"name=^/{name}$")
        if listed is None or listed.returncode != 0:
            return None
        return listed.stdout.strip() == b""
