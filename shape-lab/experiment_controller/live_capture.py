"""Mirror Docker JSONL logs while a trial is active for the local monitor."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


class LiveCapture:
    def __init__(self, compose_file: Path, project: str, run_dir: Path,
                 services: dict[str, str], env: dict[str, str]) -> None:
        self.compose_file = compose_file
        self.project = project
        self.run_dir = run_dir
        self.services = services
        self.env = env
        self.processes: list[tuple[subprocess.Popen[bytes], object]] = []

    def start(self) -> None:
        try:
            for service, filename in self.services.items():
                self.add(service, filename)
        except Exception:
            self.stop()
            raise

    def add(self, service: str, filename: str) -> None:
        path = self.run_dir / filename
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stream = os.fdopen(descriptor, "wb", buffering=0)
        try:
            process = subprocess.Popen(
                ["docker", "compose", "--profile", "agent", "-p", self.project,
                 "-f", str(self.compose_file),
                 "logs", "--follow", "--no-color", "--no-log-prefix", service],
                cwd=self.compose_file.parent, env=self.env, stdout=stream,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
        except Exception:
            stream.close()
            raise
        self.processes.append((process, stream))

    def stop(self) -> None:
        for process, stream in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            stream.close()
        self.processes.clear()
