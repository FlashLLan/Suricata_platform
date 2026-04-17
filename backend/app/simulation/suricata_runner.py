"""
suricata_runner.py — Run real Suricata inside Docker and return eve.json alerts.

Architecture
------------
Files are transferred to/from the container entirely through Docker's
put_archive / get_archive API (tar streams over the Docker socket).
This avoids any host-path sharing concerns and works identically on
Linux, macOS, and Windows Docker Desktop.

Lifecycle of one simulation run:
  1. Build pcap bytes + rules bytes in memory (caller provides these).
  2. Create a stopped container (containers.create).
  3. Upload traffic.pcap + rules.rules into /tmp via put_archive.
  4. Start the container; it runs Suricata offline and exits.
  5. Download /tmp/eve.json via get_archive.
  6. Parse every line for event_type == "alert".
  7. Force-remove the container regardless of outcome.
"""
from __future__ import annotations

import io
import json
import logging
import tarfile
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

SURICATA_IMAGE = "jasonish/suricata:latest"
RUN_TIMEOUT_SECONDS = 60  # seconds to wait for Suricata to finish offline scan

# /tmp always exists in any Docker container — no directory creation needed.
_SIM_DIR = "/tmp"


# ---------------------------------------------------------------------------
# Status API
# ---------------------------------------------------------------------------

@dataclass
class DockerStatus:
    """
    Snapshot of the local Docker + Suricata image availability.

    States
    ------
    "docker_unavailable"  — Docker daemon not running or SDK not installed
    "image_not_pulled"    — Docker running but jasonish/suricata not present
    "ready"               — Everything available; real-Suricata mode can run
    """
    docker_running: bool
    image_available: bool
    error: Optional[str] = None

    @property
    def ready(self) -> bool:
        return self.docker_running and self.image_available

    @property
    def state(self) -> str:
        if not self.docker_running:
            return "docker_unavailable"
        if not self.image_available:
            return "image_not_pulled"
        return "ready"

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "ready": self.ready,
            "docker_running": self.docker_running,
            "image_available": self.image_available,
            "error": self.error,
            "image": SURICATA_IMAGE,
        }


def get_status() -> DockerStatus:
    """
    Check whether Docker is reachable and the Suricata image is present.

    Safe to call on every simulation request — the Docker ping is fast.
    Never raises; errors are captured in DockerStatus.error.
    """
    try:
        import docker  # deferred import so the app starts even without the package
    except ImportError:
        return DockerStatus(
            docker_running=False,
            image_available=False,
            error=(
                "The 'docker' Python package is not installed. "
                "Run: pip install docker==7.1.0"
            ),
        )

    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        return DockerStatus(
            docker_running=False,
            image_available=False,
            error=f"Docker daemon not reachable: {exc}",
        )

    try:
        client.images.get(SURICATA_IMAGE)
        return DockerStatus(docker_running=True, image_available=True)
    except docker.errors.ImageNotFound:
        return DockerStatus(
            docker_running=True,
            image_available=False,
            error=(
                f"Suricata image '{SURICATA_IMAGE}' is not pulled yet. "
                f"Run once:  docker pull {SURICATA_IMAGE}"
            ),
        )
    except Exception as exc:
        return DockerStatus(
            docker_running=True,
            image_available=False,
            error=f"Image lookup failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def run_suricata(pcap_bytes: bytes, rule_texts: list[str]) -> list[dict]:
    """
    Run Suricata offline against *pcap_bytes* with *rule_texts* loaded.

    Parameters
    ----------
    pcap_bytes:   raw pcap file bytes from pcap_builder.build_pcap()
    rule_texts:   list of Suricata rule strings (one rule per element)

    Returns
    -------
    List of eve.json alert dicts — one per fired alert, already filtered to
    ``event_type == "alert"``.  Empty list means no rules fired (or no
    traffic matched).

    Raises
    ------
    RuntimeError    — Docker unavailable, container crash, or timeout.
                      Caller should catch this and fall back to Python mode.
    """
    import docker

    rules_bytes = _build_rules_file(rule_texts)
    client = docker.from_env()

    # ── Create a stopped container ────────────────────────────────────────────
    container = client.containers.create(
        image=SURICATA_IMAGE,
        command=[
            "-r", f"{_SIM_DIR}/traffic.pcap",
            "-S", f"{_SIM_DIR}/rules.rules",
            "-l", _SIM_DIR,
            "-k", "none",          # skip checksum validation
            "--runmode", "single", # deterministic single-threaded processing
        ],
        detach=True,
        user="root",               # write permission inside /tmp
    )
    log.debug("Created Suricata container %s", container.short_id)

    try:
        # ── Upload pcap + rules ───────────────────────────────────────────────
        archive = _make_tar_archive([
            ("traffic.pcap", pcap_bytes),
            ("rules.rules", rules_bytes),
        ])
        container.put_archive(_SIM_DIR, archive)
        log.debug("Uploaded %d-byte pcap and %d-byte rules file",
                  len(pcap_bytes), len(rules_bytes))

        # ── Run ───────────────────────────────────────────────────────────────
        container.start()
        try:
            wait_result = container.wait(timeout=RUN_TIMEOUT_SECONDS)
        except Exception as exc:
            raise RuntimeError(
                f"Suricata container timed out after {RUN_TIMEOUT_SECONDS}s: {exc}"
            ) from exc

        exit_code = wait_result.get("StatusCode", -1)
        if exit_code != 0:
            logs = _tail_logs(container, 1000)
            raise RuntimeError(
                f"Suricata exited with code {exit_code}.\n"
                f"Container logs (last 1 000 chars):\n{logs}"
            )
        log.debug("Container finished with exit code 0")

        # ── Retrieve eve.json ─────────────────────────────────────────────────
        try:
            bits_gen, _ = container.get_archive(f"{_SIM_DIR}/eve.json")
        except docker.errors.NotFound:
            # Suricata only writes eve.json when at least one event occurs.
            # An empty run (no alerts, no stats) may skip the file entirely.
            log.debug("eve.json not found — no events; returning empty alert list")
            return []

        eve_tar_bytes = b"".join(bits_gen)
        eve_json_bytes = _extract_from_tar(eve_tar_bytes, "eve.json")

        # ── Parse alerts ──────────────────────────────────────────────────────
        return _parse_alerts(eve_json_bytes)

    finally:
        _safe_remove(container)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _build_rules_file(rule_texts: list[str]) -> bytes:
    """Join rule strings into a newline-separated rules file."""
    lines = [r.strip() for r in rule_texts if r.strip()]
    return "\n".join(lines).encode("utf-8")


def _make_tar_archive(files: list[tuple[str, bytes]]) -> bytes:
    """
    Build an in-memory tar archive from (filename, data) pairs.
    Suitable for passing to container.put_archive().
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for filename, data in files:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _extract_from_tar(tar_bytes: bytes, filename: str) -> bytes:
    """Extract a single named file from a tar archive (Docker get_archive output)."""
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r:*") as tar:
        for member in tar.getmembers():
            # Member name may be bare "eve.json" or prefixed "tmp/eve.json"
            if member.name == filename or member.name.endswith("/" + filename):
                f = tar.extractfile(member)
                if f:
                    return f.read()
    raise FileNotFoundError(
        f"'{filename}' was not found inside the tar archive returned by Docker."
    )


def _parse_alerts(eve_json_bytes: bytes) -> list[dict]:
    """Parse a Suricata eve.json byte stream and return only alert events."""
    alerts: list[dict] = []
    for line in eve_json_bytes.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            log.warning("Skipping non-JSON eve line: %r", line[:120])
            continue
        if event.get("event_type") == "alert":
            alerts.append(event)
    log.debug("Parsed %d alert(s) from eve.json", len(alerts))
    return alerts


def _tail_logs(container, max_chars: int = 1000) -> str:
    """Return the last *max_chars* characters of container stdout+stderr."""
    try:
        raw = container.logs(stdout=True, stderr=True)
        return raw.decode(errors="replace")[-max_chars:]
    except Exception:
        return "(could not retrieve container logs)"


def _safe_remove(container) -> None:
    """Force-remove a container, suppressing any errors."""
    try:
        container.remove(force=True)
        log.debug("Container %s removed", container.short_id)
    except Exception as exc:
        log.warning("Could not remove container %s: %s", container.short_id, exc)
