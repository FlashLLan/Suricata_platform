"""
nftables_validator.py — Validate an nftables config with `nft --check` inside Docker.

Architecture (mirrors suricata_runner.py):
  1. Build a minimal Alpine + nftables image on first use and cache it locally.
  2. Create a container with CAP_NET_ADMIN (needed for netlink access by nft).
  3. Upload the config via put_archive.
  4. Run: nft --check -f /tmp/config.nft
  5. Return exit code + parsed error lines.
  6. Force-remove the container regardless of outcome.
"""
from __future__ import annotations

import io
import logging
import tarfile
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

NFT_IMAGE = "suricata-platform-nftables:latest"
NFT_TIMEOUT_SECONDS = 30

_NFT_DOCKERFILE = b"FROM alpine:3.19\nRUN apk add --no-cache nftables\n"

_SIM_DIR = "/tmp"


# ---------------------------------------------------------------------------
# Status API
# ---------------------------------------------------------------------------

@dataclass
class NftablesValidatorStatus:
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
            return "image_not_built"
        return "ready"

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "ready": self.ready,
            "docker_running": self.docker_running,
            "image_available": self.image_available,
            "error": self.error,
            "image": NFT_IMAGE,
        }


def get_status() -> NftablesValidatorStatus:
    """Check whether Docker is reachable and the nftables validator image exists."""
    try:
        import docker
    except ImportError:
        return NftablesValidatorStatus(
            docker_running=False,
            image_available=False,
            error="The 'docker' Python package is not installed. Run: pip install docker==7.1.0",
        )

    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        return NftablesValidatorStatus(
            docker_running=False,
            image_available=False,
            error=f"Docker daemon not reachable: {exc}",
        )

    try:
        client.images.get(NFT_IMAGE)
        return NftablesValidatorStatus(docker_running=True, image_available=True)
    except docker.errors.ImageNotFound:
        return NftablesValidatorStatus(
            docker_running=True,
            image_available=False,
            error=(
                f"Image '{NFT_IMAGE}' not yet built. "
                "It will be built automatically on your first validation run (~15s, first time only)."
            ),
        )
    except Exception as exc:
        return NftablesValidatorStatus(
            docker_running=True,
            image_available=False,
            error=f"Image lookup failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------

def validate_nftables_config(config: str) -> dict:
    """
    Validate an nftables config string using `nft --check` inside Docker.

    Returns
    -------
    {
        "valid":            bool,
        "errors":           list[str],   # human-readable error lines
        "raw_output":       str,         # full nft stderr/stdout
        "docker_available": bool,        # False if Docker was unavailable
    }

    Never raises — errors are captured and returned in the response dict.
    """
    try:
        import docker
    except ImportError:
        return {
            "valid": False,
            "errors": ["Docker Python package not installed (pip install docker==7.1.0)."],
            "raw_output": "",
            "docker_available": False,
        }

    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:
        return {
            "valid": False,
            "errors": [f"Docker daemon not reachable: {exc}"],
            "raw_output": "",
            "docker_available": False,
        }

    try:
        _ensure_nft_image(client)
    except Exception as exc:
        return {
            "valid": False,
            "errors": [f"Failed to build nftables validator image: {exc}"],
            "raw_output": "",
            "docker_available": True,
        }

    config_bytes = config.encode("utf-8")
    archive = _make_tar_archive([("config.nft", config_bytes)])

    container = client.containers.create(
        image=NFT_IMAGE,
        command=["nft", "--check", "-f", f"{_SIM_DIR}/config.nft"],
        detach=True,
        cap_add=["NET_ADMIN"],
    )
    log.debug("Created nft validator container %s", container.short_id)

    try:
        container.put_archive(_SIM_DIR, archive)
        container.start()

        try:
            wait_result = container.wait(timeout=NFT_TIMEOUT_SECONDS)
        except Exception as exc:
            return {
                "valid": False,
                "errors": [f"Validator container timed out after {NFT_TIMEOUT_SECONDS}s: {exc}"],
                "raw_output": "",
                "docker_available": True,
            }

        exit_code = wait_result.get("StatusCode", -1)
        raw_output = _get_logs(container)

        if exit_code == 0:
            return {
                "valid": True,
                "errors": [],
                "raw_output": raw_output,
                "docker_available": True,
            }

        errors = _parse_nft_errors(raw_output)
        return {
            "valid": False,
            "errors": errors,
            "raw_output": raw_output,
            "docker_available": True,
        }

    finally:
        _safe_remove(container)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _ensure_nft_image(client) -> None:
    """Build the nftables validator image if it is not already present locally."""
    import docker

    try:
        client.images.get(NFT_IMAGE)
        return
    except docker.errors.ImageNotFound:
        pass

    log.info("Building nftables validator image '%s' (first-time, ~15–30s)…", NFT_IMAGE)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("Dockerfile")
        info.size = len(_NFT_DOCKERFILE)
        tar.addfile(info, io.BytesIO(_NFT_DOCKERFILE))
    buf.seek(0)

    try:
        client.images.build(
            fileobj=buf,
            custom_context=True,
            tag=NFT_IMAGE,
            rm=True,
            pull=True,         # pull alpine:3.19 if not cached
            forcerm=True,
        )
        log.info("nftables validator image built successfully.")
    except Exception as exc:
        raise RuntimeError(f"docker build failed: {exc}") from exc


def _make_tar_archive(files: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for filename, data in files:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _get_logs(container) -> str:
    try:
        raw = container.logs(stdout=True, stderr=True)
        return raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _parse_nft_errors(raw: str) -> list[str]:
    """
    Extract meaningful error lines from nft output.
    nft writes errors like:
        /tmp/config.nft:10:5-20: Error: syntax error, unexpected ...
    We strip the file path prefix and return the human-readable part.
    """
    errors: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Strip "/tmp/config.nft:row:col-col: " prefix
        if line.startswith("/tmp/config.nft:") or line.startswith("config.nft:"):
            colon_after_path = line.find(": ", line.index(":") + 1)
            if colon_after_path != -1:
                line = line[colon_after_path + 2:].strip()
        errors.append(line)
    return errors if errors else [raw] if raw else ["nft exited with a non-zero code (no output)."]


def _safe_remove(container) -> None:
    try:
        container.remove(force=True)
        log.debug("nft validator container %s removed", container.short_id)
    except Exception as exc:
        log.warning("Could not remove nft validator container: %s", exc)
