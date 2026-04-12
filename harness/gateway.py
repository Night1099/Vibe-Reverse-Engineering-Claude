"""LiteLLM gateway configuration — unified proxy for all model calls.

Provides cost tracking, fallback chains (Ollama → cloud), and a single
endpoint for both orchestrator (cloud) and worker (local) models.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from harness.config import Config

logger = logging.getLogger(__name__)


@dataclass
class GatewayStatus:
    running: bool = False
    port: int = 4000
    models: list[str] | None = None
    error: str | None = None


def generate_litellm_config(config: Config) -> dict:
    """Generate a LiteLLM proxy config dict from harness config.

    This config can be written to a YAML file and used with:
        litellm --config litellm_config.yaml
    """
    model_list = []

    # Orchestrator model(s)
    orch = config.orchestrator
    model_list.append({
        "model_name": "orchestrator",
        "litellm_params": {
            "model": f"{orch.provider}/{orch.model}",
            "temperature": orch.temperature,
            "max_tokens": orch.max_tokens,
        },
    })

    # Worker model (Ollama)
    worker = config.worker
    model_list.append({
        "model_name": "worker",
        "litellm_params": {
            "model": f"ollama/{worker.model}",
            "api_base": config.ollama.host,
            "temperature": worker.temperature,
            "max_tokens": worker.max_tokens,
        },
    })

    # Fallback model
    fb = config.fallback
    model_list.append({
        "model_name": "fallback",
        "litellm_params": {
            "model": f"{fb.provider}/{fb.model}",
            "temperature": fb.temperature,
            "max_tokens": fb.max_tokens,
        },
    })

    return {
        "model_list": model_list,
        "litellm_settings": {
            "drop_params": True,
            "set_verbose": False,
        },
        "general_settings": {
            "master_key": None,  # No auth for local use
        },
    }


def write_litellm_config(config: Config, path: str = "litellm_config.yaml") -> str:
    """Write LiteLLM config to a YAML file."""
    import yaml

    cfg = generate_litellm_config(config)
    with open(path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)
    logger.info("Wrote LiteLLM config to %s", path)
    return path


async def check_ollama(config: Config) -> bool:
    """Check if Ollama is reachable and has the required model."""
    import asyncio

    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", f"{config.ollama.host}/api/tags",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        if proc.returncode == 0:
            import json
            data = json.loads(stdout)
            models = [m["name"] for m in data.get("models", [])]
            target = config.worker.model
            if any(target in m for m in models):
                logger.info("Ollama OK: model %s available", target)
                return True
            logger.warning("Ollama running but model %s not found. Available: %s",
                         target, models)
            return False
    except Exception as e:
        logger.warning("Ollama unreachable: %s", e)
    return False


async def pull_model(config: Config) -> bool:
    """Pull the worker model into Ollama."""
    import asyncio

    model = config.worker.model
    logger.info("Pulling model %s...", model)

    proc = await asyncio.create_subprocess_exec(
        "ollama", "pull", model,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=1800)
    if proc.returncode == 0:
        logger.info("Model %s pulled successfully", model)
        return True
    logger.error("Failed to pull %s: %s", model, stderr.decode())
    return False
