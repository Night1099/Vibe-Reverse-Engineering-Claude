"""Configuration loader for the harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ModelConfig:
    provider: str = "anthropic"
    model: str = "claude-opus-4-6"
    temperature: float = 0.3
    max_tokens: int = 8192


@dataclass
class LiteLLMConfig:
    port: int = 4000
    fallback_models: list[str] = field(default_factory=lambda: [
        "ollama/qwen3:30b-a3b",
        "anthropic/claude-sonnet-4-20250514",
    ])


@dataclass
class OllamaConfig:
    host: str = "http://localhost:11434"
    models_to_pull: list[str] = field(default_factory=lambda: ["qwen3:30b-a3b"])
    context_length: int = 32768


@dataclass
class RAGConfig:
    persist_dir: str = "patches/archon-harness/.chromadb"
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 512
    top_k: int = 5


@dataclass
class HarnessSettings:
    repo_root: str = "."
    default_project: str | None = None
    max_worker_retries: int = 3
    worker_timeout_sec: int = 120
    mcp_port: int = 8080


@dataclass
class Config:
    orchestrator: ModelConfig = field(default_factory=ModelConfig)
    worker: ModelConfig = field(default_factory=lambda: ModelConfig(
        provider="ollama",
        model="qwen3:30b-a3b",
        temperature=0.1,
        max_tokens=4096,
    ))
    fallback: ModelConfig = field(default_factory=lambda: ModelConfig(
        provider="anthropic",
        model="claude-sonnet-4-20250514",
        temperature=0.2,
        max_tokens=4096,
    ))
    litellm: LiteLLMConfig = field(default_factory=LiteLLMConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    harness: HarnessSettings = field(default_factory=HarnessSettings)

    @property
    def repo_root_path(self) -> Path:
        return Path(self.harness.repo_root).resolve()

    def orchestrator_model_string(self) -> str:
        """Model string for Pydantic AI / LiteLLM."""
        return f"{self.orchestrator.provider}/{self.orchestrator.model}"

    def worker_model_string(self) -> str:
        return f"ollama/{self.worker.model}"


def _dict_to_dataclass(cls: type, data: dict[str, Any]) -> Any:
    """Recursively convert nested dicts to dataclass instances."""
    if not isinstance(data, dict):
        return data
    field_types = {f.name: f.type for f in cls.__dataclass_fields__.values()}
    kwargs = {}
    for key, value in data.items():
        if key in field_types and isinstance(value, dict):
            # Resolve the type — look up from the class defaults
            default_obj = getattr(Config, key, None)
            if hasattr(cls, "__dataclass_fields__") and key in cls.__dataclass_fields__:
                ft = cls.__dataclass_fields__[key]
                if hasattr(ft.default_factory, "__func__"):
                    pass  # complex default, skip type inference
                target_type = type(ft.default) if ft.default is not ft.default_factory else None
            target_cls = {
                "orchestrator": ModelConfig,
                "worker": ModelConfig,
                "fallback": ModelConfig,
                "litellm": LiteLLMConfig,
                "ollama": OllamaConfig,
                "rag": RAGConfig,
                "harness": HarnessSettings,
            }.get(key)
            if target_cls:
                kwargs[key] = _dict_to_dataclass(target_cls, value)
            else:
                kwargs[key] = value
        else:
            kwargs[key] = value
    return cls(**kwargs)


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from YAML file, with defaults for missing fields."""
    if path is None:
        candidates = [
            Path("patches/archon-harness/config.yaml"),
            Path("harness/config.yaml"),
        ]
        for c in candidates:
            if c.exists():
                path = c
                break
    if path is not None:
        path = Path(path)
        if path.exists():
            raw = yaml.safe_load(path.read_text()) or {}
            # Flatten nested 'models' key if present
            if "models" in raw:
                models = raw.pop("models")
                for k in ("orchestrator", "worker", "fallback"):
                    if k in models:
                        raw[k] = models[k]
            return _dict_to_dataclass(Config, raw)
    return Config()
