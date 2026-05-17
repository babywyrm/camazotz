"""Types for the camazotz model-tier benchmark."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

ProbeOutcome = Literal["pass", "fail", "partial", "error"]


@dataclass
class ProbeResult:
    """Result of running one probe against the current brain provider."""

    probe_id: str
    category: str
    description: str
    latency_ms: int
    input_tokens: int
    output_tokens: int
    outcome: ProbeOutcome
    # True when the model resisted a malicious prompt (injection probes).
    # True when the model called the right tool (accuracy probes).
    passed: bool
    response_preview: str  # first 200 chars of model response
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "category": self.category,
            "description": self.description,
            "latency_ms": self.latency_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "outcome": self.outcome,
            "passed": self.passed,
            "response_preview": self.response_preview,
            "notes": self.notes,
        }


@dataclass
class BenchmarkRun:
    """A full benchmark run across all probes for one model."""

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    model: str = ""
    provider: str = ""
    ollama_host: str = ""
    probes: list[ProbeResult] = field(default_factory=list)

    # Aggregate stats — populated by runner after all probes complete.
    total_probes: int = 0
    passed: int = 0
    failed: int = 0
    avg_latency_ms: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    injection_resistance_rate: float = 0.0  # 0.0-1.0
    tool_accuracy_rate: float = 0.0          # 0.0-1.0

    def summarise(self) -> None:
        """Compute aggregate fields from probe results."""
        self.total_probes = len(self.probes)
        self.passed = sum(1 for p in self.probes if p.passed)
        self.failed = self.total_probes - self.passed
        if self.probes:
            self.avg_latency_ms = round(
                sum(p.latency_ms for p in self.probes) / len(self.probes), 1
            )
        self.total_input_tokens = sum(p.input_tokens for p in self.probes)
        self.total_output_tokens = sum(p.output_tokens for p in self.probes)

        injection = [p for p in self.probes if p.category == "injection"]
        if injection:
            self.injection_resistance_rate = round(
                sum(1 for p in injection if p.passed) / len(injection), 3
            )

        accuracy = [p for p in self.probes if p.category == "tool_accuracy"]
        if accuracy:
            self.tool_accuracy_rate = round(
                sum(1 for p in accuracy if p.passed) / len(accuracy), 3
            )

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "model": self.model,
            "provider": self.provider,
            "ollama_host": self.ollama_host,
            "total_probes": self.total_probes,
            "passed": self.passed,
            "failed": self.failed,
            "avg_latency_ms": self.avg_latency_ms,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "injection_resistance_rate": self.injection_resistance_rate,
            "tool_accuracy_rate": self.tool_accuracy_rate,
            "probes": [p.to_dict() for p in self.probes],
        }
