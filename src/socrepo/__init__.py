"""SOC-in-a-Repo: a vendor-neutral detection-engineering lab.

The package turns a directory of Sigma rules into deployable Wazuh detections,
validates them against replayed Atomic Red Team telemetry, publishes an ATT&CK
coverage matrix distinguishing *attempted* from *validated* coverage, and triages
alerts with an LLM (falling back to a deterministic heuristic when no model is
available).

Public surface is intentionally small; import from the submodules for the rest.
"""

from __future__ import annotations

__version__ = "0.3.0"

__all__ = ["__version__"]
