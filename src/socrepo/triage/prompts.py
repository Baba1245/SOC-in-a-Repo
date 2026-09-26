"""Prompt construction for the LLM triage provider.

Kept in its own module so prompts are versioned, diffable, and testable
independently of the API-calling code.
"""

from __future__ import annotations

from ..models import Alert
from .rubric import RUBRIC, contract_json

PROMPT_VERSION = "triage-2024.1"

SYSTEM_PROMPT = f"""\
You are a senior SOC analyst performing tier-1 triage. You are precise,
calibrated, and you never invent facts not present in the alert.

{RUBRIC}

Respond with ONLY a single JSON object and nothing else — no prose, no
markdown fences. The object must have exactly these keys:

{contract_json()}
"""


def build_user_prompt(alert: Alert) -> str:
    return (
        "Triage the following alert. Return only the JSON object.\n\n"
        "----- ALERT -----\n"
        f"{alert.to_prompt_block()}\n"
        "-----------------"
    )
