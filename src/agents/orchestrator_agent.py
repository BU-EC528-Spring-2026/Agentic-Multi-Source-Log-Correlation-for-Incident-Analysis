import json
import logging
from pathlib import Path
from typing import Any

from src.agents.auth_agent import run_agent as run_auth_agent
from src.agents.openstack_vm_agent import run_agent as run_openstack_vm_agent
from src.common import load_logs


def run_source_agents(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    auth_incidents = run_auth_agent(logs)
    openstack_incidents = run_openstack_vm_agent(logs)
    return auth_incidents + openstack_incidents


class OrchestratorAgent:
    """
    Coordinate the rule-based source agents over normalized logs.

    This wrapper uses the same shared source-agent coordination path as src.main.
    """

    def __init__(
        self,
        log_file: str | Path,
        output_file: str | Path = "normalized/orchestrator_output.json",
    ) -> None:
        self.log_file = Path(log_file)
        self.output_file = Path(output_file)
        self.logger = logging.getLogger(__name__)
        self.incidents: list[dict[str, Any]] = []

    def run(self) -> list[dict[str, Any]]:
        logging.basicConfig(level=logging.INFO)
        self.logger.info("Orchestrator agent is running")

        if not self.log_file.exists():
            raise FileNotFoundError(f"normalized log file not found: {self.log_file}")

        logs = load_logs(self.log_file)
        self.incidents = run_source_agents(logs)
        self.logger.info(
            "Collected %d incidents across %d source agents",
            len(self.incidents),
            2,
        )

        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        with self.output_file.open("w", encoding="utf-8") as handle:
            json.dump(self.incidents, handle, indent=2, ensure_ascii=False)

        self.logger.info("Orchestrator output written to %s", self.output_file)
        return self.incidents


if __name__ == "__main__":
    OrchestratorAgent("normalized/unified_logs.jsonl").run()
