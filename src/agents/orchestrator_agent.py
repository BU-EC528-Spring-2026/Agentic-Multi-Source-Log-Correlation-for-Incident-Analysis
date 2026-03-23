# src/agents/orchestrator_agent.py

import json
import logging
from pathlib import Path
from src.agents.auth_agent import AuthAgent
from src.agents.openstack_vm_agent import OpenStackVMAgent

class OrchestratorAgent:
    def __init__(self, log_file: str, output_file: str = "normalized/orchestrator_output.json"):
        self.log_file = log_file
        self.output_file = Path(output_file)
        self.auth_agent = AuthAgent(log_file)
        self.openstack_agent = OpenStackVMAgent(log_file)
        self.logger = logging.getLogger(__name__)
        self.incidents = []

    def run(self):
        logging.basicConfig(level=logging.INFO)
        self.logger.info("Orchestrator agent is running")

        # Run subagents
        auth_incidents = self.auth_agent.run()
        self.logger.info("AuthAgent produced %d incidents", len(auth_incidents))

        openstack_incidents = self.openstack_agent.run()
        self.logger.info("OpenStackVMAgent produced %d incidents", len(openstack_incidents))

        # Combine incidents
        self.incidents = auth_incidents + openstack_incidents
        self.logger.info("Orchestrator agent collected %d incidents total", len(self.incidents))

        # Ensure output directory exists
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON output
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(self.incidents, f, indent=2, ensure_ascii=False)

        self.logger.info("Orchestrator output written to %s", self.output_file)

# Example usage:
if __name__ == "__main__":
    OrchestratorAgent("normalized/unified_logs.jsonl").run()
