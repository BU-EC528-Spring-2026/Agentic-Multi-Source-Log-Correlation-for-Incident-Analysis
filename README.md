## Agentic Multi-Source Log Correlation for Incident Analysis

Overview

This project implements a multi-agent pipeline for analyzing structured log data from multiple sources. It was originally developed on a different branch, with the main log ingestion and agent components already implemented.

The orchestrator agent is my addition, which coordinates multiple sub-agents to produce a unified set of incidents from the logs.

Original Components

AuthAgent – Detects authentication-related incidents from Linux and OpenSSH logs.
OpenStackVMAgent – Detects OpenStack VM-related incidents.
Ingestion scripts – Normalize logs from multiple sources into a unified JSONL format.

My Edits

Added OrchestratorAgent in src/agents/orchestrator_agent.py.
The orchestrator:
Loads the unified log file.
Runs all sub-agents (AuthAgent, OpenStackVMAgent, etc.).
Collects incidents from each sub-agent.
Writes combined results to normalized/orchestrator_output.json.
Added logging for orchestrator-level events.
Adjusted sub-agent constructors to accept a log_file argument for seamless integration.

Directory Structure

src/
agents/
auth_agent.py
openstack_vm_agent.py
orchestrator_agent.py # My addition
ingestion/
ingest_logs.py
retrieval/
build_retrieval_index.py

data/ – Folder containing structured log datasets (OpenStack, Linux, OpenSSH, Apache).
normalized/ – Output folder where unified logs and agent outputs are stored.

Setup Instructions

Clone the repository (replace YOUR_USERNAME with your GitHub username):

git clone git@github.com
:BU-EC528-Spring-2026/Agentic-Multi-Source-Log-Correlation-for-Incident-Analysis.git
cd Agentic-Multi-Source-Log-Correlation-for-Incident-Analysis

Set up a virtual environment:

python3 -m venv venv
source venv/bin/activate (macOS/Linux)
venv\Scripts\activate (Windows)

Install dependencies:

pip install -r requirements.txt

Download or copy the log data (if not already present):
Logs are hosted in a separate repository (loghub) and need to be available locally:

git clone https://github.com/logpai/loghub.git
 ~/loghub

Ensure the following files exist:

~/loghub/OpenStack/OpenStack_2k.log_structured.csv
~/loghub/OpenSSH/OpenSSH_2k.log_structured.csv
~/loghub/Linux/Linux_2k.log_structured.csv
~/loghub/Apache/Apache_2k.log_structured.csv

Or copy them into data/<source>/ inside this repo.
Run log ingestion:

PYTHONPATH=. python src/ingestion/ingest_logs.py

Output: normalized/unified_logs.jsonl
Run the orchestrator agent:

PYTHONPATH=. python -c "from src.agents.orchestrator_agent import OrchestratorAgent; OrchestratorAgent('normalized/unified_logs.jsonl').run()"

Output: normalized/orchestrator_output.json
This file contains combined incidents from all sub-agents.

Notes

The orchestrator agent does not modify the original sub-agents. It simply runs them sequentially and collects their outputs.
Logging is configured to provide status messages about the number of incidents detected by each sub-agent.
For development, make sure PYTHONPATH=. is set to allow imports from src.
