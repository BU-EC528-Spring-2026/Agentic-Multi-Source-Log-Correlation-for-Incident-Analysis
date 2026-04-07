# Data root and dataset layout

The pipeline reads **four** structured LogHub-style datasets from a configurable **data root**. The root is set by the environment variable **`LOG_DATA_ROOT`**; if unset, it defaults to **`data`** (relative to the project root). You can point it at an absolute path (e.g. a LogHub clone) so datasets stay outside this repo.

Datasets are **not** committed to git. Download and place them locally.

## Required datasets

| Dataset   | Path under data root       | Expected file name                    |
|-----------|----------------------------|----------------------------------------|
| OpenStack | `<data_root>/OpenStack/`   | `OpenStack_2k.log_structured.csv`      |
| OpenSSH   | `<data_root>/OpenSSH/`     | `OpenSSH_2k.log_structured.csv`        |
| Linux     | `<data_root>/Linux/`      | `Linux_2k.log_structured.csv`          |
| Apache    | `<data_root>/Apache/`     | `Apache_2k.log_structured.csv`         |

Examples:

- Default: `data/OpenStack/OpenStack_2k.log_structured.csv`, etc.
- With `export LOG_DATA_ROOT=/opt/loghub`: `/opt/loghub/OpenStack/OpenStack_2k.log_structured.csv`, etc.

## Getting the data

Download the structured (parsed) CSVs from the [LogHub repository](https://github.com/logpai/loghub) or its Zenodo links. Extract or copy each dataset so the expected file name lives in the path above under your chosen data root.

## Git

Contents under `data/OpenStack/`, `data/OpenSSH/`, `data/Linux/`, and `data/Apache/` are ignored. Do not commit datasets.
