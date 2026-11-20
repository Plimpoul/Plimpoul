# Hybrid Flow IDS Reproduction Artifacts

This project contains the runnable implementation and summary output for one full CIC-IDS2017 MachineLearningCSV benchmark run. It is a historical offline laboratory evaluation, not a live enterprise deployment.

## Repository files

- `src/hybrid_ids.py` — experiment implementation.
- `outputs/experiment_results.json` — file hashes, split audit, thresholds, test metrics, per-family results, runtime, and limitations.
- `outputs/run_manifest.json` — run-level audit and input hashes.
- `requirements.txt` — Python dependencies.

The raw CIC-IDS2017 CSV files and per-flow prediction export are not committed. The script generates `run_output/test_predictions.csv` when reproduced. The original dataset must be downloaded separately; see the cited dataset source in the report and implementation guide.

## Reproduce

Use Python 3.10 or later. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r hybrid-ids-testbed/requirements.txt
mkdir -p data/cicids2017
```

Place the eight standard `*.pcap_ISCX.csv` files in `data/cicids2017/`. The script assigns Monday to training, Tuesday/Wednesday to validation, and Thursday/Friday to testing. It removes exact duplicate feature rows found in later partitions and fits Isolation Forest using Monday benign flows only.

```bash
python hybrid-ids-testbed/src/hybrid_ids.py
```

Results are written to `run_output/`. The supplied MachineLearningCSV variant lacks timestamps and source IPs, so scan and repeated-connection predicates are disabled; only the packet-rate rule is evaluated.

## Dataset limitations

CIC-IDS2017 is a 2017 laboratory dataset with day-specific attack-family composition. The results are bounded by the CSV schema, feature-only duplicate-removal policy, split, and selected thresholds. Do not interpret them as current enterprise effectiveness.
