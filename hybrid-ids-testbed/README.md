# Hybrid Flow IDS Reproduction Artifacts

This bundle contains the runnable Python implementation and output from one full CIC-IDS2017 MachineLearningCSV benchmark run. The reported experiment is a historical laboratory benchmark, not a live enterprise deployment.

## Included files

- `src/hybrid_ids.py` - full experiment implementation used for the run.
- `outputs/experiment_results.json` - input file hashes, split audit, thresholds, test metrics, per-family results, runtime, and limitations.
- `outputs/test_predictions.csv.gz` - frozen per-flow held-out predictions and labels.
- `requirements.txt` - Python dependencies.

The original dataset is not included. Download the labeled flow CSV release from the official Canadian Institute for Cybersecurity page or an authenticated mirror. The files used for this run came from the public `c01dsnap/CIC-IDS2017` dataset mirror on Hugging Face. All eight file SHA-256 values are recorded in `experiment_results.json`; the Monday file hash matches the published mirror metadata. Cite the original CIC-IDS2017 dataset paper when reusing the benchmark.

## Reproduction

Use Python 3.10 or later. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p data/cicids2017
```

Place all eight `*.pcap_ISCX.csv` files in `data/cicids2017/` using their standard filenames. The script assigns Monday to training, Tuesday and Wednesday to validation, and Thursday and Friday to test. It drops exact duplicate feature rows found in later partitions, keeps near duplicates, uses all Monday benign records, and fits the Isolation Forest with 100 trees and seed 42. It selects thresholds on validation at a 1% benign false-positive objective where feasible. Results are written to `run_output/`.

```bash
python src/hybrid_ids.py
```

The supplied MachineLearningCSV variant lacks timestamps and source IPs, so the scan and repeated-connection predicates are disabled. The packet-rate rule runs on `Flow Packets/s`. The audit output records this constraint. Do not claim that the grouped rules ran for these files.

## Dataset facts and limitations

The CIC-IDS2017 source describes a five-day capture (July 3-7, 2017) with Monday normal traffic and attacks on Tuesday through Friday. The day split therefore has attack-family/day confounding. The test set includes families not represented in the training data. The result is limited to this benchmark, CSV schema, split, features, and operating thresholds.
