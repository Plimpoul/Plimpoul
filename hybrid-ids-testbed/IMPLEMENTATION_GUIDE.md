# Reproduce the CIC-IDS2017 Hybrid IDS Run

This guide reproduces the offline benchmark represented by the committed source and result JSON. It does not claim live-network performance. The script reads the full MachineLearningCSV files; allow substantial RAM and disk capacity.

## 1. Prepare Python

Use Python 3.10 or newer. From the repository root, create an isolated environment and install the pinned-range dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r hybrid-ids-testbed/requirements.txt
```

On Windows PowerShell, use `.venv\Scripts\Activate.ps1` to activate the environment.

## 2. Obtain the dataset

Download the labeled CIC-IDS2017 flow CSV files from the [Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/ids-2017.html), or obtain the same MachineLearningCSV release from the mirror identified in the run outputs. Review the dataset citation and terms. The CSV files are not included in this repository.

Create `data/cicids2017/` at the repository root and place these eight files there:

1. `Monday-WorkingHours.pcap_ISCX.csv`
2. `Tuesday-WorkingHours.pcap_ISCX.csv`
3. `Wednesday-workingHours.pcap_ISCX.csv`
4. `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
5. `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
6. `Friday-WorkingHours-Morning.pcap_ISCX.csv`
7. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
8. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

Before interpreting a reproduced run, compare the script's recorded file SHA-256 values with `hybrid-ids-testbed/outputs/run_manifest.json`. If any source file differs, record the dataset variant and do not describe it as an exact reproduction.

## 3. Run the detector

From the repository root:

```bash
python hybrid-ids-testbed/src/hybrid_ids.py
```

The script assigns Monday to benign-only training, Tuesday/Wednesday to validation, and Thursday/Friday to the held-out test. It computes numeric features and training-only medians, removes exact feature-vector duplicates across later partitions, fits a 100-tree Isolation Forest (seed 42), and selects operating thresholds on validation. The available high packet-rate predicate is evaluated; scan and repeated-connection predicates are disabled because this CSV variant lacks timestamps and source IP addresses.

## 4. Review outputs

The script writes `run_output/experiment_results.json` and `run_output/test_predictions.csv`. Compare the result JSON against the committed `hybrid-ids-testbed/outputs/experiment_results.json`, including input hashes, partition counts, threshold selection, confusion counts, per-family recall, runtime, and the recorded schema limitations. The public GitHub repository contains the summary metrics and run manifest, but does not commit the raw dataset or per-flow prediction export. The run generates the uncompressed prediction CSV locally.

## 5. Interpret results carefully

The committed experiment contains 994,400 duplicate-filtered held-out flows. Isolation Forest recall was 3.33% at 1.68% false-positive rate; OR fusion recall was 3.52% at 2.45%. Treat these as one historical benchmark run, not a claim of present-day enterprise detection. Cross-day deduplication can remove distinct but feature-identical flows, and the capture schedule couples days to attack families. The report's Discussion section details these constraints.
