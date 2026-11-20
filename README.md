# Hybrid Network Intrusion Detection Testbed

Reproducible offline evaluation of a flow-based hybrid intrusion detector on the CIC-IDS2017 MachineLearningCSV release.

## Repository contents

- [Python detector source](hybrid-ids-testbed/src/hybrid_ids.py)
- [Step-by-step implementation and reproduction guide](hybrid-ids-testbed/IMPLEMENTATION_GUIDE.md)
- [Run-specific README](hybrid-ids-testbed/README.md)
- [Experiment configuration](hybrid-ids-testbed/config/experiment.json)
- [Measured results](hybrid-ids-testbed/outputs/experiment_results.json)
- [Run manifest and input hashes](hybrid-ids-testbed/outputs/run_manifest.json)
- [Python dependencies](hybrid-ids-testbed/requirements.txt)

The raw dataset files are not redistributed. Download CIC-IDS2017 from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html) and verify the input hashes in the run manifest before reproducing the run.

## Headline held-out results

On the duplicate-filtered Thursday/Friday test partition (994,400 flows), the Isolation Forest achieved 3.33% attack recall at 1.68% false-positive rate. The OR-fused detector achieved 3.52% recall at 2.45% false-positive rate. The full analysis, thresholds, class counts, and limitations are in the run outputs and project report.

## Reproduce

1. Use Python 3.11 or a compatible version and install the packages listed in `hybrid-ids-testbed/requirements.txt`.
2. Download the eight CIC-IDS2017 MachineLearningCSV files listed in the manifest.
3. Place the CSV files in the location specified by the implementation guide/configuration.
4. Run the command in the implementation guide.
5. Compare output counts and metrics with `outputs/experiment_results.json`.

The report deliberately treats this as a benchmark-only offline test. The selected CSV export lacks timestamps and source IPs, so the grouped scan and repeated-connection rules were not evaluated.

## Citation

See the report's References section for sources and dataset citations.