# datasets/

Data from `AI_GuardRail_Datasets.zip`, audited in [`../dataset_audit/`](../dataset_audit/).

**Everything in this folder except this README and `excluded/EXCLUDED.md` is git-ignored.**

Why it stays out of git:

* The data is large: 464 MB.
* It contains secret-shaped and PII-shaped synthetic values. GitHub push protection would flag CredDetX's valid-checksum tokens.
* The CredDetX authors ask that their data never be published into training corpora.

```
datasets/
├── original/                       read-only originals (never edited)
│   ├── AI_GuardRail_Datasets.zip   the ZIP exactly as supplied (moved here from the project root)
│   └── extracted/AI_GuardRail_Datasets/
│       ├── 05_Sample_Policies/                         6 policy .txt files
│       ├── CredDetX — API keys and credential detection/  dev.jsonl, test.jsonl + docs
│       └── PII detection dataset — NVIDIA Nemotron-PII/   train/test .parquet + README
├── processed/                      rebuilt by scripts/datasets/build_processed.py
│   ├── nemotron_dev.jsonl          2,000-doc stratified sample of the TRAIN file (error analysis)
│   ├── nemotron_eval.jsonl         2,000-doc stratified sample of the TEST file (reporting only)
│   └── MANIFEST.json               hashes, seed, transformation counts
└── excluded/                       EasyOCR and Presidio README/LICENSE + EXCLUDED.md
```

The one integrated artefact that **is** committed is `policy/reference_policies.json`. It holds the six sample
policies as 27 clauses: short policy prose with no sensitive values.

## Setting it up on a new machine

```bash
mkdir -p datasets/original/extracted
mv AI_GuardRail_Datasets.zip datasets/original/            # or copy it there
cd datasets/original/extracted && unzip ../AI_GuardRail_Datasets.zip \
   -x "*/EasyOCR-master.zip" "*/presidio-main.zip" && cd ../../..
python scripts/datasets/audit_inventory.py   # optional: regenerates dataset_audit/dataset_inventory.csv
python scripts/datasets/build_processed.py   # reference policies + Nemotron samples
python scripts/datasets/evaluate.py all      # evaluation results → dataset_audit/evaluation/
```

The app itself does **not** need this folder. Without it, the gateway runs normally, and the dataset regression
tests are skipped.

Licences:

| Dataset | Licence | Credit |
|---|---|---|
| CredDetX | CC BY 4.0 | CobuildX AI, DOI 10.57967/hf/11414 |
| Nemotron-PII | CC BY 4.0 | NVIDIA |
| EasyOCR | Apache-2.0 | – |
| Presidio | MIT | – |
