"""Single place for dataset locations (all under the git-ignored datasets/ tree)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASETS = ROOT / "datasets"
ORIGINAL = DATASETS / "original"                 # read-only originals (git-ignored)
ZIP_PATH = ORIGINAL / "AI_GuardRail_Datasets.zip"
EXTRACTED = ORIGINAL / "extracted" / "AI_GuardRail_Datasets"
PROCESSED = DATASETS / "processed"               # cleaned, derived subsets (git-ignored, rebuildable)
EXCLUDED = DATASETS / "excluded"                 # files judged not relevant (kept, not used)

POLICIES_DIR = EXTRACTED / "05_Sample_Policies"
CREDDETX_DIR = EXTRACTED / "CredDetX — API keys and credential detection"
NEMOTRON_DIR = EXTRACTED / "PII detection dataset — NVIDIA Nemotron-PII"
