# Excluded from the active project

| Item from the ZIP | Kept where | Why excluded |
|---|---|---|
| `EasyOCR_Tool/EasyOCR-master.zip` (79 MB) | Inside the original ZIP only (not extracted) | Source code of an OCR engine, not a dataset. It needs PyTorch plus a model download at runtime. Tesseract already provides the OCR that PS16 requires and is tested. Adding it would make the project heavier with no measured benefit. |
| `EasyOCR_Tool/README.md`, `LICENSE (1).txt` | `datasets/excluded/EasyOCR_Tool/` | Kept for reference and attribution |
| `Microsoft Presidio …/presidio-main.zip` (108 MB) | Inside the original ZIP only (not extracted) | Source code of a PII SDK, not a dataset. It needs spaCy and a language-model download. The datasets were used to strengthen the existing explainable rules instead. Presidio stays on the future-work list. |
| `Microsoft Presidio …/README.MD`, `LICENSE.txt` | `datasets/excluded/Microsoft Presidio …/` | Kept for reference and attribution |

Nothing was deleted. To use either tool later, extract it from `datasets/original/AI_GuardRail_Datasets.zip`.
