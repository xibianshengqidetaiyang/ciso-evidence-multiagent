# CISO Evidence Multi-Agent

A multi-agent evidence processing assistant for CISO Assistant.

This project helps automate repetitive compliance evidence management tasks:

- parse evidence files such as PDF, DOCX, DOC, XLS/XLSX and CSV;
- classify evidence against compliance requirement assessments;
- import or reuse evidence through the CISO Assistant API;
- attach evidence to related controls;
- generate control-level Observation summaries and AI review suggestions.

## Positioning

This project is designed as an AI-assisted evidence triage and mapping tool.

It does **not** directly replace human auditors and does **not** enable automatic final compliance decisions by default.

Recommended default safety settings:

```env
APPLY_IMPORT=0
AUTO_APPLY_REVIEW_DECISION=0
CISO_SCORE_WRITE_MODE=none
```

AI suggestions are used for review support only.

## Architecture

```text
Evidence Folder
PDF / DOCX / DOC / XLS / XLSX / CSV
        ↓
Document Parser
text extraction / table extraction / PDF extraction / metadata
        ↓
RawEvidence
file_name / sha256 / extracted_text / metadata
        ↓
ClassifierAgent
evidence-to-control relevance matching
        ↓
Candidate Filtering
ATTACH_MIN_SCORE + FINAL_TARGET_TOP_K + child requirement expansion
        ↓
CisoApiClient
create/reuse evidence + upload file + attach to requirement assessment
        ↓
AdviceAgent
control-level Observation summary + review suggestions
        ↓
CISO Assistant
evidence mapping + Observation + human review
```

## Core Modules

```text
tools/review_and_import.py
Main orchestration script. It connects parsing, classification, CISO Assistant API import, evidence attachment, and Observation generation.

tools/document_parser.py
Parses PDF, Word, Excel and text files into RawEvidence.

tools/pdf_extractor.py
Handles PDF text extraction and OCR fallback if enabled.

tools/ciso_api.py
Wraps CISO Assistant API operations, including assessment resolution, evidence creation/reuse, upload, attachment and review note update.

agents/classifier_agent.py
Classifies evidence to candidate requirement assessments.

agents/advice_agent.py
Generates control-level Observation summaries and AI review suggestions.

schemas/evidence_models.py
Defines evidence data structures.
```

## Quick Start

Install dependencies:

```bash
pip install -r requirements.txt
```

Create local environment file:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Edit `.env`:

```env
CISO_BASE_URL=https://localhost:8443
CISO_USERNAME=your_username
CISO_PASSWORD=your_password
VERIFY_SSL=false

ASSESSMENT_ID=your_assessment_id
EVIDENCE_INPUT_DIR=demo_data/input

DEBUG_MODE=0
APPLY_IMPORT=0
AUTO_APPLY_REVIEW_DECISION=0
CISO_SCORE_WRITE_MODE=none
ATTACH_MIN_SCORE=0.40
FINAL_TARGET_TOP_K=10
```

Run dry-run:

```bash
python -m tools.review_and_import
```

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `ASSESSMENT_ID` | required | Target CISO Assistant compliance assessment ID. |
| `EVIDENCE_INPUT_DIR` | `demo_data/input` | Evidence input folder. |
| `APPLY_IMPORT` | `0` | Whether to actually create/reuse and attach evidence. |
| `AUTO_APPLY_REVIEW_DECISION` | `0` | Whether to automatically write AI review status/result. |
| `CISO_SCORE_WRITE_MODE` | `none` | Whether to write maturity score. Recommended: `none`. |
| `ATTACH_MIN_SCORE` | `0.40` | Minimum relevance score for automatic attachment. |
| `FINAL_TARGET_TOP_K` | `10` | Maximum number of controls attached by each evidence file. |

## Demo Data

The `demo_data/input` directory contains synthetic evidence examples only.

Do not upload real customer evidence, contracts, audit reports or confidential assessment files to a public repository.

## Demo Outputs

The `demo_outputs` directory contains sanitized sample output files:

```text
demo_outputs/import_review_manifest_demo.json
demo_outputs/review_decision_manifest_demo.json
```

These files demonstrate expected output structure and should not be treated as real audit results.

## Safety Design

- Low-confidence candidates are filtered by `ATTACH_MIN_SCORE`.
- Each evidence file is limited by `FINAL_TARGET_TOP_K`.
- AI review decisions are not automatically applied by default.
- Final audit conclusions should be confirmed by human reviewers.
- Real credentials should only be stored in local `.env`, which is excluded by `.gitignore`.

## Limitations

- The current version is suitable for AI-assisted triage, not full automatic auditing.
- Broad policy documents may match multiple controls.
- PPTX, ZIP and EML parsing can be further improved.
- A human confirmation UI can be added before batch import.

## Roadmap

- Add a pre-import review UI.
- Improve control-family constraints.
- Add PPTX / ZIP / EML parsing.
- Add Top-1 / Top-3 evaluation metrics.
- Add a small human-labeled benchmark set for continuous evaluation.

## Disclaimer

This project is for research, internal automation and demo purposes. It should not be used as the sole basis for compliance conclusions. Human review is required before making final audit decisions.
