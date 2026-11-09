# AGENTS.md — AI Coding Agent Instructions

## 1. Project Overview
- **Project**: `AI Dev Workbench` (`ASSU-Project/ai-dev-workbench`)
- **Stack**: Python 3.12+, FastAPI, Uvicorn, Microsoft/Data-Privacy-Stack `presidio-analyzer` & `presidio-anonymizer`, `spaCy` (`en_core_web_sm`), `openpyxl`, `pywebview`, Vanilla ES6 + Modern Light UI.

## 2. Essential Commands
- **Run Automated Test Suite**: `.venv/bin/python -m pytest -v`
- **Run Desktop Application**: `.venv/bin/python desktop.py`
- **Build Native Installers (`.dmg` & `.exe`)**: `.venv/bin/python build_installers.py`
- **Run Live E2E Self-Test**: `curl -s -X POST http://127.0.0.1:18765/api/system/self-test`

## 3. Architecture & Key Files
- `app/engine.py`: Core `PresidioMaskingEngine`, `ReversibleTokenizer`, 7 masking modes, Thai grapheme cluster segmentation, and 5 separated Entity Domain Groups.
- `app/recognizers.py`: Custom Thai & Developer Secret recognizers (`ThaiNationalIdRecognizer`, `ThaiPersonNameRecognizer`, `ThaiPhoneRecognizer`, `ThaiBankAccountRecognizer`, `ThaiAddressRecognizer`, `ApiKeyAndSecretRecognizer`).
- `app/excel_processor.py`: Deterministic parallel `.xlsx` / `.csv` batch processor with `_PII_Token_Vault` and lossless restoration.
- `app/ai_tools.py`: All 19 AI Developer Micro-Tools across Context/Token, Data/Schema, Prompt/Agent Debug, AI Guardrails, and Vector/Media.
- `app/server.py`: FastAPI REST endpoints, RFC 5987 UTF-8 `Content-Disposition` filename encoding, persistent `SESSION_TOKEN_MAP`, and `/api/system/self-test`.
- `app/static/index.html`, `app/static/styles.css`, `app/static/app.js`: Neutral Light-Theme Workbench UI.
- `tests/test_presidio_masking.py`: Comprehensive unit, integration, and DOM parity test suite.
