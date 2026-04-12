# LLM_REVEX

LLM_REVEX is a Python utility for working with GitHub repositories and local source code to generate review prompts for an Ollama model.

It currently supports:
- downloading a GitHub repository ZIP archive and extracting it locally
- collecting files by extension while excluding common binary and workspace directories
- generating security-focused vulnerability prompts for individual files
- generating file summary prompts for source files
- querying an Ollama endpoint with a configurable model

## Usage

This repository currently contains `llm_revex.py`, which is designed to support command-line operations such as downloading repositories, scanning code, and reviewing local files or folders.

### Download a GitHub repository

```bash
python llm_revex.py vuln --repo https://github.com/pallets/flask --filetype py --output ./flask_vuln_review.txt
```

### Download a GitHub repository and scan it

```bash
python llm_revex.py summary --repo https://github.com/pallets/flask --filetype py --output ./flask_summary.txt
```

### Scan an individual local file

```bash
python llm_revex.py vuln --local-file "/path/to/code.py" --output ./code_vuln_review.txt
```

### Scan a local folder

```bash
python llm_revex.py summary --local-dir "./src" --filetype js --output ./src_summary.txt
```

## Notes

- `--repo` should be a GitHub repository URL.
- `--filetype` should be a file extension such as `py`, `js`, or `ts`.
- `--local-file` scans a single local source file.
- `--local-dir` scans a local directory recursively.
- `--output` is intended for writing results to a file.
- The Ollama endpoint and model are configurable in `llm_revex.py` via `DEFAULT_OLLAMA_ENDPOINT` and `DEFAULT_OLLAMA_MODEL`.
