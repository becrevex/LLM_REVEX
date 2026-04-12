import os
import zipfile
import shutil
import argparse
import requests
from pathlib import Path
from urllib.parse import urlparse

#Usage:
#python repo_processor.py vuln --local-file "C:\code\auth.py" --output "C:\temp\auth_vuln_review.txt"
#python repo_processor.py summary --repo https://github.com/pallets/flask --filetype py --output "C:\temp\flask_summary.txt"

#Local Directory Scan Example:
#python repo_processor.py vuln --local-dir "C:\projects\app" --filetype py

#Local Directory Summary
#python repo_processor.py summary --local-dir "./src" --filetype js


#OLLAMA_ENDPOINT = "http://192.168.0.92:11434/api/generate"
#OLLAMA_MODEL = "deepseek-coder-v2:16b"

DEFAULT_OLLAMA_ENDPOINT = "http://192.168.0.227:11434/api/generate"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:3b"

BASE_DIR = Path("github_repo_processing")
ZIP_DIR = BASE_DIR / "zip"
EXTRACT_DIR = BASE_DIR / "extracted"

MAX_FILE_SIZE_BYTES = 200_000
MAX_PROMPT_CHARS = 30_000


def prepare_directories() -> None:
    if BASE_DIR.exists():
        shutil.rmtree(BASE_DIR)
    ZIP_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)


def parse_github_url(repo_url: str) -> tuple[str, str]:
    """
    Extract owner and repo from a GitHub URL.
    """
    parsed = urlparse(repo_url)
    if parsed.netloc not in ("github.com", "www.github.com"):
        raise ValueError("Provided URL is not a GitHub URL.")

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repository name.")

    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    return owner, repo


def download_github_repo_zip(repo_url: str) -> Path:
    """
    Try downloading the repo zip from main branch first, then master.
    """
    owner, repo = parse_github_url(repo_url)
    zip_path = ZIP_DIR / f"{repo}.zip"

    candidate_urls = [
        f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip",
        f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip",
    ]

    last_error = None

    for url in candidate_urls:
        try:
            print(f"[*] Trying download: {url}")
            response = requests.get(url, stream=True, timeout=60)
            if response.status_code == 200:
                with open(zip_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                print(f"[+] Downloaded repo zip to: {zip_path}")
                return zip_path
            last_error = f"HTTP {response.status_code} for {url}"
        except Exception as e:
            last_error = str(e)

    raise RuntimeError(f"Failed to download repository zip. Last error: {last_error}")


def unzip_repo(zip_path: Path) -> Path:
    """
    Extract the zip file and return the extracted repo root.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(EXTRACT_DIR)

    extracted_dirs = [p for p in EXTRACT_DIR.iterdir() if p.is_dir()]
    if not extracted_dirs:
        raise RuntimeError("No extracted repository directory found.")

    if len(extracted_dirs) == 1:
        return extracted_dirs[0]

    return EXTRACT_DIR


def is_binary_file(file_path: Path) -> bool:
    """
    Simple binary file heuristic.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
        return b"\x00" in chunk
    except Exception:
        return True


def collect_matching_files(repo_root: Path, extension: str) -> list[tuple[str, str]]:
    """
    Recursively search for files with the given extension.
    Return:
        [(file_path, file_contents), ...]
    """
    if not extension.startswith("."):
        extension = "." + extension

    matches: list[tuple[str, str]] = []

    excluded_dirs = {
        ".git", ".github", "node_modules", "dist", "build",
        "venv", ".venv", "__pycache__", ".idea", ".vscode"
    }

    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]

        for file_name in files:
            if not file_name.endswith(extension):
                continue

            file_path = Path(root) / file_name

            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    print(f"[!] Skipping large file: {file_path}")
                    continue

                if is_binary_file(file_path):
                    print(f"[!] Skipping binary file: {file_path}")
                    continue

                content = file_path.read_text(encoding="utf-8", errors="ignore")
                matches.append((str(file_path), content))

            except Exception as e:
                print(f"[!] Failed reading {file_path}: {e}")

    return matches


def build_summary_prompt(file_path: str, file_contents: str) -> str:
    truncated_contents = file_contents[:MAX_PROMPT_CHARS]

    return f"""
You are reviewing a source code file from a GitHub repository.

Summarize this file in a useful way.

Include:
1. The purpose of the file
2. Key classes, functions, or methods
3. Important workflows or logic
4. Security-relevant or unusual behavior, if any
5. A brief plain-English summary

File path:
{file_path}

File contents:
{truncated_contents}
""".strip()


def build_vuln_prompt(file_path: str, file_contents: str) -> str:
    truncated_contents = file_contents[:MAX_PROMPT_CHARS]

    return f"""
You are performing a focused secure code review on a single source code file.

Your task is to identify potentially critical or high-severity vulnerabilities in this file.

Prioritize findings such as:
- command injection
- SQL injection
- code injection
- unsafe deserialization
- path traversal
- SSRF
- authentication bypass
- authorization flaws
- arbitrary file read/write
- insecure use of cryptography
- hardcoded secrets
- memory corruption risks
- remote code execution paths
- unsafe shell execution
- insecure use of eval or dynamic execution
- trust boundary violations
- dangerous use of user-controlled input

For each finding, provide:
1. Vulnerability title
2. Severity estimate
3. Why it is a vulnerability
4. The relevant code pattern or function involved
5. How it may be exploited
6. Recommended remediation

If no critical or high-severity issue is present, say so clearly and briefly mention any lower-confidence concerns.

Be precise. Do not invent behavior not supported by the file.

File path:
{file_path}

File contents:
{truncated_contents}
""".strip()


def scan_local_file_for_vulns(local_file_path: str, endpoint: str, model: str) -> str:
    file_path = Path(local_file_path)

    if not file_path.exists() or not file_path.is_file():
        raise ValueError(f"Invalid file: {file_path}")

    file_contents = file_path.read_text(encoding="utf-8", errors="ignore")
    prompt = build_vuln_prompt(str(file_path.resolve()), file_contents)

    return query_ollama(prompt, endpoint, model)


def query_ollama(prompt: str, endpoint: str, model: str) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(endpoint, json=payload, timeout=300)
    response.raise_for_status()

    data = response.json()
    return data.get("response", "").strip()


def process_file(mode: str, file_path: str, file_contents: str, endpoint: str, model: str) -> str:
    if mode == "summary":
        prompt = build_summary_prompt(file_path, file_contents)
    elif mode == "vuln":
        prompt = build_vuln_prompt(file_path, file_contents)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    return query_ollama(prompt, endpoint, model)


def write_single_result(file_path: str, result: str, output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=" * 100 + "\n")
        f.write("MODE: vuln\n")
        f.write(f"FILE: {file_path}\n")
        f.write("=" * 100 + "\n")
        f.write(result + "\n")


def validate_local_directory(path: str) -> Path:
    dir_path = Path(path)

    if not dir_path.exists():
        raise FileNotFoundError(f"Directory does not exist: {dir_path}")

    if not dir_path.is_dir():
        raise ValueError(f"Path is not a directory: {dir_path}")

    return dir_path.resolve()

def resolve_ollama_config(endpoint_arg: str | None, model_arg: str | None):
    endpoint = endpoint_arg if endpoint_arg else DEFAULT_OLLAMA_ENDPOINT
    model = model_arg if model_arg else DEFAULT_OLLAMA_MODEL

    return endpoint, model


def run_local_directory(mode: str, local_dir: str, file_extension: str, endpoint: str, model: str, output_path: str | None = None) -> None:
    print(f"[*] Scanning local directory: {local_dir}")

    dir_path = validate_local_directory(local_dir)

    print(f"[*] Searching recursively for '*.{file_extension.lstrip('.')}' files...")
    matched_files = collect_matching_files(dir_path, file_extension)

    print(f"[+] Found {len(matched_files)} matching files")

    if not matched_files:
        print("[!] No matching files found.")
        return

    file_tuples = matched_files
    results: list[tuple[str, str]] = []

    for index, (file_path, file_contents) in enumerate(file_tuples, start=1):
        print(f"[*] Processing {index}/{len(file_tuples)}: {file_path}")
        try:
            result = process_file(mode, file_path, file_contents, endpoint, model)
        except Exception as e:
            result = f"ERROR: Failed to process file. Reason: {e}"

        results.append((file_path, result))

    default_output = BASE_DIR / f"localdir_{file_extension}_{mode}_results.txt"
    output_file = resolve_output_path(output_path, default_output)

    print(f"[*] Writing results to: {output_file}")
    write_results(results, output_file, mode)

    print("[+] Done.")
    print(f"[+] Output file created at: {output_file}")


def write_results(results: list[tuple[str, str]], output_file: Path, mode: str) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        for file_path, result in results:
            f.write("=" * 100 + "\n")
            f.write(f"MODE: {mode}\n")
            f.write(f"FILE: {file_path}\n")
            f.write("=" * 100 + "\n")
            f.write(result + "\n\n")


def build_output_file(repo_url: str, file_extension: str, mode: str) -> Path:
    _, repo = parse_github_url(repo_url)
    clean_ext = file_extension.lstrip(".")
    output_name = f"{repo}_{clean_ext}_{mode}_results.txt"
    return BASE_DIR / output_name

def resolve_output_path(output_arg: str | None, default_path: Path) -> Path:
    if output_arg:
        return Path(output_arg).expanduser().resolve()
    return default_path.resolve()

def prepare_fetch_directories() -> None:
    ZIP_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

def run_fetch_only(repo_url: str) -> None:
    print("[*] Preparing workspace...")
    prepare_fetch_directories()

    print("[*] Downloading repository zip...")
    zip_path = download_github_repo_zip(repo_url)

    print("[*] Extracting repository...")
    repo_root = unzip_repo(zip_path)

    print("[+] Done.")
    print(f"[+] Zip file saved at: {zip_path.resolve()}")
    print(f"[+] Repository extracted to: {repo_root.resolve()}")


def run(mode: str, repo_url: str, file_extension: str, endpoint: str, model: str) -> None:
    print("[*] Preparing workspace...")
    prepare_directories()

    print("[*] Downloading repository zip...")
    zip_path = download_github_repo_zip(repo_url)

    print("[*] Extracting repository...")
    repo_root = unzip_repo(zip_path)
    print(f"[+] Repository extracted to: {repo_root}")

    print(f"[*] Searching recursively for '*.{file_extension.lstrip('.')}' files...")
    matched_files = collect_matching_files(repo_root, file_extension)
    print(f"[+] Found {len(matched_files)} matching files")

    if not matched_files:
        print("[!] No matching files found.")
        return

    # Explicit structure requested: list of tuples
    file_tuples = matched_files

    results: list[tuple[str, str]] = []

    for index, (file_path, file_contents) in enumerate(file_tuples, start=1):
        print(f"[*] Processing {index}/{len(file_tuples)}: {file_path}")
        try:
            result = process_file(mode, file_path, file_contents, endpoint, model)
        except Exception as e:
            result = f"ERROR: Failed to process file. Reason: {e}"

        results.append((file_path, result))

    output_file = build_output_file(repo_url, file_extension, mode)
    print(f"[*] Writing results to: {output_file}")
    write_results(results, output_file, mode)

    print("[+] Done.")
    print(f"[+] Output file created at: {output_file.resolve()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download a GitHub repo, collect matching files, and send them to an Ollama model for summary or vulnerability review."
    )

    parser.add_argument(
        "mode",
        choices=["summary", "vuln", "fetch"],
        help="Operation mode: summary or vuln or fetch (fetch just downloads and extracts without processing)"
    )

    parser.add_argument(
        "--repo",
        help="GitHub repository URL"
    )

    parser.add_argument(
        "--local-file",
        help="Path to one local source file to review for vulnerabilities"
    )

    parser.add_argument(
        "--filetype",
        help="File extension to search for, for example: py, js, c, cpp"
    )

    parser.add_argument(
        "--output",
        help="Optional output file path (overrides default naming)"
    )

    parser.add_argument(
        "--local-dir",
        help="Path to a local directory to recursively search for files (alternative to --repo)"
    )

    parser.add_argument(
        "--endpoint",
        help="Ollama endpoint (e.g. http://192.168.0.92:11434/api/generate)"
    )

    parser.add_argument(
        "--model",
        help="Ollama model name (e.g. deepseek-coder-v2:16b)"
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    endpoint, model = resolve_ollama_config(args.endpoint, args.model)

    print(f"[*] Using Ollama endpoint: {endpoint}")
    print(f"[*] Using model: {model}")

    # --- LOCAL FILE ---
    if args.local_file:
        result = scan_local_file_for_vulns(args.local_file, endpoint, model)

        default_output = BASE_DIR / "single_file_vuln_result.txt"
        output_file = resolve_output_path(args.output, default_output)

        write_single_result(args.local_file, result, output_file)
        return

    # --- LOCAL DIR ---
    if args.local_dir:
        if not args.filetype:
            raise ValueError("You must provide --filetype when using --local-dir.")

        run_local_directory(args.mode, args.local_dir, args.filetype, args.output, endpoint, model)
        return

    # --- REPO ---
    if not args.repo or not args.filetype:
        raise ValueError("For repo mode, you must provide --repo and --filetype.")

    run(args.mode, args.repo, args.filetype, args.output, endpoint, model)


if __name__ == "__main__":
    main()