# CoyoteKey: Advanced API Security Reconnaissance Toolkit

[![Go Version](https://img.shields.io/badge/go-1.20%2B-blue.svg)](https://golang.org)

**CoyoteKey** is a powerful and modern API security toolkit written in Go. It goes beyond simple brute-forcing by providing an intelligent, multi-layered discovery engine designed for both black-box and grey-box penetration testing.

From recursive endpoint discovery and smart parameter fuzzing to technology fingerprinting and targeted vulnerability probing, CoyoteKey is an all-in-one solution for comprehensively mapping and testing an API's attack surface.

## Key Features

- **Dual Modes**: A powerful `brutekey` mode for API key/token cracking and a sophisticated `discover` mode for full API reconnaissance.
- **Intelligent Discovery**: Merges inputs from multiple sources—wordlists, OpenAPI/Swagger specifications, and contextual data—for accurate endpoint mapping.
- **Multi-Layer Fingerprinting**: Identifies backend technologies through headers, cookies, content analysis, and favicon hashing, complete with a confidence scoring system.
- **Contextual Scanning**: Automatically loads relevant, technology-specific wordlists based on fingerprinting results to find non-obvious endpoints.
- **In-Depth Parameter Fuzzing**: Actively tests for parameters in URL queries, form-urlencoded bodies, and complex JSON structures via user-provided templates.
- **Targeted Vulnerability Probes**: After identifying the tech stack, it can run specific probes for common misconfigurations and vulnerabilities (e.g., exposed Spring Boot Actuators).
- **Adaptive Rate Limiting**: Automatically detects `429 Too Many Requests` responses and adjusts request delays to avoid being blocked.
- **Highly Extensible**: Fingerprinting and vulnerability probe behaviors are controlled by external JSON files, making the tool easy to update and customize.

## Installation

**Requirements:**
- **Go version 1.20 or newer** is required to compile the project and its dependencies.

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Febrian-chiperbase/CoyoteKey.git](https://github.com/Febrian-chiperbase/CoyoteKey.git)
    cd CoyoteKey
    ```

2.  **Install Dependencies:**
    This command will download and sync all required modules, including `kin-openapi`.
    ```bash
    go mod tidy
    ```

3.  **Build the Executable:**
    ```bash
    go build -o CoyoteKey .
    ```
    This command compiles the project and creates an executable file named `CoyoteKey` (or `CoyoteKey.exe` on Windows).

## Preparation

For full functionality in `discover` mode, create the following files and directories within your project's root directory:

1.  **`fingerprints.json`**: Your custom database of rules for detecting web technologies.
2.  **`vulnerabilities.json`**: Your database of specific vulnerability probes to run.
3.  **`context_wordlists/`**: A directory containing technology-specific wordlists (e.g., `spring_boot.txt`, `wordpress.txt`). The filenames must match the `tech` tags in `fingerprints.json`.

*You can use the examples provided in our previous conversations to get started.*

## Usage & Flags

CoyoteKey is controlled entirely through command-line flags.

### Common Flags

| Flag | Description |
| :--- | :--- |
| `-u` | **(Required)** Target Base URL. |
| `-mode`| Mode of operation: `brutekey` or `discover` (default: `brutekey`). |
| `-t` | Number of concurrent threads (default: 20). |
| `-o` | Output file to save results in JSON format. |
| `-proxy`| URL of an HTTP/S proxy to use. |
| `-delay` | Initial delay in milliseconds between requests per thread. |
| `-v` | Enable verbose logging for debugging. |
| `-timeout`| HTTP request timeout in seconds (default: 10). |

### `brutekey` Mode Flags

| Flag | Description |
| :--- | :--- |
| `-w` | **(Required)** Path to the wordlist file containing keys/tokens. |
| `-H` | Header format for placing the key (e.g., `"Authorization: Bearer %KEY%"`). |
| `-qp`| Query parameter name for placing the key. |
| `-jb` | JSON body template for placing the key (e.g., `'{"token":"%KEY%"}'`). |
| `-m` | HTTP method to use (default: `GET`). |
| `-s` | Comma-separated success HTTP status codes (e.g., `"200,201"`). |
| `-sr`| Regex pattern in the response body to consider a success. |
| `-fr`| Regex pattern in the response body to filter out and ignore. |

### `discover` Mode Flags

| Flag | Description |
| :--- | :--- |
| `-pw` | Path to the wordlist for path/endpoint discovery. |
| `-pp` | (Optional) Path to the wordlist for parameter discovery. |
| `--spec` | (Optional) Path to an OpenAPI/Swagger specification file. |
| `--depth`| (Optional) Recursion depth for discovery (default: 0). |
| `--fuzz-json` | (Optional) Path to a JSON template file for fuzzing request bodies. |
| `--fp-db` | Path to the `fingerprints.json` definition file (default: `./fingerprints.json`). |
| `--cwd` | Path to the contextual wordlists directory (default: `./context_wordlists`). |
| `--min-confidence`| Minimum confidence (`low`, `medium`, `high`) to use a contextual wordlist (default: `low`). |
| `--vuln-scan` | Enable the vulnerability probing phase after discovery. |
| `--vuln-db` | Path to the `vulnerabilities.json` definition file (default: `./vulnerabilities.json`). |

## Example Commands

**1. Brute-force an API Key in a Header**
```bash
./CoyoteKey -mode brutekey -u [https://api.example.com/v1/user](https://api.example.com/v1/user) -w tokens.txt -H "X-API-Token: %KEY%"
```

**Simple Path Discovery with a Wordlist**
```bash
./CoyoteKey -mode discover -u [https://api.example.com](https://api.example.com) -pw paths.txt
```

**Advanced Discovery and Vulnerability Scan**
This command uses recursion, parameter fuzzing, loads a spec file, enables fingerprinting, and runs vulnerability probes for high-confidence findings.
```bash
./CoyoteKey -mode discover -u [http://target.com](http://target.com) \
    -pw common-paths.txt \
    -pp common-params.txt \
    --spec api.json \
    --depth 1 \
    --min-confidence high \
    --vuln-scan \
    -v -o results.json
```
**Disclaimer**
This tool is intended for educational purposes and legitimate security testing only. The developer is not responsible for any misuse or damage caused by this program. Use it responsibly and only on systems you have explicit permission to test.

