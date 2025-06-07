Of course. Here is the complete `README.md` description for **Coyotekey**, translated into English.

-----

# Coyotekey

> A fast and configurable command-line (CLI) API reconnaissance tool, designed to help pentesters and bug hunters discover hidden or undocumented API endpoints.

Coyotekey works by performing a wordlist-based attack against a target host to identify valid endpoints, leveraging concurrency to maximize speed.

## Key Features

  * **Fast Scanning**: Leverages Go's Goroutines to perform hundreds of concurrent HTTP requests.
  * **Flexible Configuration**: All settings can be managed through a single `config.json` file for ease of use.
  * **Multi-Method Support**: Test endpoints with GET, POST, PUT, DELETE, or other custom HTTP methods.
  * **Custom Headers**: Include custom headers in requests, essential for handling authentication (e.g., `Authorization: Bearer ...`).
  * **Status Code Filtering**: Focus only on relevant results by filtering responses based on HTTP status codes.
  * **Structured Output**: Save findings in a clean, machine-readable JSON format.

## Installation

You can install Coyotekey in one of two ways:

**1. From Source (Requires Go):**

```bash
go install github.com/YOUR_USERNAME/coyotekey@latest
```

*Be sure to replace `YOUR_USERNAME` with your GitHub username.*

**2. From GitHub Releases:**

Download the pre-compiled binary for your operating system from the [Releases page](https://www.google.com/search?q=https://github.com/YOUR_USERNAME/coyotekey/releases).

## Usage

While Coyotekey supports command-line arguments, the recommended way to use it is with a configuration file.

```bash
coyotekey -c config.json
```

**Command-Line Options (Flags):**

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-c`, `--config` | Path to the configuration file (`config.json`) | `config.json` |
| `-t`, `--target` | Target host URL (overrides config) | |
| `-w`, `--wordlist`| Path to the wordlist file (overrides config) | |
| `-o`, `--output` | Output file for results (overrides config) | `results.json` |
| `-v`, `--verbose` | Enable verbose output | `false` |

## Configuration File

Create a `config.json` file to control all aspects of the scan.

**Example `config.json`:**

```json
{
  "target_host": "https://api.example.com",
  "wordlist_path": "./wordlists/api-endpoints.txt",
  "http_methods": [
    "GET",
    "POST"
  ],
  "request_headers": {
    "User-Agent": "Coyotekey/1.0",
    "Authorization": "Bearer YOUR_ACCESS_TOKEN_HERE"
  },
  "threads": 20,
  "timeout_seconds": 10,
  "match_status_codes": [
    200,
    201,
    401,
    403
  ],
  "output_file": "results.json",
  "follow_redirects": true,
  "verbose": false
}
```

## Example Usage

1.  **Create a `config.json` file** like the example above and adjust its values.
2.  **Prepare your wordlist**, e.g., `api-endpoints.txt`.
3.  **Run the tool:**
    ```bash
    coyotekey -c config.json
    ```
4.  **Check the results:** Once finished, the `results.json` file will be created with all discovered endpoints.

## License

This project is licensed under the MIT License. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

## Disclaimer

This tool is intended for educational purposes and legitimate security testing only. The developer is not responsible for any misuse or damage caused by this program. **Use it responsibly and only on systems you have explicit permission to test.**
