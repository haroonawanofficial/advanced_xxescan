# Advanced XXE Scan Script

## Description

This script is designed to scan a specified domain for XXE (XML External Entity) vulnerabilities. It extracts URLs from the Wayback Machine and CommonCrawl, checks for the presence of a sitemap, and sends multiple XXE payloads to the extracted URLs. The script uses multiprocessing to improve efficiency and provides detailed logging throughout the process. The results are saved in an SQLite database, and an HTML report is generated to display the findings.

## Features

- **URL Extraction**: Extracts URLs from the Wayback Machine and CommonCrawl for a specified domain.
- **Sitemap Check**: Checks if the domain has a `sitemap.xml` file and includes it in the URL list if found.
- **Multiprocessing**: Uses multiprocessing to send payloads in parallel, improving performance and efficiency.
- **Advanced Heuristic Detection**: Utilizes advanced heuristics to detect potential vulnerabilities based on common indicators.
- **Robust Error Handling**: Includes error handling to ensure the script continues running even if individual requests fail.
- **HTML Escaping**: Properly escapes HTML characters in the payloads, responses, and URLs to ensure the report does not break.
- **Detailed Logging**: Provides detailed logging for debugging and tracking the script's progress.
- **HTML Report Generation**: Generates a detailed HTML report with the status (Vulnerable/Not Vulnerable) for each tested URL.
- **Obfuscation**: Includes various obfuscation techniques to evade detection by security mechanisms, increasing the likelihood of finding vulnerabilities.

## How It Works

1. **Setup Database**: Initializes the SQLite database and creates the necessary tables.
2. **Extract URLs**: Extracts URLs from the Wayback Machine and CommonCrawl for the specified domain.
3. **Check Sitemap**: Checks if the domain has a `sitemap.xml` file and adds it to the URL list if found.
4. **Send XXE Payloads**: Sends multiple XXE payloads to the extracted URLs using multiprocessing to improve efficiency.
5. **Log Responses**: Logs the responses to the SQLite database, including whether the URL is vulnerable or not based on heuristic detection.
6. **Generate HTML Report**: Generates an HTML report displaying the results in a table format, with proper HTML escaping to prevent report breakage.

## Benefits and Advantages

- **Comprehensive URL Extraction**: Leverages both Wayback Machine and CommonCrawl to extract a wide range of URLs, ensuring thorough testing.
- **Efficiency with Multiprocessing**: By utilizing multiple CPU cores, the script sends payloads in parallel, significantly speeding up the scanning process.
- **Advanced Vulnerability Detection**: Uses advanced heuristics to accurately detect XXE vulnerabilities, providing reliable results.
- **Robust Error Handling**: Ensures the script continues running smoothly even if individual requests encounter errors.
- **Detailed and Clear Reporting**: Generates a comprehensive HTML report with clear indications of vulnerability status, helping in quick assessment and remediation.
- **Scalable and Flexible**: Can handle large numbers of URLs and payloads, making it suitable for extensive security assessments.
- **Open-Source and Customizable**: The script can be easily modified and extended to include additional features or payloads as needed.

## How to Use

1. **Save the Script**: Save the script to a file, e.g., `xxescan.py`.
2. **Install Required Packages**:
    ```bash
    pip install requests waybackpy beautifulsoup4
    ```
3. **Run the Script** with the desired options:
    ```bash
    python xxescan.py -d <domain> -db <database_name> -r -v
    ```
   Replace `<domain>` with the target domain and `<database_name>` with the desired SQLite database file name.

## Example Command

```bash
python xxescan.py -d testphp.vulnweb.com -db xxe_test.db -r -v
