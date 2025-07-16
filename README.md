# CVSS Score Sage

**CVSS Score Sage** is a tool designed to **compare the CVSS score** RHTPA against GitHub CVE Project

---

## What It Does

- Fetches CVE data from the [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) GitHub repository.
- Connects to RHTPA using Vulnerability API.
- Compares `baseScore` from CVE json from github cve project repository against TPA `average_score`

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/cvss-score-sage.git
cd cvss-score-sage
```

### 2. Set Up Your Environment
Open main.rs and configure the following:
```bash
let tpa_baseurl = "<TPA_BaseURL>";       // e.g., "https://server-tpa.apps.cluster.tpa.qe.net/"
let tpa_access_token = "Access Token";   // your access token here
```
### 3. Run the application
```bash
cargo run
```
### 4. Log and Output
The log and output files saved in the project directory `sage.log` and `analysis.csv`

## Limitations
 - Reported loaded with `mismatch_tpa_cvev5`as `Yes`, when the loaded CVE JSON contains only `other` block on cna.metrics. 