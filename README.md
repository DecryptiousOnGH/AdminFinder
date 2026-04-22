# AdminFinder

**Author:** Decryptious_ on Discord / Punchborn on IG  
**License:** MIT  
**Platforms:** Linux, Windows, macOS

A fast, cross-platform reconnaissance tool that resolves target IPs and discovers admin/login panels through multi-threaded path brute-forcing.

---

## Features

- **Dual IP Resolution:** DNS socket lookup + native OS ping (Windows/Linux)
- **Multi-threaded Scanning:** Configurable thread pool for speed
- **Smart Detection:** Status code analysis + content keyword matching
- **Cross-Platform Colors:** Works in CMD, PowerShell, and Linux terminals
- **Export Reports:** Saves results to both `.txt` and `.json`
- **Custom Wordlists:** Use built-in paths or supply your own
- **Session Persistence:** Reuses HTTP connections for efficiency

---

## Installation

### Method 1: Direct Run
```bash
git clone https://github.com/DecryptiousOnGH/AdminFinder.git
cd AdminFinder
pip install -r requirements.txt
python3 adminfinder.py -u https://target.com