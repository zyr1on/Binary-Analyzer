# Binary Analyzer

A static analysis tool designed to extract information, detect security mitigations, and identify potential indicators of compromise (IOCs) from binary files.

## Overview

This tool performs several levels of static analysis on executable files to help determine their behavior and security posture. It is modular, allowing you to run specific checks or a full scan.

## Installation

Ensure you have Python 3.x installed. The project structure should look like this:

Linux
```bash
$ git clone https://github.com/zyr1on/Binary-Analyzer.git
$ cd Binary-Analyzer
$ python3 binary_analyzer.py <executable path>
```
Windows
```bash
# if you dont have git, install zip file and unzip it
C:\> cd Binary-Analyzer
C:\> python.exe binary_analyzer.py <executable_path>
```



## Usage and Arguments
You can run the analyzer by passing the path to a binary file. Use flags to filter the output. If no flags are provided, the tool runs all checks by default.
```bash
python3 main.py <path_to_binary> [flags]
```

## Modules
```text
Info (-i):           Binary type (PE/ELF/Mach-O) and architecture.
Security (-s):       Exploitation protections like NX, ASLR, and Stack Canaries.
Entropy (-e):        Measures data randomness to identify packed code.
Packer (-p):         Detects common packers (UPX, ASPack) and suspicious sections.
Capabilities (-c):   Extracts network/injection APIs and network indicators.
```

---


### Available Flags
| Flag | Long Flag | Description |
|-----|----------|-------------|
| `-i` | `--info` | Show basic binary metadata (arch, type, etc.) |
| `-s` | `--security` | Show security mitigations (NX, ASLR, Canary, etc.) |
| `-e` | `--entropy` | Show entropy analysis to detect packed data |
| `-p` | `--packer` | Run packer detection logic |
| `-c` | `--capability` | Scan for suspicious APIs and IOCs (IPs, URLs) |
| `-a` | `--all` | Run all modules (Default behavior) |


## Examples
Run a full analysis on a sample:
```
> python3 main.py a.exe
or
> python3 main.py a.out
```
Check only the security mitigations and entropy:
```
python3 main.py malware.exe -s -e
```
Check capabilities and IOCs:
```
python3 main.py malware.exe -c
```
