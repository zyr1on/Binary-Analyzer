# Binary Static Analysis Tool

The tool is organized into a modular architecture to separate core analysis logic from specific packer detection signatures:

## Overview

This tool automates the process of gathering technical metadata from a binary file. It helps in identifying security features, potential obfuscation, and structural characteristics without the need to execute the file in a sandbox.

## Key Features

* **Static Triage:** Analyze binaries without execution to ensure safety..
* **Security Auditing:** Identify if a file lacks modern protections like Stack Canaries, NX bits, or ASLR.:
* **Obfuscation Detection:** Use high entropy values and signature matching to find hidden payloads..
* **Multi-Packer Support:** Built-in detection for industry-standard packers like Themida, UPX, and ASPack..
