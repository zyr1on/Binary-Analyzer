#!/usr/bin/env python3

import sys
import os
from pathlib import Path

# importing core modules
from core.binary_info import BinaryInfo
from core.security_checks import SecurityChecker
from core.entropy import EntropyAnalyzer
from core.packer_detector import PackerDetector
from core.capabilities import CapabilityScanner

def print_section(title):
    # standard separator for clean text output
    print(f"\n>>> {title}")
    print("-" * 50)

def analyze_binary(filepath):
    # check if file exists
    if not os.path.exists(filepath):
        print(f"[!] Error: File Not Found: {filepath}")
        return
    
    print(f"\n[INFO] Starting Analysis for: {filepath}")

    # 1. basic metadata
    print_section("Basic Information")
    try:
        binary_info = BinaryInfo(filepath)
        binary_info.display()
    except Exception:
        print("[!] Failed to retrieve binary info.")
        return 
    
    # 2. security checks
    print_section("Security Checks")
    try:
        security = SecurityChecker(filepath, binary_info.binary_type)
        security.display()
    except Exception:
        print("[!] Security check failed.")

    # 3. entropy analysis
    print_section("Entropy Analysis")
    try:
        entropy = EntropyAnalyzer(filepath)
        entropy.display()
    except Exception:
        print("[!] Entropy analysis failed.")
    
    # 4. packer detection
    print_section("Packer Detection")
    try:
        packer = PackerDetector(filepath, binary_info.binary_type, entropy.entropy_value)
        packer.display()
    except Exception:
        print("[!] Packer detection failed.")

    print_section("Capabilities & IOCs")
    try:
        cap_scanner = CapabilityScanner(filepath)
        cap_scanner.display()
    except Exception:
        print("[!] Capability scan failed.")
        
    
    print(f"\n[INFO] Analysis Completed.")

def main():    
    # argument check
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary_file>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    analyze_binary(binary_path)

if __name__ == "__main__":
    main()
