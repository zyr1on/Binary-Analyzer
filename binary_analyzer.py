#!/usr/bin/env python3

import sys
import os
import argparse
from pathlib import Path

# Importing core modules
from core.binary_info import BinaryInfo
from core.security_checks import SecurityChecker
from core.entropy import EntropyAnalyzer
from core.packer_detector import PackerDetector
from core.capabilities import CapabilityScanner

def print_section(title):
    print(f"\n>>> {title}")
    print("-" * 50)

def analyze_binary(filepath, args):
    # 0. check if file exists
    if not os.path.exists(filepath):
        print(f"[!] Error: File Not Found: {filepath}")
        return
    
    # Logic: If -a is selected OR no flags are provided, run everything.
    run_all = args.all or not (args.info or args.security or args.entropy or args.packer or args.capability)

    print(f"\n[INFO] Starting Analysis for: {filepath}")

    # --- 1. Basic Metadata ---
    # We always instantiate this because other modules need binary_info.binary_type
    try:
        binary_info = BinaryInfo(filepath)
        if run_all or args.info:
            print_section("Basic Information")
            binary_info.display()
    except Exception as e:
        print(f"[!] Critical Error: Failed to retrieve binary info: {e}")
        return 

    # --- 2. Security Checks ---
    if run_all or args.security:
        print_section("Security Checks")
        try:
            security = SecurityChecker(filepath, binary_info.binary_type)
            security.display()
        except Exception:
            print("[!] Security check failed.")

    # --- 3. Entropy Analysis ---
    # we calculate entropy even if not displayed, as PackerDetector might need it
    entropy_val = None
    try:
        entropy = EntropyAnalyzer(filepath)
        entropy_val = entropy.entropy_value
        if run_all or args.entropy:
            print_section("Entropy Analysis")
            entropy.display()
    except Exception:
        if run_all or args.entropy:
            print("[!] Entropy analysis failed.")
    
    # --- 4. Packer Detection ---
    if run_all or args.packer:
        print_section("Packer Detection")
        try:
            packer = PackerDetector(filepath, binary_info.binary_type, entropy_val)
            packer.display()
        except Exception:
            print("[!] Packer detection failed.")

    # --- 5. Capabilities & IOCs ---
    if run_all or args.capability:
        print_section("Capabilities & IOCs")
        try:
            cap_scanner = CapabilityScanner(filepath)
            cap_scanner.display()
        except Exception:
            print("[!] Capability scan failed.")
        
    print(f"\n[INFO] Analysis Completed.")

def main():    
    parser = argparse.ArgumentParser(
        description="Binary Analyzer - A static analysis tool for suspicious binaries.",
        epilog="Example: python3 main.py malware.exe -s -c"
    )
    
    # positional argument
    parser.add_argument("filepath", help="Path to the binary file to analyze")

    # optional args
    parser.add_argument("-i", "--info", action="store_true", help="Show Basic Information")
    parser.add_argument("-s", "--security", action="store_true", help="Show Security Checks (NX, ASLR, etc.)")
    parser.add_argument("-e", "--entropy", action="store_true", help="Show Entropy Analysis")
    parser.add_argument("-p", "--packer", action="store_true", help="Show Packer Detection")
    parser.add_argument("-c", "--capability", action="store_true", help="Show Capabilities & IOCs")
    parser.add_argument("-a", "--all", action="store_true", help="Run all analyses (Default)")

    args = parser.parse_args()
    analyze_binary(args.filepath, args)

if __name__ == "__main__":
    main()
