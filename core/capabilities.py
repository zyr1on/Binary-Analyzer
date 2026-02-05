#!/usr/bin/env python3
import re

"""
Capabilities & IOC Scanner
Extracts interesting strings (IPs, URLs) and detects suspicious API usage.
"""

class CapabilityScanner:
    def __init__(self, filepath):
        self.filepath = filepath
        self.strings = self._get_strings()
        self.capabilities = []
        self.iocs = {
            'URLs': [],
            'IPs': [],
            'Emails': []
        }
        
        self._scan_iocs()
        self._scan_capabilities()

    def _get_strings(self):
        # extracts printable strings from binary
        # similar to unix 'strings' command
        min_length = 4
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
                result = ""
                for byte in data:
                    if 32 <= byte <= 126:
                        result += chr(byte)
                    else:
                        if len(result) >= min_length:
                            yield result
                        result = ""
                if len(result) >= min_length:
                    yield result
        except:
            return []

    def _scan_iocs(self):
        # regex patterns for indicators of compromise
        # analyzing extracted strings without re-reading file
        
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        # turning generator into list for multiple iterations
        # warning: memory intensive for huge files
        string_list = list(self.strings)
        full_text = " ".join(string_list)

        self.iocs['URLs'] = list(set(url_pattern.findall(full_text)))
        self.iocs['IPs'] = list(set(ip_pattern.findall(full_text)))
        self.iocs['Emails'] = list(set(email_pattern.findall(full_text)))

    def _scan_capabilities(self):
        # searching for suspicious api names in strings
        # this is a heuristic, imports might be hidden/packed
        
        suspicious_apis = {
            'Network': [
                'InternetOpen', 'HttpSendRequest', 'WSAStartup', 'connect', 
                'socket', 'URLDownloadToFile', 'WinHttpOpen'
            ],
            'File System': [
                'CreateFile', 'WriteFile', 'DeleteFile', 'CopyFile', 
                'ShellExecute', 'MoveFile'
            ],
            'Process Manipulation': [
                'CreateProcess', 'VirtualAllocEx', 'WriteProcessMemory', 
                'CreateRemoteThread', 'OpenProcess' # classic injection
            ],
            'Registry/Persistence': [
                'RegOpenKey', 'RegSetValueEx', 'RegCreateKey'
            ],
            'Spying/Keylog': [
                'GetAsyncKeyState', 'SetWindowsHookEx', 'GetForegroundWindow',
                'BitBlt' # screen capture
            ],
            'Cryptography': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash'
            ]
        }
        
        # re-getting strings since generator was consumed
        # optimizing: re-reading file is safer for memory than storing 100mb string list
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
                
                for category, apis in suspicious_apis.items():
                    found_apis = []
                    for api in apis:
                        if api.encode() in data:
                            found_apis.append(api)
                    
                    if found_apis:
                        self.capabilities.append({
                            'category': category,
                            'matches': found_apis
                        })
        except:
            pass

    def display(self):
        # 1. capabilities
        if self.capabilities:
            print(f"Detected Capabilities:")
            for cap in self.capabilities:
                print(f"  [{cap['category']}]")
                # print first 3 matches to avoid spam
                shown = cap['matches'][:3]
                remainder = len(cap['matches']) - 3
                print(f"   -> {', '.join(shown)}" + (f" (+{remainder} more)" if remainder > 0 else ""))
        else:
            print("No suspicious capabilities detected (or strings are obfuscated).")

        # 2. iocs
        print(f"\nExtracted IOCs:")
        
        has_ioc = False
        
        if self.iocs['URLs']:
            print(f"  [URLs] found {len(self.iocs['URLs'])}")
            for url in self.iocs['URLs'][:3]: # limit output
                print(f"   -> {url}")
            has_ioc = True
            
        if self.iocs['IPs']:
            print(f"  [IPs] found {len(self.iocs['IPs'])}")
            for ip in self.iocs['IPs'][:3]:
                print(f"   -> {ip}")
            has_ioc = True
            
        if self.iocs['Emails']:
            print(f"  [Emails] found {len(self.iocs['Emails'])}")
            for email in self.iocs['Emails'][:3]:
                print(f"   -> {email}")
            has_ioc = True
            
        if not has_ioc:
            print("  No obvious IOCs found.")
