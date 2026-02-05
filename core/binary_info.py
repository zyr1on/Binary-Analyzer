#!/usr/bin/env python3

import os
import hashlib
import struct
from pathlib import Path

class BinaryInfo:
    """
    A tool to extract static information from binary files (ELF for Linux, PE for Windows).
    It parses file headers to determine architecture, type, and other metadata.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.filesize = os.path.getsize(filepath)
        # Calculate properties upon initialization
        self.sha256 = self._calculate_sha256()
        self.binary_type = self._detect_binary_type()
        self.architecture = self._detect_architecture()
        self.stripped = self._is_stripped()
        self.section_count = self._count_sections()
        self.strings_count = self._count_strings()
        
    def _calculate_sha256(self):
        #Calculates the SHA256 hash of the file efficiently using chunks
        sha256_hash = hashlib.sha256()
        with open(self.filepath, "rb") as f:
            # Read file in 4KB blocks to avoid loading large files entirely into memory
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _detect_binary_type(self):
        # Identifies the file type by checking the 'Magic Bytes' at the beginning of the file
        with open(self.filepath, "rb") as f:
            magic = f.read(4)
            # 0x7F + 'ELF' indicates a Linux Executable and Linkable Format
            if magic[:4] == b'\x7fELF':
                return "ELF"
            # 'MZ' indicates a DOS/Windows Portable Executable (PE)
            elif magic[:2] == b'MZ':
                return "PE"
            else:
                return "UNKNOWN"
    
    def _detect_architecture(self):
        """
        Parses the binary header to find the Machine/Architecture field.
        The offset location depends on whether it is an ELF or PE file.
        """
        try:
            with open(self.filepath, "rb") as f:
                if self.binary_type == "ELF":
                    # In ELF headers, 'e_machine' field is at offset 0x12 (18 bytes)
                    f.seek(0x12)
                    e_machine = struct.unpack('<H', f.read(2))[0] # Read 2 bytes as unsigned short (little-endian)
                    
                    # Map hex values to human-readable architecture names
                    arch_map = {
                        0x03: "x86",
                        0x3E: "x86-64",
                        0x28: "ARM",
                        0xB7: "AArch64"
                    }
                    return arch_map.get(e_machine, f"Unknown (0x{e_machine:x})")
                
                elif self.binary_type == "PE":
                    # PE files have a pointer to the PE header at offset 0x3C
                    f.seek(0x3C)
                    pe_offset = struct.unpack('<I', f.read(4))[0]
                    
                    # The Machine field is 4 bytes after the PE signature start
                    f.seek(pe_offset + 4)
                    machine = struct.unpack('<H', f.read(2))[0]
                    
                    arch_map = {
                        0x014c: "x86",
                        0x8664: "x86-64",
                        0x01c0: "ARM",
                        0xAA64: "AArch64"
                    }
                    return arch_map.get(machine, f"Unknown (0x{machine:x})")
        except:
            return "Unknown"
        
        return "Unknown"
    
    def _is_stripped(self):
        """
        Checks if debug symbols have been stripped from the binary.
        Note: Currently relies on the external 'file' command (Linux specific).
        """
        if self.binary_type == "ELF":
            try:
                import subprocess
                # Execute the 'file' command and check output for the word 'stripped'
                result = subprocess.run(['file', self.filepath], 
                                        capture_output=True, text=True)
                return 'stripped' in result.stdout.lower()
            except:
                return None
        return None
    
    def _count_sections(self):
        # Reads the number of sections/segments defined in the file header
        try:
            if self.binary_type == "ELF":
                with open(self.filepath, "rb") as f:
                    # e_shnum (number of section headers) is at offset 0x30 in 64-bit ELF
                    # Note: This offset might vary for 32-bit ELF (usually 0x20)
                    f.seek(0x30)
                    e_shnum = struct.unpack('<H', f.read(2))[0]
                    return e_shnum
            elif self.binary_type == "PE":
                with open(self.filepath, "rb") as f:
                    f.seek(0x3C)
                    pe_offset = struct.unpack('<I', f.read(4))[0]
                    # NumberOfSections is at offset +6 from the PE signature
                    f.seek(pe_offset + 6)
                    num_sections = struct.unpack('<H', f.read(2))[0]
                    return num_sections
        except:
            return None
        return None
    
    def _count_strings(self):
        """
        Extracts ASCII strings from the binary.
        Looks for sequences of printable characters (length >= 4).
        Similar to the unix 'strings' command.
        """
        try:
            count = 0
            with open(self.filepath, "rb") as f:
                data = f.read() # Warning: Reads entire file into memory
                current_string = []
                for byte in data:
                    # Check if byte is a printable ASCII character (32-126)
                    if 32 <= byte <= 126:
                        current_string.append(chr(byte))
                    else:
                        # If sequence ends, check if it met the minimum length
                        if len(current_string) >= 4:
                            count += 1
                        current_string = []
                # Check for the last string in the file
                if len(current_string) >= 4:
                    count += 1
            return count
        except:
            return None
    
    def display(self):
        # Prints the gathered information to the console.
        print(f"File: {self.filepath}")
        print(f"Type: {self.binary_type}")
        print(f"Size: {self.filesize:,} bytes ({self.filesize / 1024:.2f} KB)")
        print(f"SHA256: {self.sha256}")
        print(f"Arch: {self.architecture}")
        
        if self.stripped is not None:
            status = f"Yes" if self.stripped else f"No"
            print(f"Stripped: {status}")
        
        if self.section_count is not None:
            print(f"Section: {self.section_count}")
        
        if self.strings_count is not None:
            print(f"Strings: {self.strings_count:,}")

# info = BinaryInfo("test_binary")
# info.display()
