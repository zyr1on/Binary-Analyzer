#!/usr/bin/env python3

import struct
import subprocess

class SecurityChecker:
    # main init, detects if we need to check elf (linux) or pe (windows)
    def __init__(self, filepath, binary_type):
        self.filepath = filepath
        self.binary_type = binary_type
        self.checks = {}
        
        if binary_type == "ELF":
            self._check_elf_security()
        elif binary_type == "PE":
            self._check_pe_security()
    
    def _check_elf_security(self):
        # running standard linux security checks
        
        # nx: checks if stack is non-executable
        self.checks['NX'] = self._check_elf_nx()
        
        # pie: position independent executable, randomized memory
        self.checks['PIE'] = self._check_elf_pie()
        
        # relro: read only relocations, protects got table
        self.checks['RELRO'] = self._check_elf_relro()
        
        # canary: stack cookie protection against buffer overflow
        self.checks['CANARY'] = self._check_elf_canary()
        
        # interpreter: showing the loader path just in case
        self.checks['INTERPRETER'] = self._get_elf_interpreter()
    
    def _check_elf_nx(self):
        # parsing elf header manually to find gnu_stack segment
        try:
            with open(self.filepath, "rb") as f:
                
                f.seek(0)
                e_ident = f.read(16)
                ei_class = e_ident[4]  # 1 means 32bit, 2 means 64bit
                
                # getting program header offset based on arch
                if ei_class == 2:  # 64-bit
                    f.seek(0x20)
                    e_phoff = struct.unpack('<Q', f.read(8))[0]
                    f.seek(0x38)
                    e_phnum = struct.unpack('<H', f.read(2))[0]
                    ph_size = 56
                else:  # 32-bit
                    f.seek(0x1C)
                    e_phoff = struct.unpack('<I', f.read(4))[0]
                    f.seek(0x2C)
                    e_phnum = struct.unpack('<H', f.read(2))[0]
                    ph_size = 32
                
                # looping through headers to find the stack one
                for i in range(e_phnum):
                    offset = e_phoff + (i * ph_size)
                    f.seek(offset)
                    p_type = struct.unpack('<I', f.read(4))[0]
                    
                    # 0x6474e551 is PT_GNU_STACK
                    if p_type == 0x6474e551:
                        # checking flags
                        f.seek(offset + (4 if ei_class == 1 else 8))
                        p_flags = struct.unpack('<I', f.read(4))[0]
                        # if first bit is 0, it means not executable (nx enabled)
                        return not (p_flags & 0x1)
                
                return False
        except:
            return None
    
    def _check_elf_pie(self):
        # looking at file type in header
        try:
            with open(self.filepath, "rb") as f:
                f.seek(0x10)
                e_type = struct.unpack('<H', f.read(2))[0]
                # type 3 is dynamic/shared object, usually means pie
                return e_type == 3
        except:
            return None
    
    def _check_elf_relro(self):
        # using readelf here cause manual parsing of dynamic section is annoying
        try:
            result = subprocess.run(['readelf', '-l', self.filepath],
                                  capture_output=True, text=True)
            output = result.stdout
            
            if 'GNU_RELRO' in output:
                # checking if bind_now is set for full relro
                result2 = subprocess.run(['readelf', '-d', self.filepath],
                                       capture_output=True, text=True)
                if 'BIND_NOW' in result2.stdout:
                    return "Full"
                return "Partial"
            return "No"
        except:
            return None
    
    def _check_elf_canary(self):
        # scanning symbols for __stack_chk_fail function
        try:
            result = subprocess.run(['readelf', '-s', self.filepath],
                                  capture_output=True, text=True)
            return '__stack_chk_fail' in result.stdout
        except:
            return None
    
    def _get_elf_interpreter(self):
        # extracting interpreter path like /lib64/ld-linux...
        try:
            result = subprocess.run(['readelf', '-l', self.filepath],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'interpreter' in line.lower():
                    parts = line.split('[')
                    if len(parts) > 1:
                        return parts[1].split(']')[0]
            return None
        except:
            return None
    
    def _check_pe_security(self):
        # windows specific checks
        
        # aslr: randomization
        self.checks['ASLR'] = self._check_pe_aslr()
        
        # dep: data execution prevention (same as nx)
        self.checks['DEP'] = self._check_pe_dep()
        
        # cfg: control flow guard
        self.checks['CFG'] = self._check_pe_cfg()
        
        # safeseh: exception handler check (32bit only)
        self.checks['SafeSEH'] = self._check_pe_safeseh()
    
    def _check_pe_aslr(self):
        # checking dll characteristics in optional header
        try:
            with open(self.filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                
                # jumping to dll characteristics
                f.seek(pe_offset + 0x5E)
                dll_chars = struct.unpack('<H', f.read(2))[0]
                
                # 0x0040 flag means dynamic base (aslr)
                return bool(dll_chars & 0x0040)
        except:
            return None
    
    def _check_pe_dep(self):
        # checking nx compat flag
        try:
            with open(self.filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset + 0x5E)
                dll_chars = struct.unpack('<H', f.read(2))[0]
                
                # 0x0100 flag is nx compat
                return bool(dll_chars & 0x0100)
        except:
            return None
    
    def _check_pe_cfg(self):
        # checking control flow guard flag
        try:
            with open(self.filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset + 0x5E)
                dll_chars = struct.unpack('<H', f.read(2))[0]
                
                # 0x4000 flag is guard cf
                return bool(dll_chars & 0x4000)
        except:
            return None
    
    def _check_pe_safeseh(self):
        # only relevant for 32 bit x86 binaries
        try:
            with open(self.filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset + 4)
                machine = struct.unpack('<H', f.read(2))[0]
                
                if machine != 0x014c:  
                    return "N/A"
                
                # if load config table exists safeseh is usually on
                f.seek(pe_offset + 0xD8)
                load_config_rva = struct.unpack('<I', f.read(4))[0]
                
                return load_config_rva != 0
        except:
            return None
    
    def display(self):
        # printing results nicely
        if self.binary_type == "ELF":
            self._display_elf()
        elif self.binary_type == "PE":
            self._display_pe()
    
    def _display_elf(self):
        nx = self.checks.get('NX')
        pie = self.checks.get('PIE')
        relro = self.checks.get('RELRO')
        canary = self.checks.get('CANARY')
        interpreter = self.checks.get('INTERPRETER')
        
        print(f"NX: {self._format_bool(nx)}")
        print(f"PIE: {self._format_bool(pie)}")
        print(f"RELRO: {self._format_relro(relro)}")
        print(f"CANARY: {self._format_bool(canary)}")
        if interpreter:
            print(f"Interpreter: {interpreter}")
    
    def _display_pe(self):
        aslr = self.checks.get('ASLR')
        dep = self.checks.get('DEP')
        cfg = self.checks.get('CFG')
        safeseh = self.checks.get('SafeSEH')
        
        print(f"ASLR: {self._format_bool(aslr)}")
        print(f"DEP (NX): {self._format_bool(dep)}")
        print(f"CFG: {self._format_bool(cfg)}")
        print(f"SafeSEH: {self._format_safeseh(safeseh)}")
    
    def _format_bool(self, value):
        if value is None:
            return f" Unknown"
        elif value:
            return f" Enabled"
        else:
            return f" Disabled"
    
    def _format_relro(self, value):
        if value is None:
            return f" Unknown"
        elif value == " Full":
            return f" Full RELRO"
        elif value == " Partial":
            return f" Partial RELRO"
        else:
            return f" No RELRO"
    
    def _format_safeseh(self, value):
        if value == " N/A":
            return f" N/A (64-bit)"
        return self._format_bool(value)
