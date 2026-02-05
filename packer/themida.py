#!/usr/bin/env python3
"""
Themida / WinLicense Detector
"""

def detect(filepath, binary_type, entropy):
    # themida is windows only so skipping elf
    if binary_type != "PE":
        return None
    
    confidence = 0
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            
            # 1. checking for section names
            # themida sometimes leaves these but modern versions might randomize them
            themida_sections = [
                b'.themida',
                b'.winlice',
                b'.boot', # boot section often used by themida
                b'.shared'
            ]
            
            for section in themida_sections:
                if section in data:
                    confidence += 30
            
            # 2. checking for specific strings
            # oreans is the company that makes themida
            themida_strings = [
                b'Themida',
                b'WinLicense',
                b'Oreans',
                b'SecureEngine' # the core engine name
            ]
            
            for string in themida_strings:
                if string in data:
                    confidence += 25
            
            # themida uses strong encryption so entropy is usually very high
            # nearly 8.0 typically, higher than simple packers like upx
            if entropy and entropy >= 7.8:
                confidence += 15
            
            # 3. checking for anti-debugging apis
            # themida packs heavy anti-debug tricks, so presence of these APIs
            # increases the chance it's protected
            anti_strings = [
                b'IsDebuggerPresent',
                b'CheckRemoteDebuggerPresent',
                b'NtQueryInformationProcess'
            ]
            
            # counting how many anti-debug functions we found
            anti_count = sum(1 for s in anti_strings if s in data)
            if anti_count >= 2:
                confidence += 10
        
        # if we are confident enough
        if confidence >= 50:
            # trying to guess if its themida or winlicense specifically
            name = 'Themida' if b'Themida' in data else 'WinLicense'
            return {
                'name': name,
                'confidence': min(confidence, 100)
            }
        
    except Exception as e:
        pass
    
    return None
