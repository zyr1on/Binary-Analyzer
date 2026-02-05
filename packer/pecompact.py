#!/usr/bin/env python3
"""
PECompact Detector Module
"""

def detect(filepath, binary_type, entropy):
    # pecompact is only for windows pe files
    if binary_type != "PE":
        return None

    confidence = 0
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            
            # 1. String signs
            # specific strings and vendor names associated with pecompact
            pecompact_markers = [
                b'PECompact2', 
                b'PEC2', 
                b'PECompact V',
                b'Bitsum Technologies' # the company behind it
            ]
            
            # if we find the vendor signature, we are pretty sure it's pecompact
            for marker in pecompact_markers:
                if marker in data:
                    confidence += 70
                    break

            # checking standard section names used by this packer
            pec_sections = [b'.pec1', b'.pec2', b'PEC2', b'PEC2VSD']
            for section in pec_sections:
                if section in data:
                    confidence += 25
            
            # scanning the header area (first 2kb) for a specific opcode sequence
            # likely a jump instruction or specific header byte signature
            if b'\xeb\x06\xff\xff\xff\xff\x00\x00' in data[:2048]:
                confidence += 20

            # compression check, high entropy means it's packed
            if entropy and entropy >= 7.2:
                confidence += 10

            # packer stubs need these functions to load the original executable manually
            # finding them together increases likelihood slightly
            if b'LoadLibraryA' in data and b'GetProcAddress' in data:
                confidence += 5

        # if confidence hits 40 or more return the result
        if confidence >= 40:
            return {
                'name': 'PECompact',
                'confidence': min(confidence, 100)
            }
            
    except Exception:
        pass
    
    return None
