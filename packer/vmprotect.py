#!/usr/bin/env python3
"""
VMProtect Detector
"""

def detect(filepath, binary_type, entropy):
    # vmprotect is windows specific
    if binary_type != "PE":
        return None
        
    confidence = 0
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            
            # 1. explicit section names
            # standard vmp sections
            vmp_sections = [
                b'.vmp0',
                b'.vmp1',
                b'.vmp2',
                b'.vmp'
            ]
            
            found_vmp_section = False
            for section in vmp_sections:
                if section in data:
                    confidence += 60
                    found_vmp_section = True
            
            # 2. string signatures
            # rare, but sometimes left in headers or resources
            if b'VMProtect' in data:
                confidence += 50
                
            # 3. high entropy is crucial here
            # vmprotect encrypts everything heavily
            if entropy and entropy >= 7.6:
                confidence += 15
                
            # 4. heuristic: random section names + high entropy
            # if we didn't find .vmp but entropy is huge, it might be a packed vmp
            if not found_vmp_section and entropy and entropy > 7.8:
                # vmprotect creates massive code sections
                confidence += 10
        
        if confidence >= 50:
            return {
                'name': 'VMProtect',
                'confidence': min(confidence, 100)
            }
            
    except Exception:
        pass
    
    return None
