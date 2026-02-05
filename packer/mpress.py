#!/usr/bin/env python3
"""
MPRESS Detector
"""

def detect(filepath, binary_type, entropy):
    # mpress works on pe, elf and even macos
    # but mostly seen on windows pe
    confidence = 0
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            
            # 1. section names
            # mpress almost always renames sections to these
            mpress_sections = [
                b'.MPRESS1',
                b'.MPRESS2', 
                b'.mpress1',
                b'.mpress2'
            ]
            
            for section in mpress_sections:
                if section in data:
                    confidence += 40
            
            # 2. signature strings
            # older versions leave signatures explicitly
            if b'MPRESS' in data:
                confidence += 20
                
            if b'MATCODE' in data: # matcode is the author
                confidence += 20
            
            # 3. entropy check
            # since it compresses code, entropy is high
            if entropy and entropy >= 7.0:
                confidence += 10
        
        if confidence >= 50:
            return {
                'name': 'MPRESS',
                'confidence': min(confidence, 100)
            }
            
    except Exception:
        pass
    
    return None
