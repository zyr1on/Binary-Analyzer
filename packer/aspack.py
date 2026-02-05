#!/usr/bin/env python3
"""
ASPack Detector
"""

def detect(filepath, binary_type, entropy):
    if binary_type != "PE":
        return None
    
    confidence = 0
    
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            
            # ASPack section names
            aspack_sections = [
                b'.aspack',
                b'.adata',
                b'ASPack',
                b'.packed'
            ]
            
            for section in aspack_sections:
                if section in data:
                    confidence += 40
            
            # ASPack strings
            aspack_strings = [
                b'ASPack',
                b'aspack.com',
                b'ASProtect',
                b'.aspack'
            ]
            
            for string in aspack_strings:
                if string in data:
                    confidence += 30
            
            
            if entropy and entropy >= 7.2:
                confidence += 10
            if b'ASPR' in data:
                confidence += 20
        
        if confidence >= 50:
            return {
                'name': 'ASPack',
                'confidence': min(confidence, 100)
            }
        
    except Exception as e:
        pass
    
    return None
