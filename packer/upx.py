#!/usr/bin/env python3

"""
UPX (Ultimate Packer for eXecutables) Detector
"""

def detect(filepath, binary_type, entropy):
    # confidence score starts at 0, we add points as we find clues
    confidence = 0
    try:
        with open(filepath, "rb") as f:
            # reading entire file into memory to search for signatures
            # might be heavy for huge files but works for standard binaries
            data = f.read()
            
            # looking for standard upx magic bytes
            # upx! is the most common one found in headers
            if b'UPX!' in data or b'UPX0' in data or b'UPX1' in data:
                confidence += 80
            
            # checking section names
            # upx typically renames sections to .upx0 (empty) and .upx1 (compressed)
            if b'.UPX0' in data or b'.UPX1' in data or b'UPX2' in data:
                confidence += 15
            
            # dead giveaway string
            # if this string is present, it is 100% upx unless someone faked it
            if b'This file is packed with the UPX' in data:
                confidence = 100
            
            # heuristic for windows pe files
            # packed binaries usually hide imports, so if we see very few dlls
            # it increases probability of being packed
            if binary_type == "PE":
                import_count = data.count(b'.dll\x00')
                if import_count < 5:
                    confidence += 5
            
            # combining with entropy result from main script
            # packed files look like random noise (high entropy)
            if entropy and entropy >= 7.0:
                confidence += 10
            
            # basic size heuristic
            # very small files might be just shellcode or tests
            if binary_type == "ELF" or binary_type == "PE":
                if len(data) > 100000:
                    confidence += 5
        
        # if we are at least half sure, return the result
        if confidence >= 50:
            return {
                'name': 'UPX',
                'confidence': min(confidence, 100)
            }
        
    except Exception as e:
        # just ignore errors if file cant be read
        pass
    
    return None
