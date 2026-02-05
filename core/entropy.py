#!/usr/bin/env python3

import math
from collections import Counter

class EntropyAnalyzer:
    # class to measure how random the file data is
    # useful to find packed or encrypted executables
    def __init__(self, filepath):
        self.filepath = filepath
        self.entropy_value = self._calculate_entropy()
        self.assessment = self._assess_entropy()
    
    def _calculate_entropy(self):
        try:
            # reading the whole file as bytes
            with open(self.filepath, "rb") as f:
                data = f.read()
            
            if len(data) == 0:
                return 0.0
            
            # using counter to quickly count frequency of each byte (0-255)
            # e.g. how many 0x90 (NOP) bytes are there
            byte_counts = Counter(data)
            
            # starting shannon entropy calculation
            entropy = 0.0
            length = len(data)
            
            for count in byte_counts.values():
                # calculating probability of this byte appearing
                probability = count / length
                
                # applying formula: -sum(p * log2(p))
                # log2 is used because we are dealing with bits/bytes
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            # returns a value between 0 and 8 (since 2^8 = 256 possibilities)
            return entropy
        except Exception as e:
            return None
    
    def _assess_entropy(self):
        # interpreting the result based on common malware analysis heuristics
        if self.entropy_value is None:
            return "Could not calculate"
        
        # if value is close to 8, it means data is super random
        # random data usually indicates compression or encryption (packers)
        if self.entropy_value >= 7.5:
            return "Very High (Possibly packaged/encrypted)"
        
        # between 7 and 7.5 is usually compressed data or dense code
        elif self.entropy_value >= 7.0:
            return "High (May be packaged or compressed)"
        
        # standard compiled c/c++ code usually sits around 6.0
        elif self.entropy_value >= 6.0:
            return "Medium (Normal compiled binary)"
        
        # text files or sparse binaries
        elif self.entropy_value >= 4.0:
            return "Low (Contains plain text or simple data)"
        
        # lots of padding (0x00) or repeated strings
        else:
            return "Very Low (Mostly Repeated Data)"
    
    def display(self):
        if self.entropy_value is None:
            print(f"Entropy: Could not calculate")
            return
                
        print(f"Entropy: {self.entropy_value:.4f} / 8.000")
        print(f"Assessment: {self.assessment}")
        
        # drawing a cool progress bar to visualize randomness
        bar_length = 40
        filled = int((self.entropy_value / 8.0) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        print(f"\nEntropy Graph: [{bar}]")
